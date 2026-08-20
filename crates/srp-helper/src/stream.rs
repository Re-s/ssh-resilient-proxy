//! 单条逻辑流在 helper 侧的执行体。
//!
//! # 状态归属
//!
//! 每条流的状态被刻意切成两半，避免"共享一切"带来的死锁：
//!
//! * **接收侧** `RecvTracker` 只被会话主循环触碰（帧解析是单点的，天然有序），
//!   所以它不需要任何同步原语。
//! * **发送侧** `SendBuffer` 必须同时被两方读写——出口 socket 的读取任务往里
//!   `push`，主循环收到 `Ack`/`Resume` 时要 `ack`/`rewind_to`。这里用
//!   `std::sync::Mutex` + `Notify`：临界区内只做纯内存操作、**绝不 await**
//!   （编译器也会拦住：`MutexGuard` 跨 await 会让任务失去 `Send`），
//!   状态变化后用 `Notify` 唤醒发送任务重新评估。
//!
//! # 三个并发单元
//!
//! * `run_stream`：连接出口地址，随后同时驱动下面两个方向（同一个 task 内的
//!   两个 future，互不阻塞）。
//! * `uplink`：出口 socket → `SendBuffer` → `Data`/`Fin` 帧。窗口耗尽时**停止
//!   读取 socket**，这是"不丢字节"的背压前提。
//! * `downlink_loop`：客户端 `Data` → 出口 socket，写入成功后再累积确认。
//!   先落地、后确认，保证客户端在收到 `Ack` 之前不会释放重传缓冲。

use std::io;
use std::net::SocketAddr;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use bytes::Bytes;
use srp_proto::{Frame, ResetCode, SendBuffer, StreamId, TargetAddr, DATA_CHUNK};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Notify};
use tokio::time::{sleep_until, timeout, Instant};

/// 累积确认阈值：新增交付字节达到该值就立刻 `Ack`，让对端窗口尽快滑动。
const ACK_BYTES: u64 = 64 * 1024;

/// 累积确认最大延迟：数据量小也必须在该时间内确认，否则对端窗口会白等。
const ACK_DELAY: Duration = Duration::from_millis(100);

/// 发送侧共享状态：重传缓冲 + 变更通知。
#[derive(Debug)]
pub struct StreamTx {
    buf: Mutex<SendBuffer>,
    /// 唤醒 `uplink`：窗口释放（`Ack`）或游标回退（`Resume`）。
    notify: Notify,
}

impl StreamTx {
    pub fn new(window: u64) -> Self {
        Self {
            buf: Mutex::new(SendBuffer::new(window)),
            notify: Notify::new(),
        }
    }

    /// 在临界区内操作重传缓冲。闭包里不允许 await（类型系统会强制这一点）。
    pub fn with<T>(&self, f: impl FnOnce(&mut SendBuffer) -> T) -> T {
        // 临界区内没有 await、也没有 panic 点，理论上不会中毒；
        // 万一中毒（例如别处 abort 的极端时序）也直接取回内部值继续用，
        // 因为 SendBuffer 的不变式不依赖"是否发生过 panic"。
        let mut guard: MutexGuard<'_, SendBuffer> = self
            .buf
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&mut guard)
    }

    /// 通知发送任务："状态变了，重新评估待发数据与窗口"。
    pub fn wake(&self) {
        self.notify.notify_one();
    }
}

/// 主循环 → 出口写方向的指令。
#[derive(Debug)]
pub enum Downlink {
    /// 新到达的按序数据。写入 socket 成功后确认到 `delivered`。
    Data { bytes: Bytes, delivered: u64 },
    /// 整帧重复（重连重传造成），无需写 socket，只需重申确认位置。
    Duplicate { delivered: u64 },
    /// 客户端半关闭：对出口 socket 做 write shutdown，读方向保持。
    Fin,
}

/// 流任务 → 主循环的状态上报。
#[derive(Debug)]
pub enum StreamEvent {
    /// 出口方向彻底结束：读到 EOF、`Fin` 已发出、发送缓冲已被完全确认。
    EgressDone(StreamId),
    /// 该流失败。`reset` 为 `Some` 时主循环还需向客户端发 `Reset`
    /// （连接失败已经用 `OpenErr` 回报过，此时为 `None`）。
    Failed {
        stream_id: StreamId,
        reset: Option<ResetCode>,
    },
}

/// 终止原因。区分"会话没了"与"出口坏了"，前者不必再向客户端报错。
#[derive(Debug)]
enum Halt {
    /// 写队列已关闭，说明会话正在收摊，静默退出。
    Closed,
    /// 出口 socket I/O 错误。
    Io(io::Error),
    /// 内部不变式被破坏。
    Internal(&'static str),
}

impl std::fmt::Display for Halt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "session writer closed"),
            Self::Io(e) => write!(f, "egress io error: {e}"),
            Self::Internal(m) => write!(f, "internal invariant violated: {m}"),
        }
    }
}

/// 启动一条流所需的全部材料。
pub struct StreamTask {
    pub stream_id: StreamId,
    pub addr: TargetAddr,
    pub shared: std::sync::Arc<StreamTx>,
    pub downlink: mpsc::Receiver<Downlink>,
    pub frames: mpsc::Sender<Frame>,
    pub events: mpsc::Sender<StreamEvent>,
    pub connect_timeout: Duration,
}

/// 流的生命周期：建连 → 双向转发 → 上报结束。
pub async fn run_stream(task: StreamTask) {
    let StreamTask {
        stream_id,
        addr,
        shared,
        mut downlink,
        frames,
        events,
        connect_timeout,
    } = task;

    let mut sock = match dial(&addr, connect_timeout).await {
        Ok(sock) => sock,
        Err(msg) => {
            tracing::warn!(stream = stream_id, target = %addr, "egress connect failed: {msg}");
            let _ = frames
                .send(Frame::OpenErr {
                    stream_id,
                    code: ResetCode::ConnectFailed,
                    msg,
                })
                .await;
            // OpenErr 已经是终局回复，主循环只需回收状态。
            let _ = events
                .send(StreamEvent::Failed {
                    stream_id,
                    reset: None,
                })
                .await;
            return;
        }
    };
    // 代理转发以小包交互为主，禁用 Nagle 能明显降低往返延迟。
    let _ = sock.set_nodelay(true);

    if frames.send(Frame::OpenOk { stream_id }).await.is_err() {
        return;
    }
    tracing::debug!(stream = stream_id, target = %addr, "egress connected");

    let (rd, wr) = sock.split();
    let mut up = std::pin::pin!(uplink(stream_id, rd, &shared, &frames));
    let mut down = std::pin::pin!(downlink_loop(stream_id, wr, &mut downlink, &frames));
    let mut up_done = false;
    let mut down_done = false;

    // 两个方向各自独立结束：上行结束（EOF + 全部确认）不影响下行继续写，
    // 反之亦然。任一方向出错则整条流立即判死。
    while !(up_done && down_done) {
        tokio::select! {
            r = &mut up, if !up_done => {
                up_done = true;
                match r {
                    Ok(()) => {
                        let _ = events.send(StreamEvent::EgressDone(stream_id)).await;
                    }
                    Err(Halt::Closed) => return,
                    Err(err) => {
                        tracing::warn!(stream = stream_id, "uplink stopped: {err}");
                        let _ = events.send(StreamEvent::Failed {
                            stream_id,
                            reset: Some(ResetCode::Internal),
                        }).await;
                        return;
                    }
                }
            }
            r = &mut down, if !down_done => {
                down_done = true;
                match r {
                    Ok(()) => {}
                    Err(Halt::Closed) => return,
                    Err(err) => {
                        tracing::warn!(stream = stream_id, "downlink stopped: {err}");
                        let _ = events.send(StreamEvent::Failed {
                            stream_id,
                            reset: Some(ResetCode::Internal),
                        }).await;
                        return;
                    }
                }
            }
        }
    }
    tracing::debug!(stream = stream_id, "stream task finished");
}

/// 建立出口 TCP 连接。
///
/// 域名以 `(host, port)` 元组交给系统解析器，因此 DNS **发生在远端**——
/// 这既避免本地 DNS 污染，也让重连后的重放保持幂等。
async fn dial(addr: &TargetAddr, limit: Duration) -> Result<TcpStream, String> {
    let attempt = async {
        match addr {
            TargetAddr::Domain(host, port) => TcpStream::connect((host.as_str(), *port)).await,
            TargetAddr::V4(octets, port) => {
                TcpStream::connect(SocketAddr::from((*octets, *port))).await
            }
            TargetAddr::V6(octets, port) => {
                TcpStream::connect(SocketAddr::from((*octets, *port))).await
            }
        }
    };
    match timeout(limit, attempt).await {
        Ok(Ok(sock)) => Ok(sock),
        // 拒绝连接与 DNS 失败都在这里，io::Error 的描述已经足够定位问题。
        Ok(Err(err)) => Err(err.to_string()),
        Err(_) => Err(format!("connect timed out after {:?}", limit)),
    }
}

/// 出口 socket → 客户端。
///
/// 返回 `Ok(())` 表示"出口已 EOF、`Fin` 已发、缓冲全部被确认"，此时该方向
/// 再无遗留字节，可以安全丢弃状态。
async fn uplink(
    stream_id: StreamId,
    mut rd: tokio::net::tcp::ReadHalf<'_>,
    shared: &StreamTx,
    frames: &mpsc::Sender<Frame>,
) -> Result<(), Halt> {
    let mut scratch = vec![0u8; DATA_CHUNK];
    let mut eof = false;
    let mut fin_sent = false;

    loop {
        // 1) 把缓冲中所有未发送字节冲刷出去。`Resume` 回退游标后，这里会
        //    自动把缺口重发一遍——重传路径与首发路径完全共用。
        while let Some((offset, data)) = shared.with(|b| b.next_unsent(DATA_CHUNK)) {
            frames
                .send(Frame::Data {
                    stream_id,
                    offset,
                    data,
                })
                .await
                .map_err(|_| Halt::Closed)?;
        }

        // 2) 出口已 EOF：补一个 Fin，然后等所有字节被确认才算真正结束。
        //    在此期间必须保持存活，否则客户端的 Resume 将无从重发。
        if eof {
            if !fin_sent {
                frames
                    .send(Frame::Fin { stream_id })
                    .await
                    .map_err(|_| Halt::Closed)?;
                fin_sent = true;
            }
            if shared.with(|b| b.is_fully_acked()) {
                return Ok(());
            }
            shared.notify.notified().await;
            continue;
        }

        // 3) 背压：窗口为 0 时**不读** socket，只等 Ack 释放空间。
        //    未确认数据必须留在缓冲里，读进来就无处安放。
        let writable = shared.with(|b| b.writable());
        if writable == 0 {
            tracing::trace!(stream = stream_id, "send window full, pausing egress reads");
            shared.notify.notified().await;
            continue;
        }

        let cap = writable.min(scratch.len() as u64) as usize;
        let read = tokio::select! {
            // TcpStream 的 read 是取消安全的：被 select 丢弃时不会吞掉字节。
            r = rd.read(&mut scratch[..cap]) => r.map_err(Halt::Io)?,
            _ = shared.notify.notified() => continue,
        };
        if read == 0 {
            eof = true;
            shared.with(|b| b.mark_fin());
            continue;
        }
        let pushed = shared.with(|b| b.push(&scratch[..read]));
        if pushed != read {
            // 读取量已按 writable 裁剪过，出现这种情况说明窗口计算被破坏，
            // 继续跑下去会静默丢字节，宁可判死。
            return Err(Halt::Internal("send buffer rejected clamped write"));
        }
    }
}

/// 客户端 → 出口 socket，并负责该流的累积确认。
async fn downlink_loop(
    stream_id: StreamId,
    mut wr: tokio::net::tcp::WriteHalf<'_>,
    rx: &mut mpsc::Receiver<Downlink>,
    frames: &mpsc::Sender<Frame>,
) -> Result<(), Halt> {
    let mut pending = 0u64;
    let mut delivered = 0u64;
    let mut deadline = Instant::now() + ACK_DELAY;

    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Some(Downlink::Data { bytes, delivered: at }) => {
                    // 先落地再确认：客户端收到 Ack 时，字节已经进入出口 socket。
                    wr.write_all(&bytes).await.map_err(Halt::Io)?;
                    if pending == 0 {
                        deadline = Instant::now() + ACK_DELAY;
                    }
                    pending += bytes.len() as u64;
                    delivered = at;
                    if pending >= ACK_BYTES {
                        send_ack(frames, stream_id, delivered).await?;
                        pending = 0;
                    }
                }
                Some(Downlink::Duplicate { delivered: at }) => {
                    // 重连重传导致的重复帧：立刻重申确认位置，帮对端尽快对齐。
                    delivered = at;
                    send_ack(frames, stream_id, delivered).await?;
                    pending = 0;
                }
                Some(Downlink::Fin) => {
                    if pending > 0 {
                        send_ack(frames, stream_id, delivered).await?;
                        pending = 0;
                    }
                    // 半关闭：出口对端会看到 EOF，但它仍可继续向我们发数据。
                    wr.shutdown().await.map_err(Halt::Io)?;
                    tracing::debug!(stream = stream_id, "egress write side shut down");
                }
                None => {
                    if pending > 0 {
                        send_ack(frames, stream_id, delivered).await?;
                    }
                    return Ok(());
                }
            },
            _ = sleep_until(deadline), if pending > 0 => {
                send_ack(frames, stream_id, delivered).await?;
                pending = 0;
            }
        }
    }
}

async fn send_ack(
    frames: &mpsc::Sender<Frame>,
    stream_id: StreamId,
    offset: u64,
) -> Result<(), Halt> {
    frames
        .send(Frame::Ack { stream_id, offset })
        .await
        .map_err(|_| Halt::Closed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_buffer_is_mutated_under_lock() {
        let tx = StreamTx::new(64);
        assert_eq!(tx.with(|b| b.push(b"abcd")), 4);
        let (offset, data) = tx.with(|b| b.next_unsent(64)).expect("pending");
        assert_eq!(offset, 0);
        assert_eq!(&data[..], b"abcd");
        tx.with(|b| b.ack(4)).expect("ack");
        assert!(tx.with(|b| b.is_fully_acked()));
        tx.wake(); // 无等待者时也不应 panic
    }

    #[test]
    fn window_reports_backpressure() {
        let tx = StreamTx::new(4);
        assert_eq!(tx.with(|b| b.push(b"abcdef")), 4, "必须按窗口裁剪");
        assert_eq!(tx.with(|b| b.writable()), 0);
    }

    #[tokio::test]
    async fn dial_reports_refused_connection() {
        // 端口 1 上不会有监听者，且非 root 也无法绑定，因此结果稳定。
        let err = dial(&TargetAddr::V4([127, 0, 0, 1], 1), Duration::from_secs(5))
            .await
            .expect_err("connect must fail");
        assert!(!err.is_empty(), "错误描述不能为空");
    }

    #[tokio::test]
    async fn dial_honours_timeout() {
        // 192.0.2.0/24 是 RFC 5737 文档用网段，不可路由，连接会挂住直到超时。
        let err = dial(
            &TargetAddr::V4([192, 0, 2, 1], 9),
            Duration::from_millis(50),
        )
        .await
        .expect_err("must time out or fail");
        assert!(!err.is_empty());
    }
}
