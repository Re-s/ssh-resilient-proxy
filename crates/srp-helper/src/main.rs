//! `srp-helper`：运行在远端 SSH session 通道上的多路 TCP 出口代理。
//!
//! stdin/stdout 是严格的二进制协议通道，**绝不可**打印诊断信息；所有日志只写
//! stderr，且默认等级为 off。
//!
//! 会话层（本文件）只负责协议解析、流目录与状态机；真正的 socket I/O 交给
//! `stream` 模块的独立任务。这样一个慢出口不会阻塞其它流，也不会阻塞 stdin 上的
//! 控制帧（`Ping`、`Ack`、`Reset`）。

mod allow;
mod stream;

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use allow::AllowList;
use anyhow::{anyhow, bail, Context, Result};
use bytes::BytesMut;
use clap::Parser;
use srp_proto::{
    Frame, RecvTracker, ResetCode, SessionId, StreamId, DEFAULT_STREAM_WINDOW, PROTO_VERSION,
};
use stream::{Downlink, StreamEvent, StreamTask, StreamTx};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{sleep_until, Instant};
use tracing_subscriber::filter::LevelFilter;

/// 单个 helper 默认最多同时持有的逻辑流数量。
///
/// 上限存在的意义是防资源耗尽：每条流都占用一个远端 fd、一份重传缓冲和一个
/// DNS 解析槽位，没有上限时一个失控客户端就能打爆远端主机。
const MAX_STREAMS: usize = 512;

/// 单次出口连接的时间上限，DNS 查询与 TCP 握手都算在内。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// stdout writer 与各流任务之间的帧队列深度。
///
/// 队列满时对流任务形成背压，而不是无限吃内存；stdout 可写后 writer 会继续排空。
const FRAME_QUEUE: usize = 1024;

/// 每条流的下行指令队列深度。
const DOWNLINK_QUEUE: usize = 128;

#[derive(Debug, Parser)]
#[command(
    name = "srp-helper",
    version,
    about = "srp 远端 helper：在一条 SSH session 通道的 stdin/stdout 上跑多路 TCP 代理协议"
)]
struct Cli {
    /// 允许的出口目标：host、host:port、*:port，host 支持前导 *. 通配子域名；可重复
    #[arg(long = "allow", value_name = "PATTERN")]
    allow: Vec<String>,

    /// stdin 超过该秒数没有收到任何完整帧就退出；0 表示不启用
    #[arg(long, default_value_t = 0, value_name = "SECS")]
    idle_timeout: u64,

    /// 每条流的重传缓冲容量，同时是出口读取的背压窗口
    #[arg(long, default_value_t = DEFAULT_STREAM_WINDOW, value_name = "BYTES")]
    stream_window: u64,

    /// stderr 日志等级：off / error / warn / info / debug / trace
    #[arg(long, default_value = "off", value_name = "LEVEL")]
    log_level: String,
}

/// 会话运行参数。把 CLI 与核心逻辑解耦，测试才能直接构造。
#[derive(Debug, Clone)]
struct SessionConfig {
    allow: AllowList,
    idle_timeout: Option<Duration>,
    stream_window: u64,
    max_streams: usize,
}

impl SessionConfig {
    fn from_cli(cli: &Cli) -> Result<Self> {
        if cli.stream_window == 0 {
            bail!("--stream-window 必须大于 0");
        }
        Ok(Self {
            allow: AllowList::parse(&cli.allow)?,
            idle_timeout: (cli.idle_timeout != 0).then(|| Duration::from_secs(cli.idle_timeout)),
            stream_window: cli.stream_window,
            max_streams: MAX_STREAMS,
        })
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            allow: AllowList::default(),
            idle_timeout: None,
            stream_window: DEFAULT_STREAM_WINDOW,
            max_streams: MAX_STREAMS,
        }
    }
}

/// 流目录中的一条流。
///
/// `recv` 只被会话主循环访问（帧解析是单点且有序的），因此无需同步原语；
/// `shared` 里的发送缓冲要被出口读取任务并发访问，才用锁包起来。
struct StreamState {
    recv: RecvTracker,
    downlink: mpsc::Sender<Downlink>,
    shared: Arc<StreamTx>,
    /// 出口已 EOF、`Fin` 已发出、且发送缓冲被完全确认。
    egress_done: bool,
    /// 客户端已发 `Fin`，出口 socket 的写半边已关闭。
    ingress_fin: bool,
    task: JoinHandle<()>,
}

impl StreamState {
    /// 立即释放出口 socket，不等待对端可读。
    fn stop(self) {
        self.task.abort();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let level = LevelFilter::from_str(&cli.log_level)
        .map_err(|_| anyhow!("无效的 --log-level {:?}", cli.log_level))?;
    // 日志只走 stderr：stdout 属于协议，混入一个字节就会让对端解码失败。
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .without_time()
        .with_target(false)
        .init();

    let config = SessionConfig::from_cli(&cli)?;
    if config.allow.is_empty() {
        // 直接 eprintln 而非 tracing：默认 log level 为 off，安全告警不能被吞掉。
        eprintln!("srp-helper 警告：未配置 --allow，将允许连接任意目标");
    }
    // stdin/stdout 就是 SSH session 通道：sshd 把它们接到客户端的通道两端。
    run_session(tokio::io::stdin(), tokio::io::stdout(), config).await
}

/// 驱动一个 helper 会话，直到 stdin EOF、空闲超时、版本不兼容或协议违规。
///
/// 核心逻辑的唯一入口，故意对 `AsyncRead`/`AsyncWrite` 泛型化：生产环境传入真实
/// stdin/stdout，测试传入 `tokio::io::duplex`。stdout 由唯一的 writer 任务独占，
/// 其它任务只往有界 channel 里投递 `Frame`，因此并发写入不可能让帧交织损坏。
async fn run_session<R, W>(mut input: R, output: W, config: SessionConfig) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (frames_tx, frames_rx) = mpsc::channel(FRAME_QUEUE);
    let writer = tokio::spawn(writer_task(output, frames_rx));
    // 每条流终局至多产生一个事件，容量按流上限给足即可，不会反压主循环。
    let (events_tx, mut events_rx) = mpsc::channel(config.max_streams.max(1) * 2);

    let mut buffered = BytesMut::with_capacity(8192);
    let mut scratch = vec![0u8; 16 * 1024];
    let mut session_id: Option<SessionId> = None;
    let mut streams: HashMap<StreamId, StreamState> = HashMap::new();
    let mut last_frame = Instant::now();
    let mut result = Ok(());

    'session: loop {
        // 先把已缓冲的字节里能解析的帧全部处理完：一次 read 往往带来多个帧。
        loop {
            let frame = match Frame::decode(&mut buffered) {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(err) => {
                    result = Err(anyhow!("收到无效协议帧: {err}"));
                    break 'session;
                }
            };
            last_frame = Instant::now();
            let keep_going = handle_frame(
                frame,
                &mut session_id,
                &mut streams,
                &frames_tx,
                &events_tx,
                &config,
            )
            .await;
            if !keep_going {
                // 版本不兼容：`HelloAck` 已排入 writer 队列，随后立即收摊退出。
                break 'session;
            }
        }

        let idle_deadline = config.idle_timeout.map(|d| last_frame + d);
        tokio::select! {
            // read 在这些类型上是取消安全的：被 select 丢弃时不会吞掉已读字节。
            read = input.read(&mut scratch) => match read {
                Ok(0) => break 'session,
                Ok(n) => buffered.extend_from_slice(&scratch[..n]),
                Err(err) => {
                    result = Err(err).context("读取 helper stdin 失败");
                    break 'session;
                }
            },
            event = events_rx.recv() => {
                if let Some(event) = event {
                    handle_stream_event(event, &mut streams, &frames_tx).await;
                }
            },
            _ = async {
                match idle_deadline {
                    Some(deadline) => sleep_until(deadline).await,
                    // 未启用空闲超时：这一分支永远不就绪。
                    None => std::future::pending().await,
                }
            } => {
                tracing::info!("stdin 空闲超时，helper 退出");
                break 'session;
            }
        }
    }

    // 关闭全部出口；drop sender 后 writer 会把队列里已提交的帧写完并 flush。
    close_all(&mut streams);
    drop(events_tx);
    drop(frames_tx);
    match writer.await {
        Ok(Ok(())) => result,
        Ok(Err(err)) => result.and(Err(err)),
        Err(err) => result.and(Err(anyhow!("stdout writer 任务异常退出: {err}"))),
    }
}

/// 唯一持有 stdout 的任务。
///
/// 每批帧写完 flush 一次：不 flush 会让 SSH 通道白等一轮往返，
/// 每帧都 flush 又会在高吞吐时把 syscall 打满，所以按"排空当前队列"分批。
async fn writer_task<W>(mut output: W, mut frames: mpsc::Receiver<Frame>) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut wire = BytesMut::with_capacity(16 * 1024);
    while let Some(first) = frames.recv().await {
        wire.clear();
        first.encode(&mut wire);
        while let Ok(frame) = frames.try_recv() {
            frame.encode(&mut wire);
        }
        output
            .write_all(&wire)
            .await
            .context("写入 helper stdout 失败")?;
        output.flush().await.context("flush helper stdout 失败")?;
    }
    output
        .flush()
        .await
        .context("收尾 flush helper stdout 失败")
}

/// 处理一个已完整解码的帧。返回 `false` 表示会话应当退出。
async fn handle_frame(
    frame: Frame,
    session_id: &mut Option<SessionId>,
    streams: &mut HashMap<StreamId, StreamState>,
    frames: &mpsc::Sender<Frame>,
    events: &mpsc::Sender<StreamEvent>,
    config: &SessionConfig,
) -> bool {
    match frame {
        Frame::Hello {
            version,
            session_id: requested,
            resume,
        } => {
            if version != PROTO_VERSION {
                // 版本不兼容不做降级：回一个明确的失败握手，然后退出进程。
                let _ = frames
                    .send(Frame::HelloAck {
                        version: PROTO_VERSION,
                        session_id: requested,
                        resumed: false,
                    })
                    .await;
                return false;
            }
            // 只有"同一会话 + 明确要求续传 + 本进程确实还握着流"三者同时成立，
            // 才能声称 resumed；否则客户端会误以为旧流仍然有效。
            let resumed = resume && *session_id == Some(requested) && !streams.is_empty();
            if !resumed {
                close_all(streams);
                *session_id = Some(requested);
            }
            tracing::info!(resumed, "会话握手完成");
            if frames
                .send(Frame::HelloAck {
                    version: PROTO_VERSION,
                    session_id: requested,
                    resumed,
                })
                .await
                .is_err()
            {
                return false;
            }
        }

        Frame::Open { stream_id, addr } => {
            if streams.contains_key(&stream_id) {
                send_open_err(
                    frames,
                    stream_id,
                    ResetCode::Internal,
                    "duplicate stream id",
                )
                .await;
            } else if streams.len() >= config.max_streams {
                tracing::warn!(stream = stream_id, "拒绝新流：已达并发上限");
                send_open_err(frames, stream_id, ResetCode::Internal, "too many streams").await;
            } else if !config.allow.permits(&addr) {
                // 目标信息只写 stderr，绝不进 stdout。
                tracing::warn!(stream = stream_id, target = %addr, "允许列表拒绝该目标");
                send_open_err(
                    frames,
                    stream_id,
                    ResetCode::Forbidden,
                    "target rejected by allow list",
                )
                .await;
            } else {
                let (down_tx, down_rx) = mpsc::channel(DOWNLINK_QUEUE);
                let shared = Arc::new(StreamTx::new(config.stream_window));
                let task = tokio::spawn(stream::run_stream(StreamTask {
                    stream_id,
                    addr,
                    shared: Arc::clone(&shared),
                    downlink: down_rx,
                    frames: frames.clone(),
                    events: events.clone(),
                    connect_timeout: CONNECT_TIMEOUT,
                }));
                streams.insert(
                    stream_id,
                    StreamState {
                        recv: RecvTracker::new(),
                        downlink: down_tx,
                        shared,
                        egress_done: false,
                        ingress_fin: false,
                        task,
                    },
                );
            }
        }

        Frame::Data {
            stream_id,
            offset,
            data,
        } => {
            let Some(state) = streams.get_mut(&stream_id) else {
                send_reset(frames, stream_id, ResetCode::UnknownStream).await;
                return true;
            };
            match state.recv.accept(offset, data) {
                Ok(Some(bytes)) => {
                    let delivered = state.recv.delivered();
                    // 交给流任务落地；Ack 由它在 write 成功之后发出。
                    if state
                        .downlink
                        .send(Downlink::Data { bytes, delivered })
                        .await
                        .is_err()
                    {
                        remove_stream(streams, stream_id);
                        send_reset(frames, stream_id, ResetCode::Internal).await;
                    }
                }
                Ok(None) => {
                    // 重连重传造成的整帧重复：重申确认位置，帮对端尽快对齐。
                    let delivered = state.recv.delivered();
                    if state
                        .downlink
                        .send(Downlink::Duplicate { delivered })
                        .await
                        .is_err()
                    {
                        remove_stream(streams, stream_id);
                        send_reset(frames, stream_id, ResetCode::Internal).await;
                    }
                }
                Err(err) => {
                    // 本协议下正常重传不会产生空洞，出现即为对端实现有误。
                    tracing::warn!(stream = stream_id, "入向数据出现空洞: {err}");
                    remove_stream(streams, stream_id);
                    send_reset(frames, stream_id, ResetCode::Internal).await;
                }
            }
        }

        Frame::Ack { stream_id, offset } => {
            let Some(state) = streams.get_mut(&stream_id) else {
                // 流已清理时迟到的 Ack 无害，静默忽略。
                return true;
            };
            match state.shared.with(|b| b.ack(offset)) {
                Ok(()) => {
                    // 唤醒出口读取任务：窗口刚刚被释放，背压可以解除了。
                    state.shared.wake();
                    maybe_cleanup_finished(streams, stream_id);
                }
                Err(err) => {
                    tracing::warn!(stream = stream_id, "非法 Ack: {err}");
                    remove_stream(streams, stream_id);
                    send_reset(frames, stream_id, ResetCode::Internal).await;
                }
            }
        }

        Frame::Fin { stream_id } => {
            let Some(state) = streams.get_mut(&stream_id) else {
                send_reset(frames, stream_id, ResetCode::UnknownStream).await;
                return true;
            };
            if !state.ingress_fin {
                state.ingress_fin = true;
                state.recv.mark_fin();
                // 只关出口的写半边，读方向继续——对端很可能还要回数据。
                if state.downlink.send(Downlink::Fin).await.is_err() {
                    remove_stream(streams, stream_id);
                    send_reset(frames, stream_id, ResetCode::Internal).await;
                    return true;
                }
            }
            maybe_cleanup_finished(streams, stream_id);
        }

        Frame::Reset { stream_id, code } => {
            // 对端已宣告该流作废，无需回应，立刻释放出口资源。
            tracing::debug!(stream = stream_id, ?code, "客户端重置流");
            remove_stream(streams, stream_id);
        }

        Frame::Resume {
            stream_id,
            recv_offset,
        } => {
            let Some(state) = streams.get_mut(&stream_id) else {
                send_resume_err(frames, stream_id, ResetCode::UnknownStream).await;
                return true;
            };
            match state.shared.with(|b| b.rewind_to(recv_offset)) {
                Ok(gap) => {
                    // 回退游标后由出口读取任务自动重发缺口，重传与首发共用同一路径。
                    let local_received = state.recv.delivered();
                    state.shared.wake();
                    tracing::info!(stream = stream_id, gap, "流续传成功");
                    let _ = frames
                        .send(Frame::ResumeOk {
                            stream_id,
                            recv_offset: local_received,
                        })
                        .await;
                }
                Err(err) => {
                    // 缺口已超出重传缓冲，续传无从谈起，只能让客户端重开流。
                    tracing::warn!(stream = stream_id, "无法续传: {err}");
                    remove_stream(streams, stream_id);
                    send_resume_err(frames, stream_id, ResetCode::ResumeImpossible).await;
                }
            }
        }

        Frame::Ping { nonce } => {
            let _ = frames.send(Frame::Pong { nonce }).await;
        }

        // 以下都是 helper → 客户端方向的帧。收到说明对端方向弄反了；忽略比断开
        // 整条 SSH 会话更划算，反正它们不携带任何本地状态变更。
        Frame::HelloAck { .. }
        | Frame::OpenOk { .. }
        | Frame::OpenErr { .. }
        | Frame::ResumeOk { .. }
        | Frame::ResumeErr { .. }
        | Frame::Pong { .. } => {
            tracing::debug!("忽略方向错误的帧");
        }
    }
    true
}

async fn handle_stream_event(
    event: StreamEvent,
    streams: &mut HashMap<StreamId, StreamState>,
    frames: &mpsc::Sender<Frame>,
) {
    match event {
        StreamEvent::EgressDone(stream_id) => {
            if let Some(state) = streams.get_mut(&stream_id) {
                state.egress_done = true;
            }
            maybe_cleanup_finished(streams, stream_id);
        }
        StreamEvent::Failed { stream_id, reset } => {
            remove_stream(streams, stream_id);
            if let Some(code) = reset {
                send_reset(frames, stream_id, code).await;
            }
        }
    }
}

/// 双向都已 FIN 且发送缓冲被完全确认时回收流状态。
///
/// 三个条件缺一不可：缓冲里还有未确认字节就意味着客户端仍可能 `Resume`，
/// 此时丢状态等于丢数据。
fn maybe_cleanup_finished(streams: &mut HashMap<StreamId, StreamState>, stream_id: StreamId) {
    let done = streams
        .get(&stream_id)
        .is_some_and(|s| s.ingress_fin && s.egress_done && s.shared.with(|b| b.is_fully_acked()));
    if done {
        tracing::debug!(stream = stream_id, "流双向结束，回收状态");
        remove_stream(streams, stream_id);
    }
}

fn remove_stream(streams: &mut HashMap<StreamId, StreamState>, stream_id: StreamId) {
    if let Some(state) = streams.remove(&stream_id) {
        state.stop();
    }
}

fn close_all(streams: &mut HashMap<StreamId, StreamState>) {
    for (_, state) in streams.drain() {
        state.stop();
    }
}

async fn send_open_err(
    frames: &mpsc::Sender<Frame>,
    stream_id: StreamId,
    code: ResetCode,
    msg: &str,
) {
    let _ = frames
        .send(Frame::OpenErr {
            stream_id,
            code,
            msg: msg.to_owned(),
        })
        .await;
}

async fn send_reset(frames: &mpsc::Sender<Frame>, stream_id: StreamId, code: ResetCode) {
    let _ = frames.send(Frame::Reset { stream_id, code }).await;
}

async fn send_resume_err(frames: &mpsc::Sender<Frame>, stream_id: StreamId, code: ResetCode) {
    let _ = frames.send(Frame::ResumeErr { stream_id, code }).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use srp_proto::TargetAddr;
    use tokio::io::{duplex, DuplexStream, ReadHalf, WriteHalf};
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    /// 测试用客户端：拿着 duplex 的一端，扮演真实 srp 客户端。
    struct Peer {
        write: WriteHalf<DuplexStream>,
        read: ReadHalf<DuplexStream>,
        session: JoinHandle<Result<()>>,
        buffered: BytesMut,
    }

    impl Peer {
        fn spawn(config: SessionConfig) -> Self {
            let (client, server) = duplex(1 << 20);
            let (client_read, client_write) = tokio::io::split(client);
            let (server_read, server_write) = tokio::io::split(server);
            Self {
                write: client_write,
                read: client_read,
                session: tokio::spawn(run_session(server_read, server_write, config)),
                buffered: BytesMut::new(),
            }
        }

        async fn send(&mut self, frame: Frame) {
            let mut wire = BytesMut::new();
            frame.encode(&mut wire);
            self.write
                .write_all(&wire)
                .await
                .expect("写入 helper stdin");
            self.write.flush().await.expect("flush helper stdin");
        }

        async fn recv(&mut self) -> Frame {
            loop {
                if let Some(frame) = Frame::decode(&mut self.buffered).expect("解码 helper 输出")
                {
                    return frame;
                }
                let mut scratch = [0u8; 8192];
                let n = timeout(Duration::from_secs(5), self.read.read(&mut scratch))
                    .await
                    .expect("等待 helper 响应超时")
                    .expect("读取 helper stdout");
                assert_ne!(n, 0, "helper 在预期响应之前就关闭了 stdout");
                self.buffered.extend_from_slice(&scratch[..n]);
            }
        }

        /// 完成握手，返回 `resumed` 标志。
        async fn handshake(&mut self, id: u8, resume: bool) -> bool {
            self.send(Frame::Hello {
                version: PROTO_VERSION,
                session_id: [id; 16],
                resume,
            })
            .await;
            match self.recv().await {
                Frame::HelloAck {
                    version,
                    session_id,
                    resumed,
                } => {
                    assert_eq!(version, PROTO_VERSION);
                    assert_eq!(session_id, [id; 16]);
                    resumed
                }
                other => panic!("期望 HelloAck，实际收到 {other:?}"),
            }
        }

        /// 关闭 stdin 触发优雅退出，并断言会话本身没有报错。
        async fn shutdown(mut self) {
            self.write.shutdown().await.expect("关闭 helper stdin");
            timeout(Duration::from_secs(5), &mut self.session)
                .await
                .expect("helper 未在超时内退出")
                .expect("会话任务 panic")
                .expect("会话应正常结束");
        }
    }

    fn loopback(port: u16) -> TargetAddr {
        TargetAddr::V4([127, 0, 0, 1], port)
    }

    /// 起一个监听器并返回端口；`accept` 由调用方决定何时进行。
    async fn listener() -> (TcpListener, u16) {
        let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = l.local_addr().expect("local_addr").port();
        (l, port)
    }

    // 1. 版本不匹配：先回 HelloAck{resumed:false}，然后进程退出。
    #[tokio::test]
    async fn hello_version_mismatch_nacks_then_exits() {
        let mut peer = Peer::spawn(SessionConfig::default());
        peer.send(Frame::Hello {
            version: PROTO_VERSION.wrapping_add(1),
            session_id: [9; 16],
            resume: false,
        })
        .await;
        assert_eq!(
            peer.recv().await,
            Frame::HelloAck {
                version: PROTO_VERSION,
                session_id: [9; 16],
                resumed: false,
            }
        );
        // 不需要关 stdin：版本不兼容时 helper 自己就该退出。
        let ended = timeout(Duration::from_secs(5), peer.session)
            .await
            .expect("helper 应在版本不匹配后立即退出")
            .expect("会话任务 panic");
        ended.expect("退出不应报错");
    }

    // 2. 首次 Hello 为 false；同 session_id + resume=true 且流仍在 → true。
    #[tokio::test]
    async fn hello_resume_requires_same_session_and_live_streams() {
        let (l, port) = listener().await;
        let accepted = tokio::spawn(async move { l.accept().await.expect("accept").0 });

        let mut peer = Peer::spawn(SessionConfig::default());
        assert!(!peer.handshake(7, false).await, "首次 Hello 不可能续传");

        // 必须真的持有一条流，否则"续传"没有任何意义。
        peer.send(Frame::Open {
            stream_id: 1,
            addr: loopback(port),
        })
        .await;
        assert_eq!(peer.recv().await, Frame::OpenOk { stream_id: 1 });
        let _egress = accepted.await.expect("egress 连接");

        assert!(peer.handshake(7, true).await, "同会话 + 活跃流应续传");
        assert!(
            !peer.handshake(8, true).await,
            "session_id 不同必须重置为 resumed=false"
        );
        // 上一步已经清空流目录，所以同 id 再来一次也无从续传。
        assert!(!peer.handshake(8, true).await, "无流可续时必须报 false");
        peer.shutdown().await;
    }

    // 3. Open 到真实 echo server：OpenOk → Data 进 → Ack 出 → echo 以 Data 回。
    #[tokio::test]
    async fn open_relays_data_and_acknowledges() {
        let (l, port) = listener().await;
        let echo = tokio::spawn(async move {
            let (mut sock, _) = l.accept().await.expect("accept");
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.expect("read");
            sock.write_all(&buf[..n]).await.expect("echo write");
        });

        let mut peer = Peer::spawn(SessionConfig::default());
        peer.handshake(1, false).await;
        peer.send(Frame::Open {
            stream_id: 3,
            addr: loopback(port),
        })
        .await;
        assert_eq!(peer.recv().await, Frame::OpenOk { stream_id: 3 });
        peer.send(Frame::Data {
            stream_id: 3,
            offset: 0,
            data: Bytes::from_static(b"payload"),
        })
        .await;

        // Ack 与 echo 的到达顺序由调度决定，两者都必须出现。
        //
        // 这里还必须容忍 Fin：测试的 echo 服务器回完数据就 drop socket，
        // helper 检测到出口 EOF 后如实发出 Fin 是**正确**行为，
        // 而它与 Ack/Data 的相对顺序同样由调度决定。
        let mut acked = false;
        let mut echoed = false;
        while !(acked && echoed) {
            match peer.recv().await {
                Frame::Ack {
                    stream_id: 3,
                    offset: 7,
                } => acked = true,
                Frame::Data {
                    stream_id: 3,
                    offset: 0,
                    data,
                } => {
                    assert_eq!(&data[..], b"payload");
                    echoed = true;
                }
                // 出口关闭导致的半关闭通知，与本用例的断言无关。
                Frame::Fin { stream_id: 3 } => {}
                other => panic!("意外的帧 {other:?}"),
            }
        }
        peer.send(Frame::Ack {
            stream_id: 3,
            offset: 7,
        })
        .await;
        echo.await.expect("echo server");
        peer.shutdown().await;
    }

    // 4. 必定失败的出口 → OpenErr{ConnectFailed}，且 msg 带 io::Error 描述。
    #[tokio::test]
    async fn failed_connect_reports_connect_failed() {
        let mut peer = Peer::spawn(SessionConfig::default());
        peer.handshake(1, false).await;
        peer.send(Frame::Open {
            stream_id: 4,
            addr: loopback(1),
        })
        .await;
        match peer.recv().await {
            Frame::OpenErr {
                stream_id: 4,
                code: ResetCode::ConnectFailed,
                msg,
            } => assert!(!msg.is_empty(), "必须带上失败原因"),
            other => panic!("期望 OpenErr(ConnectFailed)，实际 {other:?}"),
        }
        peer.shutdown().await;
    }

    // 5. 允许列表：不匹配 → Forbidden；通配匹配 → 放行。
    #[tokio::test]
    async fn allow_list_blocks_and_permits() {
        let (l, port) = listener().await;
        let accepted = tokio::spawn(async move { l.accept().await.expect("accept").0 });
        let config = SessionConfig {
            allow: AllowList::parse(&[format!("*:{port}")]).expect("解析允许列表"),
            ..SessionConfig::default()
        };
        let mut peer = Peer::spawn(config);
        peer.handshake(1, false).await;

        peer.send(Frame::Open {
            stream_id: 1,
            addr: loopback(port.wrapping_add(1)),
        })
        .await;
        assert!(matches!(
            peer.recv().await,
            Frame::OpenErr {
                stream_id: 1,
                code: ResetCode::Forbidden,
                ..
            }
        ));

        peer.send(Frame::Open {
            stream_id: 2,
            addr: loopback(port),
        })
        .await;
        assert_eq!(peer.recv().await, Frame::OpenOk { stream_id: 2 });
        let _egress = accepted.await.expect("egress 连接");
        peer.shutdown().await;
    }

    // 6 / 7 / 8. 未知流的 Data → Reset{UnknownStream}；Ping → Pong；
    // 未知流的 Resume → ResumeErr{UnknownStream}。
    #[tokio::test]
    async fn control_frames_get_protocol_replies() {
        let mut peer = Peer::spawn(SessionConfig::default());
        peer.handshake(1, false).await;

        peer.send(Frame::Data {
            stream_id: 99,
            offset: 0,
            data: Bytes::from_static(b"x"),
        })
        .await;
        assert_eq!(
            peer.recv().await,
            Frame::Reset {
                stream_id: 99,
                code: ResetCode::UnknownStream,
            }
        );

        peer.send(Frame::Resume {
            stream_id: 99,
            recv_offset: 0,
        })
        .await;
        assert_eq!(
            peer.recv().await,
            Frame::ResumeErr {
                stream_id: 99,
                code: ResetCode::UnknownStream,
            }
        );

        peer.send(Frame::Fin { stream_id: 99 }).await;
        assert_eq!(
            peer.recv().await,
            Frame::Reset {
                stream_id: 99,
                code: ResetCode::UnknownStream,
            }
        );

        peer.send(Frame::Ping { nonce: 0xdead_beef }).await;
        assert_eq!(peer.recv().await, Frame::Pong { nonce: 0xdead_beef });
        peer.shutdown().await;
    }

    // 9. Fin 半关闭：客户端发 Fin 后，出口仍能把剩余数据送回来。
    #[tokio::test]
    async fn fin_is_half_close_and_tail_still_arrives() {
        let (l, port) = listener().await;
        let server = tokio::spawn(async move {
            let (mut sock, _) = l.accept().await.expect("accept");
            // read_to_end 只有在收到 FIN 时才会返回，等于断言半关闭确实发生了。
            let mut got = Vec::new();
            sock.read_to_end(&mut got).await.expect("read_to_end");
            assert_eq!(&got, b"request");
            sock.write_all(b"tail response").await.expect("write tail");
        });

        let mut peer = Peer::spawn(SessionConfig::default());
        peer.handshake(1, false).await;
        peer.send(Frame::Open {
            stream_id: 5,
            addr: loopback(port),
        })
        .await;
        assert_eq!(peer.recv().await, Frame::OpenOk { stream_id: 5 });
        peer.send(Frame::Data {
            stream_id: 5,
            offset: 0,
            data: Bytes::from_static(b"request"),
        })
        .await;
        peer.send(Frame::Fin { stream_id: 5 }).await;

        let mut tail = None;
        let mut fin = false;
        while tail.is_none() || !fin {
            match peer.recv().await {
                Frame::Data {
                    stream_id: 5,
                    offset: 0,
                    data,
                } => tail = Some(data),
                Frame::Fin { stream_id: 5 } => fin = true,
                Frame::Ack { stream_id: 5, .. } => {}
                other => panic!("意外的帧 {other:?}"),
            }
        }
        assert_eq!(&tail.expect("tail")[..], b"tail response");
        assert!(fin, "出口 EOF 必须向客户端传播 Fin");
        server.await.expect("server");
        peer.shutdown().await;
    }

    // 10. 并发流上限：超出后回 OpenErr{Internal, "too many streams"}。
    #[tokio::test]
    async fn stream_limit_is_enforced() {
        let (l, port) = listener().await;
        // 出口一律连到真实监听端口：连接总会成功，流不会因失败提前消失，
        // 上限判定因此是确定性的（不依赖任何超时或网络可达性）。
        let mut egress = Vec::new();
        let config = SessionConfig {
            max_streams: 4,
            ..SessionConfig::default()
        };
        let mut peer = Peer::spawn(config);
        peer.handshake(1, false).await;

        for id in 1..=4u32 {
            peer.send(Frame::Open {
                stream_id: id,
                addr: loopback(port),
            })
            .await;
            assert_eq!(peer.recv().await, Frame::OpenOk { stream_id: id });
            egress.push(l.accept().await.expect("accept").0);
        }
        peer.send(Frame::Open {
            stream_id: 5,
            addr: loopback(port),
        })
        .await;
        match peer.recv().await {
            Frame::OpenErr {
                stream_id: 5,
                code: ResetCode::Internal,
                msg,
            } => assert_eq!(msg, "too many streams"),
            other => panic!("期望流上限错误，实际 {other:?}"),
        }
        drop(egress);
        peer.shutdown().await;
    }

    // 重复 stream_id 必须被拒绝，且不影响既有流。
    #[tokio::test]
    async fn duplicate_stream_id_is_rejected() {
        let (l, port) = listener().await;
        let accepted = tokio::spawn(async move { l.accept().await.expect("accept").0 });
        let mut peer = Peer::spawn(SessionConfig::default());
        peer.handshake(1, false).await;
        peer.send(Frame::Open {
            stream_id: 6,
            addr: loopback(port),
        })
        .await;
        assert_eq!(peer.recv().await, Frame::OpenOk { stream_id: 6 });
        let _egress = accepted.await.expect("egress");

        peer.send(Frame::Open {
            stream_id: 6,
            addr: loopback(port),
        })
        .await;
        match peer.recv().await {
            Frame::OpenErr {
                stream_id: 6,
                code: ResetCode::Internal,
                msg,
            } => assert_eq!(msg, "duplicate stream id"),
            other => panic!("期望 duplicate stream id，实际 {other:?}"),
        }
        peer.shutdown().await;
    }

    /// 活跃流的 Resume：回 ResumeOk 并携带 helper 侧已交付字节数，随后重发缺口。
    #[tokio::test]
    async fn resume_live_stream_rewinds_and_resends() {
        let (l, port) = listener().await;
        let server = tokio::spawn(async move {
            let (mut sock, _) = l.accept().await.expect("accept");
            sock.write_all(b"0123456789").await.expect("write");
            // 保持连接存活，避免 EOF 干扰断言。
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(sock);
        });

        let mut peer = Peer::spawn(SessionConfig::default());
        peer.handshake(1, false).await;
        peer.send(Frame::Open {
            stream_id: 8,
            addr: loopback(port),
        })
        .await;
        assert_eq!(peer.recv().await, Frame::OpenOk { stream_id: 8 });
        peer.send(Frame::Data {
            stream_id: 8,
            offset: 0,
            data: Bytes::from_static(b"abc"),
        })
        .await;

        let mut first = None;
        while first.is_none() {
            match peer.recv().await {
                Frame::Data {
                    stream_id: 8,
                    offset: 0,
                    data,
                } => first = Some(data),
                Frame::Ack { stream_id: 8, .. } => {}
                other => panic!("意外的帧 {other:?}"),
            }
        }
        assert_eq!(&first.expect("first")[..], b"0123456789");

        // 假装只收到了前 4 字节，其余在断线中丢失。
        peer.send(Frame::Resume {
            stream_id: 8,
            recv_offset: 4,
        })
        .await;
        assert_eq!(
            peer.recv().await,
            Frame::ResumeOk {
                stream_id: 8,
                recv_offset: 3,
            },
            "helper 必须回报自己已交付 3 字节"
        );
        match peer.recv().await {
            Frame::Data {
                stream_id: 8,
                offset: 4,
                data,
            } => assert_eq!(&data[..], b"456789", "必须精确重发缺口"),
            other => panic!("期望重发帧，实际 {other:?}"),
        }
        server.abort();
        peer.shutdown().await;
    }

    /// Resume 请求的偏移超过已发送量属于协议违规 → ResumeErr{ResumeImpossible}。
    #[tokio::test]
    async fn impossible_resume_destroys_stream() {
        let (l, port) = listener().await;
        let accepted = tokio::spawn(async move { l.accept().await.expect("accept").0 });
        let mut peer = Peer::spawn(SessionConfig::default());
        peer.handshake(1, false).await;
        peer.send(Frame::Open {
            stream_id: 9,
            addr: loopback(port),
        })
        .await;
        assert_eq!(peer.recv().await, Frame::OpenOk { stream_id: 9 });
        let _egress = accepted.await.expect("egress");

        peer.send(Frame::Resume {
            stream_id: 9,
            recv_offset: 4096,
        })
        .await;
        assert_eq!(
            peer.recv().await,
            Frame::ResumeErr {
                stream_id: 9,
                code: ResetCode::ResumeImpossible,
            }
        );
        // 流已销毁：后续 Data 应当按未知流处理。
        peer.send(Frame::Data {
            stream_id: 9,
            offset: 0,
            data: Bytes::from_static(b"z"),
        })
        .await;
        assert_eq!(
            peer.recv().await,
            Frame::Reset {
                stream_id: 9,
                code: ResetCode::UnknownStream,
            }
        );
        peer.shutdown().await;
    }

    /// 数据空洞是协议违规 → Reset{Internal} 并关流。
    #[tokio::test]
    async fn data_gap_resets_stream() {
        let (l, port) = listener().await;
        let accepted = tokio::spawn(async move { l.accept().await.expect("accept").0 });
        let mut peer = Peer::spawn(SessionConfig::default());
        peer.handshake(1, false).await;
        peer.send(Frame::Open {
            stream_id: 10,
            addr: loopback(port),
        })
        .await;
        assert_eq!(peer.recv().await, Frame::OpenOk { stream_id: 10 });
        let _egress = accepted.await.expect("egress");

        peer.send(Frame::Data {
            stream_id: 10,
            offset: 64,
            data: Bytes::from_static(b"gap"),
        })
        .await;
        assert_eq!(
            peer.recv().await,
            Frame::Reset {
                stream_id: 10,
                code: ResetCode::Internal,
            }
        );
        peer.shutdown().await;
    }

    /// 超前的 Ack（AckBeyondSent）→ Reset{Internal}。
    #[tokio::test]
    async fn bogus_ack_resets_stream() {
        let (l, port) = listener().await;
        let accepted = tokio::spawn(async move { l.accept().await.expect("accept").0 });
        let mut peer = Peer::spawn(SessionConfig::default());
        peer.handshake(1, false).await;
        peer.send(Frame::Open {
            stream_id: 11,
            addr: loopback(port),
        })
        .await;
        assert_eq!(peer.recv().await, Frame::OpenOk { stream_id: 11 });
        let _egress = accepted.await.expect("egress");

        peer.send(Frame::Ack {
            stream_id: 11,
            offset: 12345,
        })
        .await;
        assert_eq!(
            peer.recv().await,
            Frame::Reset {
                stream_id: 11,
                code: ResetCode::Internal,
            }
        );
        peer.shutdown().await;
    }

    /// 客户端 Reset 后出口 socket 必须真的关闭（对端读到 EOF）。
    #[tokio::test]
    async fn client_reset_closes_egress_socket() {
        let (l, port) = listener().await;
        let mut peer = Peer::spawn(SessionConfig::default());
        peer.handshake(1, false).await;
        peer.send(Frame::Open {
            stream_id: 12,
            addr: loopback(port),
        })
        .await;
        assert_eq!(peer.recv().await, Frame::OpenOk { stream_id: 12 });
        let (mut egress, _) = l.accept().await.expect("accept");

        peer.send(Frame::Reset {
            stream_id: 12,
            code: ResetCode::Normal,
        })
        .await;
        let mut sink = Vec::new();
        timeout(Duration::from_secs(5), egress.read_to_end(&mut sink))
            .await
            .expect("出口 socket 应在 Reset 后关闭")
            .expect("read_to_end");
        assert!(sink.is_empty());
        peer.shutdown().await;
    }

    /// stdin EOF 必须关掉所有出口 socket。
    #[tokio::test]
    async fn stdin_eof_closes_all_egress() {
        let (l, port) = listener().await;
        let mut peer = Peer::spawn(SessionConfig::default());
        peer.handshake(1, false).await;
        peer.send(Frame::Open {
            stream_id: 13,
            addr: loopback(port),
        })
        .await;
        assert_eq!(peer.recv().await, Frame::OpenOk { stream_id: 13 });
        let (mut egress, _) = l.accept().await.expect("accept");
        peer.shutdown().await;

        let mut sink = Vec::new();
        timeout(Duration::from_secs(5), egress.read_to_end(&mut sink))
            .await
            .expect("stdin EOF 后出口应关闭")
            .expect("read_to_end");
    }

    /// 空闲超时：没有任何帧抵达时 helper 自行退出，无需 stdin EOF。
    #[tokio::test]
    async fn idle_timeout_exits_session() {
        let config = SessionConfig {
            idle_timeout: Some(Duration::from_millis(120)),
            ..SessionConfig::default()
        };
        let peer = Peer::spawn(config);
        timeout(Duration::from_secs(5), peer.session)
            .await
            .expect("空闲超时后 helper 应退出")
            .expect("会话任务 panic")
            .expect("空闲退出不应报错");
    }

    /// 背压：窗口小于出口数据量时，未收到 Ack 前 helper 不会超发。
    #[tokio::test]
    async fn send_window_applies_backpressure() {
        let (l, port) = listener().await;
        let payload = vec![7u8; 64 * 1024];
        let expected = payload.clone();
        let server = tokio::spawn(async move {
            let (mut sock, _) = l.accept().await.expect("accept");
            sock.write_all(&payload).await.expect("write payload");
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let config = SessionConfig {
            stream_window: 4096,
            ..SessionConfig::default()
        };
        let mut peer = Peer::spawn(config);
        peer.handshake(1, false).await;
        peer.send(Frame::Open {
            stream_id: 14,
            addr: loopback(port),
        })
        .await;
        assert_eq!(peer.recv().await, Frame::OpenOk { stream_id: 14 });

        // 逐步确认，边确认边收：总字节数必须完整且顺序严格递增。
        let mut got = Vec::new();
        while got.len() < expected.len() {
            match peer.recv().await {
                Frame::Data {
                    stream_id: 14,
                    offset,
                    data,
                } => {
                    assert_eq!(offset as usize, got.len(), "偏移必须严格连续");
                    assert!(
                        data.len() <= 4096,
                        "单帧不可超过窗口，否则背压失效：{}",
                        data.len()
                    );
                    got.extend_from_slice(&data);
                    peer.send(Frame::Ack {
                        stream_id: 14,
                        offset: got.len() as u64,
                    })
                    .await;
                }
                other => panic!("意外的帧 {other:?}"),
            }
        }
        assert_eq!(got, expected, "背压路径不得丢字节");
        server.abort();
        peer.shutdown().await;
    }

    /// 域名目标由远端解析：这里只验证解析失败会映射成 ConnectFailed。
    #[tokio::test]
    async fn unresolvable_domain_maps_to_connect_failed() {
        let mut peer = Peer::spawn(SessionConfig::default());
        peer.handshake(1, false).await;
        // .invalid 是 RFC 2606 保留 TLD，永远不会解析成功。
        peer.send(Frame::Open {
            stream_id: 15,
            addr: TargetAddr::Domain("srp-helper-test.invalid".into(), 80),
        })
        .await;
        match peer.recv().await {
            Frame::OpenErr {
                stream_id: 15,
                code: ResetCode::ConnectFailed,
                msg,
            } => assert!(!msg.is_empty()),
            other => panic!("期望 ConnectFailed，实际 {other:?}"),
        }
        peer.shutdown().await;
    }

    /// 默认配置必须保留 512 的硬上限，且非法参数会被拒绝。
    #[test]
    fn cli_maps_to_session_config() {
        let cli = Cli::parse_from(["srp-helper"]);
        let config = SessionConfig::from_cli(&cli).expect("默认配置合法");
        assert_eq!(config.max_streams, MAX_STREAMS);
        assert_eq!(config.stream_window, DEFAULT_STREAM_WINDOW);
        assert!(config.idle_timeout.is_none(), "默认不启用空闲超时");
        assert!(config.allow.is_empty(), "默认允许所有目标");

        let cli = Cli::parse_from([
            "srp-helper",
            "--allow",
            "*.example.com:443",
            "--idle-timeout",
            "30",
            "--stream-window",
            "8192",
        ]);
        let config = SessionConfig::from_cli(&cli).expect("显式配置合法");
        assert_eq!(config.idle_timeout, Some(Duration::from_secs(30)));
        assert_eq!(config.stream_window, 8192);
        assert!(!config.allow.is_empty());

        let bad = Cli::parse_from(["srp-helper", "--stream-window", "0"]);
        assert!(SessionConfig::from_cli(&bad).is_err(), "窗口为 0 必须拒绝");

        let bad = Cli::parse_from(["srp-helper", "--allow", "nope:port"]);
        assert!(SessionConfig::from_cli(&bad).is_err(), "非法模式必须拒绝");
    }
}
