//! `FlakyProxy`：TCP 层故障注入代理。
//!
//! 把它插在客户端与真实 SSH 服务器之间，就能在不碰服务端的情况下精确控制
//! "断网"发生的时刻与时长，是测试"断网自愈"最可控的手段。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context as _;
use socket2::Socket;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::net_util::{dup_socket, hard_reset_and_drop, hard_reset_dup};

/// TCP 故障注入代理的门面类型。
pub struct FlakyProxy;

impl FlakyProxy {
    /// 在 `127.0.0.1:0` 上监听，并把每条连接转发到 `upstream`。
    pub async fn start(upstream: SocketAddr) -> anyhow::Result<FlakyProxyHandle> {
        Self::start_on(SocketAddr::from(([127, 0, 0, 1], 0)), upstream).await
    }

    /// 指定监听地址的版本（端口写 0 表示随机端口）。
    pub async fn start_on(
        listen: SocketAddr,
        upstream: SocketAddr,
    ) -> anyhow::Result<FlakyProxyHandle> {
        let listener = TcpListener::bind(listen)
            .await
            .with_context(|| format!("FlakyProxy 无法绑定 {listen}"))?;
        let listen_addr = listener
            .local_addr()
            .context("读取 FlakyProxy 监听地址失败")?;

        let state = Arc::new(ProxyState {
            upstream,
            conns: Mutex::new(HashMap::new()),
            next_conn_id: AtomicU64::new(1),
            blackhole: AtomicBool::new(false),
            swallow: AtomicBool::new(false),
            chunk_size: AtomicUsize::new(0),
            delay_us: AtomicU64::new(0),
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
        });

        let accept_state = Arc::clone(&state);
        let task = tokio::spawn(async move {
            accept_loop(listener, accept_state).await;
        });

        Ok(FlakyProxyHandle {
            listen_addr,
            state,
            task: Some(task),
        })
    }
}

/// 故障注入代理的控制句柄。所有控制方法都是同步的，调用后立即生效。
pub struct FlakyProxyHandle {
    /// 客户端应该连接的地址。
    pub listen_addr: SocketAddr,
    state: Arc<ProxyState>,
    task: Option<JoinHandle<()>>,
}

impl FlakyProxyHandle {
    /// 上游（真实服务器）地址。
    pub fn upstream_addr(&self) -> SocketAddr {
        self.state.upstream
    }

    /// 切断当前所有连接（两侧都 `SO_LINGER=0` + `shutdown(BOTH)`，即发 RST），
    /// 新连接仍可建立。
    pub fn cut_now(&self) {
        let conns: Vec<ConnEntry> = {
            let mut guard = self.state.conns.lock().expect("代理连接表互斥锁被污染");
            guard.drain().map(|(_, entry)| entry).collect()
        };
        for entry in &conns {
            hard_reset_dup(&entry.client);
            hard_reset_dup(&entry.upstream);
        }
    }

    /// 进入/退出"黑洞"模式。
    ///
    /// `on = true`：现有连接立刻被切断，之后到来的新连接一被 accept 就直接 RST，
    /// 因此客户端的 SSH 握手会**立即失败**（注意：由于监听 socket 仍然存在，
    /// 内核会先完成 TCP 三次握手，所以失败点在读 SSH banner 而不是 `connect(2)`）。
    ///
    /// `on = false`：恢复正常转发。
    pub fn blackhole(&self, on: bool) {
        self.state.blackhole.store(on, Ordering::SeqCst);
        if on {
            self.cut_now();
        }
    }

    /// 是否处于黑洞模式。
    pub fn is_blackhole(&self) -> bool {
        self.state.blackhole.load(Ordering::SeqCst)
    }

    /// "静默丢包"模式：连接保持建立，但两个方向读到的数据被直接丢弃。
    ///
    /// 用于模拟"链路还在但数据到不了"，可触发客户端的 keepalive / 应用层超时逻辑。
    pub fn swallow_data(&self, on: bool) {
        self.state.swallow.store(on, Ordering::SeqCst);
    }

    /// 限速：每次最多转发 `chunk_size` 字节，并在每块之后等待 `delay`。
    ///
    /// `chunk_size = 0` 表示不限制块大小，`delay = Duration::ZERO` 表示不延迟。
    pub fn set_throttle(&self, chunk_size: usize, delay: Duration) {
        self.state.chunk_size.store(chunk_size, Ordering::SeqCst);
        self.state.delay_us.store(
            delay.as_micros().min(u64::MAX as u128) as u64,
            Ordering::SeqCst,
        );
    }

    /// 累计**成功进入转发**的连接数（黑洞期间被 RST 的不计入）。
    ///
    /// 测试里可以用它断言"确实发生了 N 次重连"。
    pub fn accepted_count(&self) -> u64 {
        self.state.accepted.load(Ordering::SeqCst)
    }

    /// 累计在黑洞模式下被立刻切断的连接数。
    pub fn rejected_count(&self) -> u64 {
        self.state.rejected.load(Ordering::SeqCst)
    }

    /// 当前仍在转发的连接数。
    pub fn live_connection_count(&self) -> usize {
        self.state
            .conns
            .lock()
            .expect("代理连接表互斥锁被污染")
            .len()
    }

    /// 客户端 → 上游 已转发字节数。
    pub fn bytes_client_to_upstream(&self) -> u64 {
        self.state.bytes_up.load(Ordering::SeqCst)
    }

    /// 上游 → 客户端 已转发字节数。
    pub fn bytes_upstream_to_client(&self) -> u64 {
        self.state.bytes_down.load(Ordering::SeqCst)
    }

    /// 彻底关停代理：停止 accept、切断所有连接、释放监听端口。
    pub async fn shutdown(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
        self.cut_now();
    }
}

impl Drop for FlakyProxyHandle {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        let conns: Vec<ConnEntry> = match self.state.conns.lock() {
            Ok(mut guard) => guard.drain().map(|(_, entry)| entry).collect(),
            Err(_) => Vec::new(),
        };
        for entry in &conns {
            hard_reset_dup(&entry.client);
            hard_reset_dup(&entry.upstream);
        }
    }
}

/// 一条代理连接的两端 dup 句柄。
struct ConnEntry {
    client: Socket,
    upstream: Socket,
}

struct ProxyState {
    upstream: SocketAddr,
    conns: Mutex<HashMap<u64, ConnEntry>>,
    next_conn_id: AtomicU64,
    blackhole: AtomicBool,
    swallow: AtomicBool,
    chunk_size: AtomicUsize,
    delay_us: AtomicU64,
    accepted: AtomicU64,
    rejected: AtomicU64,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
}

async fn accept_loop(listener: TcpListener, state: Arc<ProxyState>) {
    loop {
        let (client, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::debug!("FlakyProxy accept 结束: {e}");
                return;
            }
        };

        if state.blackhole.load(Ordering::SeqCst) {
            state.rejected.fetch_add(1, Ordering::SeqCst);
            hard_reset_and_drop(client);
            continue;
        }

        let conn_state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_conn(client, conn_state).await {
                tracing::debug!("FlakyProxy 连接处理结束: {e}");
            }
        });
    }
}

async fn handle_conn(client: TcpStream, state: Arc<ProxyState>) -> anyhow::Result<()> {
    let upstream = match TcpStream::connect(state.upstream).await {
        Ok(stream) => stream,
        Err(e) => {
            // 连不上上游：直接把客户端也 RST 掉，让它立刻感知失败。
            hard_reset_and_drop(client);
            return Err(e).context("FlakyProxy 连接上游失败");
        }
    };
    let _ = client.set_nodelay(true);
    let _ = upstream.set_nodelay(true);

    // 在 split 前 dup 出两端句柄，cut_now 才有东西可打。
    let client_dup = dup_socket(&client).context("dup 客户端 fd 失败")?;
    let upstream_dup = dup_socket(&upstream).context("dup 上游 fd 失败")?;

    let conn_id = state.next_conn_id.fetch_add(1, Ordering::SeqCst);
    state.accepted.fetch_add(1, Ordering::SeqCst);
    {
        let mut guard = state.conns.lock().expect("代理连接表互斥锁被污染");
        guard.insert(
            conn_id,
            ConnEntry {
                client: client_dup,
                upstream: upstream_dup,
            },
        );
    }

    let (client_read, client_write) = client.into_split();
    let (upstream_read, upstream_write) = upstream.into_split();

    let up_state = Arc::clone(&state);
    let up = tokio::spawn(async move {
        pump(client_read, upstream_write, up_state, Direction::Up).await;
    });
    let down_state = Arc::clone(&state);
    let down = tokio::spawn(async move {
        pump(upstream_read, client_write, down_state, Direction::Down).await;
    });

    let _ = up.await;
    let _ = down.await;

    let mut guard = state.conns.lock().expect("代理连接表互斥锁被污染");
    guard.remove(&conn_id);
    Ok(())
}

#[derive(Copy, Clone)]
enum Direction {
    Up,
    Down,
}

/// 单向数据泵：负责限速、静默丢弃与 EOF 传播。
async fn pump(
    mut from: OwnedReadHalf,
    mut to: OwnedWriteHalf,
    state: Arc<ProxyState>,
    dir: Direction,
) {
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let limit = match state.chunk_size.load(Ordering::SeqCst) {
            0 => buf.len(),
            n => n.min(buf.len()),
        };
        let n = match from.read(&mut buf[..limit]).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => return, // 连接被 RST：直接放弃，不必再传播 EOF
        };

        if !state.swallow.load(Ordering::SeqCst) {
            if to.write_all(&buf[..n]).await.is_err() {
                return;
            }
            match dir {
                Direction::Up => state.bytes_up.fetch_add(n as u64, Ordering::SeqCst),
                Direction::Down => state.bytes_down.fetch_add(n as u64, Ordering::SeqCst),
            };
        }

        let delay_us = state.delay_us.load(Ordering::SeqCst);
        if delay_us > 0 {
            tokio::time::sleep(Duration::from_micros(delay_us)).await;
        }
    }
    // 正常 EOF：把 FIN 传播到另一侧，保证半关闭语义可被观察。
    let _ = to.shutdown().await;
}
