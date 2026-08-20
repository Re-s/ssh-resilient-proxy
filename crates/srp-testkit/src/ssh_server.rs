//! 进程内的测试用 SSH 服务器，基于 `russh::server`。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::server::{Auth, ChannelOpenHandle, Handler, Msg, Session};
use russh::{Channel, ChannelId, ChannelOpenFailure};
use socket2::Socket;
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::task::JoinHandle;

use crate::net_util::{dup_socket, hard_reset_and_drop, hard_reset_dup};

/// 生成一个随机 Ed25519 私钥。
///
/// **为什么不用 workspace 的 `rand`**：`ssh_key::PrivateKey::random` 要求
/// `R: rand_core@0.10::CryptoRng`，而 workspace 里的 `rand` 是 0.9（对应
/// `rand_core@0.9`）。两个 `CryptoRng` 是**不同的 trait**，直接传
/// `&mut rand::rng()`（rand 0.9）会报 trait 不满足。russh 也**没有**re-export
/// `rand`，所以唯一稳妥的入口是 russh 自己暴露的 [`russh::keys::key::safe_rng`]，
/// 它返回 russh 依赖的那个 rand（0.10）的 `impl CryptoRng`。
pub fn generate_ed25519_key() -> anyhow::Result<PrivateKey> {
    let mut rng = russh::keys::key::safe_rng();
    PrivateKey::random(&mut rng, Algorithm::Ed25519)
        .map_err(|e| anyhow::anyhow!("生成 Ed25519 私钥失败: {e}"))
}

/// 测试服务器的行为配置。
///
/// 推荐用 `..Default::default()` 的方式构造，后续新增字段不会破坏调用方。
#[derive(Clone, Debug)]
pub struct TestServerConfig {
    /// 唯一允许登录的用户名。
    pub username: String,
    /// 允许的密码；`None` 表示关闭 password 认证。
    pub password: Option<String>,
    /// 允许的客户端公钥；`None` 表示关闭 publickey 认证。
    pub authorized_key: Option<PublicKey>,
    /// 是否允许 `direct-tcpip` 通道（默认 `true`）。
    pub allow_direct_tcpip: bool,
    /// 是否允许 session 通道 + `exec` 请求（默认 `true`），helper 模式需要。
    pub allow_exec: bool,
    /// 覆盖客户端请求的命令：`Some(cmd)` 时无论客户端 exec 什么都执行 `sh -c cmd`；
    /// `None` 时把客户端的 exec command 原样交给 `sh -c` 执行。
    pub exec_override: Option<String>,
    /// 服务器主机私钥；`None` 时随机生成一个 Ed25519 密钥。
    ///
    /// 想模拟"服务器重启但 host key 不变"时，把上一次的私钥传进来。
    pub host_key: Option<PrivateKey>,
    /// 监听地址；`None` 时用 `127.0.0.1:0`（随机端口）。
    pub listen_addr: Option<SocketAddr>,
}

impl Default for TestServerConfig {
    fn default() -> Self {
        Self {
            username: "tester".to_string(),
            password: None,
            authorized_key: None,
            allow_direct_tcpip: true,
            allow_exec: true,
            exec_override: None,
            host_key: None,
            listen_addr: None,
        }
    }
}

/// 内存中的测试用 SSH 服务器。
///
/// 这是一个只有构造函数的门面类型，真正的操作都在 [`TestSshServerHandle`] 上。
pub struct TestSshServer;

impl TestSshServer {
    /// 启动服务器并返回控制句柄。监听在 `cfg.listen_addr`（默认 `127.0.0.1:0`）。
    ///
    /// 认证规则：用户名必须等于 `cfg.username`；publickey 必须等于
    /// `cfg.authorized_key`；password 必须等于 `cfg.password`。两者都为 `None`
    /// 时没有任何认证方式可用（此时只适合测试"认证一定失败"的路径）。
    pub async fn start(cfg: TestServerConfig) -> anyhow::Result<TestSshServerHandle> {
        let host_key = match cfg.host_key.clone() {
            Some(key) => key,
            None => generate_ed25519_key()?,
        };
        let host_public_key = host_key.public_key().clone();

        let bind_addr = cfg
            .listen_addr
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));
        let listener = TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("测试 SSH 服务器无法绑定 {bind_addr}"))?;
        let addr = listener.local_addr().context("读取监听地址失败")?;

        let russh_config = Arc::new(russh::server::Config {
            // 测试里不希望被 russh 的 1 秒常量时间拒绝拖慢
            auth_rejection_time: std::time::Duration::from_millis(0),
            auth_rejection_time_initial: Some(std::time::Duration::from_millis(0)),
            keys: vec![host_key],
            // 测试会刻意让连接空转，别让 russh 主动超时干扰断线判定
            inactivity_timeout: Some(std::time::Duration::from_secs(600)),
            nodelay: true,
            ..Default::default()
        });

        let state = Arc::new(ServerState {
            cfg: Arc::new(cfg),
            conns: Mutex::new(HashMap::new()),
            next_conn_id: AtomicU64::new(1),
            paused: AtomicBool::new(false),
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
        });

        let accept_state = Arc::clone(&state);
        let accept_loop = tokio::spawn(async move {
            accept_loop(listener, russh_config, accept_state).await;
        });

        Ok(TestSshServerHandle {
            addr,
            host_key: host_public_key,
            state,
            accept_loop: Some(accept_loop),
        })
    }
}

/// 测试 SSH 服务器的控制句柄。
pub struct TestSshServerHandle {
    /// 实际监听地址（默认使用 `127.0.0.1:0` 分配的随机端口）。
    pub addr: SocketAddr,
    /// 服务器主机公钥，供客户端做 host key 校验。
    pub host_key: PublicKey,
    state: Arc<ServerState>,
    accept_loop: Option<JoinHandle<()>>,
}

impl TestSshServerHandle {
    /// 立即强杀所有已建立的 SSH 连接（模拟断网 / 服务端进程被打断），
    /// 但监听端口继续 accept —— 用于测试客户端自愈重连。
    ///
    /// 实现方式：accept 时给每条连接 `dup(2)` 一个 fd 留在手上，这里对它
    /// `SO_LINGER=0` + `shutdown(BOTH)`，再关闭该 fd。客户端会立刻读到 EOF/RST，
    /// `russh::client::Handle::is_closed()` 随之变 `true`。
    pub fn kill_all_connections(&self) {
        let conns: Vec<ConnEntry> = {
            let mut guard = self.state.conns.lock().expect("连接表互斥锁被污染");
            guard.drain().map(|(_, entry)| entry).collect()
        };
        for entry in &conns {
            hard_reset_dup(&entry.socket);
        }
        // drop(conns) 关闭 dup 出来的 fd
    }

    /// 停止服务新连接（模拟服务器完全不可达）。
    ///
    /// 暂停期间仍然会 `accept`，但连接会被立刻 RST 掉，所以客户端得到的是
    /// **确定且立即**的连接错误，而不是无限等待 SSH banner。可用 [`Self::resume_accept`] 恢复。
    pub fn pause_accept(&self) {
        self.state.paused.store(true, Ordering::SeqCst);
    }

    /// 恢复服务新连接。
    pub fn resume_accept(&self) {
        self.state.paused.store(false, Ordering::SeqCst);
    }

    /// 当前是否处于暂停状态。
    pub fn is_paused(&self) -> bool {
        self.state.paused.load(Ordering::SeqCst)
    }

    /// 已经进入 SSH 协议处理的连接总数（不含暂停期间被 RST 掉的）。
    pub fn accepted_count(&self) -> u64 {
        self.state.accepted.load(Ordering::SeqCst)
    }

    /// 暂停期间被立刻切断的连接数。
    pub fn rejected_count(&self) -> u64 {
        self.state.rejected.load(Ordering::SeqCst)
    }

    /// 当前仍然存活的 SSH 连接数。
    pub fn live_connection_count(&self) -> usize {
        self.state.conns.lock().expect("连接表互斥锁被污染").len()
    }

    /// 彻底关停：停止 accept、强杀所有连接、等待 accept 任务退出并释放端口。
    ///
    /// 用 `abort()` 而不是通知式退出：`accept()` 阻塞在 epoll 上，
    /// 通知式退出会与"通知早于 waiter 登记"产生竞态，导致 `await` 永久挂住。
    /// abort 之后 `join.await` 会立即以 `Cancelled` 返回，监听 socket 随任务一起释放。
    pub async fn shutdown(mut self) {
        if let Some(join) = self.accept_loop.take() {
            join.abort();
            let _ = join.await;
        }
        self.kill_all_connections();
    }
}

impl Drop for TestSshServerHandle {
    fn drop(&mut self) {
        // 没有显式 shutdown 时也要确保后台任务和连接不泄漏。
        if let Some(join) = self.accept_loop.take() {
            join.abort();
        }
        let conns: Vec<ConnEntry> = {
            match self.state.conns.lock() {
                Ok(mut guard) => guard.drain().map(|(_, entry)| entry).collect(),
                Err(_) => Vec::new(),
            }
        };
        for entry in &conns {
            hard_reset_dup(&entry.socket);
        }
    }
}

/// 一条已建立连接的登记项。
struct ConnEntry {
    /// `dup(2)` 出来的 socket 句柄，用于强杀这条连接。
    socket: Socket,
    /// russh 的会话句柄，用于优雅断开（当前保留给后续扩展使用）。
    #[allow(dead_code)]
    handle: russh::server::Handle,
}

/// 服务器共享状态。
struct ServerState {
    cfg: Arc<TestServerConfig>,
    conns: Mutex<HashMap<u64, ConnEntry>>,
    next_conn_id: AtomicU64,
    paused: AtomicBool,
    accepted: AtomicU64,
    rejected: AtomicU64,
}

/// accept 主循环。任务被 abort 时整个循环随之结束。
async fn accept_loop(
    listener: TcpListener,
    russh_config: Arc<russh::server::Config>,
    state: Arc<ServerState>,
) {
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!("测试 SSH 服务器 accept 失败: {e}");
                continue;
            }
        };

        if state.paused.load(Ordering::SeqCst) {
            state.rejected.fetch_add(1, Ordering::SeqCst);
            hard_reset_and_drop(socket);
            continue;
        }

        state.accepted.fetch_add(1, Ordering::SeqCst);
        let conn_state = Arc::clone(&state);
        let config = Arc::clone(&russh_config);
        tokio::spawn(async move {
            serve_connection(socket, peer, config, conn_state).await;
        });
    }
}

/// 处理单条连接：登记 dup fd + 跑完 russh 会话 + 注销。
async fn serve_connection(
    socket: TcpStream,
    peer: SocketAddr,
    config: Arc<russh::server::Config>,
    state: Arc<ServerState>,
) {
    // 必须在 socket 所有权交给 russh 之前 dup 出一个句柄，
    // 否则之后没有任何办法从外部强杀这条连接。
    let dup = match dup_socket(&socket) {
        Ok(dup) => dup,
        Err(e) => {
            tracing::warn!("dup 连接 fd 失败: {e}");
            return;
        }
    };

    let handler = TestHandler {
        cfg: Arc::clone(&state.cfg),
        peer,
        session_channels: HashMap::new(),
    };

    let running = match russh::server::run_stream(config, socket, handler).await {
        Ok(running) => running,
        Err(e) => {
            tracing::debug!("SSH 连接握手阶段失败: {e}");
            return;
        }
    };

    let conn_id = state.next_conn_id.fetch_add(1, Ordering::SeqCst);
    {
        let mut guard = state.conns.lock().expect("连接表互斥锁被污染");
        guard.insert(
            conn_id,
            ConnEntry {
                socket: dup,
                handle: running.handle(),
            },
        );
    }

    if let Err(e) = running.await {
        tracing::debug!("SSH 会话结束: {e}");
    }

    let mut guard = state.conns.lock().expect("连接表互斥锁被污染");
    guard.remove(&conn_id);
}

/// 每条连接一个的 russh 服务端回调实现。
struct TestHandler {
    cfg: Arc<TestServerConfig>,
    peer: SocketAddr,
    /// 已打开但还没收到 `exec` 的 session 通道。
    session_channels: HashMap<ChannelId, Channel<Msg>>,
}

impl Handler for TestHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        let ok = user == self.cfg.username
            && self
                .cfg
                .password
                .as_deref()
                .is_some_and(|expected| expected == password);
        tracing::debug!("auth_password user={user} peer={} ok={ok}", self.peer);
        Ok(if ok { Auth::Accept } else { Auth::reject() })
    }

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        let ok = user == self.cfg.username
            && self
                .cfg
                .authorized_key
                .as_ref()
                .is_some_and(|expected| expected == key);
        tracing::debug!("auth_publickey user={user} peer={} ok={ok}", self.peer);
        Ok(if ok { Auth::Accept } else { Auth::reject() })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.cfg.allow_exec {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        // 先记下通道，等 exec_request 到了再启动子进程。
        self.session_channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.cfg.allow_direct_tcpip {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }

        tracing::debug!(
            "direct-tcpip {host_to_connect}:{port_to_connect} (来自 {originator_address}:{originator_port})"
        );

        let port = match u16::try_from(port_to_connect) {
            Ok(port) => port,
            Err(_) => {
                reply.reject(ChannelOpenFailure::ConnectFailed).await;
                return Ok(());
            }
        };

        match TcpStream::connect((host_to_connect, port)).await {
            Ok(upstream) => {
                // 必须先 accept，客户端才会认为通道可用。
                reply.accept().await;
                tokio::spawn(async move {
                    let mut ssh_stream = channel.into_stream();
                    let mut upstream = upstream;
                    // copy_bidirectional 会把任一侧的 EOF 变成另一侧的 shutdown，
                    // 所以 SSH EOF ↔ TCP FIN 是双向传播的。
                    if let Err(e) =
                        tokio::io::copy_bidirectional(&mut ssh_stream, &mut upstream).await
                    {
                        tracing::debug!("direct-tcpip 桥接结束: {e}");
                    }
                });
            }
            Err(e) => {
                tracing::debug!("direct-tcpip 连接 {host_to_connect}:{port} 失败: {e}");
                reply.reject(ChannelOpenFailure::ConnectFailed).await;
            }
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let requested = String::from_utf8_lossy(data).to_string();
        let Some(chan) = self.session_channels.remove(&channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        if !self.cfg.allow_exec {
            session.channel_failure(channel)?;
            return Ok(());
        }

        let command = self
            .cfg
            .exec_override
            .clone()
            .unwrap_or_else(|| requested.clone());
        tracing::debug!("exec_request 请求={requested:?} 实际执行={command:?}");

        match spawn_exec_bridge(chan, command) {
            Ok(()) => session.channel_success(channel)?,
            Err(e) => {
                tracing::warn!("启动 exec 子进程失败: {e}");
                session.channel_failure(channel)?;
            }
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // 本 testkit 不支持交互式 shell，明确回失败，避免客户端一直等回复。
        self.session_channels.remove(&channel);
        session.channel_failure(channel)?;
        Ok(())
    }
}

/// 启动 `sh -c <command>` 并把它的 stdio 桥接到 SSH 通道。
fn spawn_exec_bridge(channel: Channel<Msg>, command: String) -> anyhow::Result<()> {
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(&command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("无法启动子进程: sh -c {command:?}"))?;

    let mut stdin = child.stdin.take().context("子进程 stdin 不可用")?;
    let mut stdout = child.stdout.take().context("子进程 stdout 不可用")?;
    let mut stderr = child.stderr.take().context("子进程 stderr 不可用")?;

    let (mut read_half, write_half) = channel.split();

    // SSH data → 子进程 stdin；SSH EOF（或通道关闭）→ 关闭 stdin，向子进程传播 EOF。
    let stdin_pump = tokio::spawn(async move {
        {
            let mut reader = read_half.make_reader();
            if let Err(e) = tokio::io::copy(&mut reader, &mut stdin).await {
                tracing::debug!("exec stdin 泵结束: {e}");
            }
        }
        drop(stdin);
    });

    // 子进程 stdout → SSH data
    let mut stdout_writer = write_half.make_writer();
    let stdout_pump = tokio::spawn(async move {
        if let Err(e) = tokio::io::copy(&mut stdout, &mut stdout_writer).await {
            tracing::debug!("exec stdout 泵结束: {e}");
        }
    });

    // 子进程 stderr → SSH extended_data(1)
    let mut stderr_writer = write_half.make_writer_ext(Some(1));
    let stderr_pump = tokio::spawn(async move {
        if let Err(e) = tokio::io::copy(&mut stderr, &mut stderr_writer).await {
            tracing::debug!("exec stderr 泵结束: {e}");
        }
    });

    tokio::spawn(async move {
        // 先等两个输出泵结束（意味着子进程已关闭 stdout/stderr），
        // 保证 exit_status 排在所有输出之后。
        let _ = stdout_pump.await;
        let _ = stderr_pump.await;

        let code = match child.wait().await {
            Ok(status) => status.code().unwrap_or(255) as u32,
            Err(e) => {
                tracing::debug!("等待子进程失败: {e}");
                255
            }
        };

        let _ = write_half.exit_status(code).await;
        let _ = write_half.eof().await;
        let _ = write_half.close().await;
        stdin_pump.abort();
    });

    Ok(())
}
