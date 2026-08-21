//! SSH 会话管理器：保持连接 + 断网自愈。
//!
//! # 为什么需要一个独立的管理器
//!
//! `russh` 的 `client::Handle` 是一次性的：底层 TCP 一断，这个 handle 就
//! 永久失效，所有由它派生的通道随之报废。要做到"断网自愈"，必须在它之上
//! 加一层间接：使用者持有的不是 handle 本身，而是一个**会话代号（epoch）**
//! 加上"取当前活跃会话"的能力。
//!
//! # 三条自愈机制
//!
//! 1. **主动保活**：`keepalive_interval` 让 russh 周期性发送 SSH 保活请求。
//!    NAT 与状态防火墙会静默丢弃空闲连接，主动探测让死链在几十秒内暴露，
//!    而不是等用户发起请求时才失败。
//! 2. **失败即重连**：监督循环发现会话失效后按带抖动的指数退避重连，
//!    成功后 epoch 自增，旧会话的所有引用自然失效。
//! 3. **请求侧等待**：隧道不可用期间新到达的代理请求不会立即报错，
//!    而是在 `dial_wait` 内等待隧道恢复。用户视角就是"卡一下然后好了"。
//!
//! # 关于"掉包恢复"的边界
//!
//! 在 `DirectTcpip` 模式下，远端出口 TCP 由 sshd 持有，SSH 一断 sshd
//! 必然关闭它——**任何**纯客户端实现都无法让这条出口连接续命，这是
//! 协议边界。该模式能做到的是：秒级重连、重连期间新请求排队不失败、
//! 以及尚未开始转发的请求被完整重放。字节级续传需要 `Helper` 模式。

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context as _};
use russh::client::{self, Handle};
use russh::keys::{HashAlg, PrivateKeyWithHashAlg};
use tokio::sync::{watch, Mutex, Notify};
use tracing::{debug, info, warn};

use super::backoff::Backoff;
use super::config::{AuthMethod, Config, HostKeyPolicy};
use super::handler::{ClientHandler, DisconnectSignal};

/// 跨平台连接 SSH 代理。
///
/// Unix: 读取 `SSH_AUTH_SOCK` 环境变量连接 Unix domain socket。
/// Windows: 使用 Pageant（PuTTY agent）协议。
///
/// 返回类型在两个平台上不同（UnixStream vs PageantStream），
/// 但两者都实现了 `AgentStream`，不影响调用方使用。
#[cfg(unix)]
async fn connect_ssh_agent(
) -> anyhow::Result<russh::keys::agent::client::AgentClient<tokio::net::UnixStream>> {
    russh::keys::agent::client::AgentClient::connect_env()
        .await
        .map_err(|e| anyhow!("SSH_AUTH_SOCK 未设置或代理不可达: {e}"))
}

#[cfg(windows)]
async fn connect_ssh_agent() -> anyhow::Result<
    russh::keys::agent::client::AgentClient<russh::keys::agent::pageant::PageantStream>,
> {
    russh::keys::agent::client::AgentClient::connect_pageant()
        .await
        .map_err(|e| anyhow!("无法连接 Pageant (PuTTY agent): {e}"))
}

/// 会话代号。每次成功建连自增，用于识别"引用是否属于当前会话"。
pub type Epoch = u64;

/// 隧道对外暴露的连接状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    /// 尚未建立首个连接。
    Connecting,
    /// 会话可用。
    Up(Epoch),
    /// 会话已断，正在退避重连。
    Reconnecting { attempts: u32 },
    /// 已被显式关停，不再重连。
    Closed,
}

impl TunnelState {
    pub fn is_up(&self) -> bool {
        matches!(self, Self::Up(_))
    }
}

/// 一次成功建立的 SSH 会话。
pub struct Session {
    pub epoch: Epoch,
    pub handle: Handle<ClientHandler>,
    /// 由 Handler 在收到断连信号时触发。
    disconnect: Arc<DisconnectSignal>,
}

impl Session {
    /// 该会话是否已失效。
    ///
    /// 两路判断：`is_closed()` 反映 russh 内部通道是否已关，
    /// `disconnect` 由 Handler 回调置位。任何一路成立即视为死链——
    /// 宁可多重连一次，也不能把请求交给已死的会话。
    pub fn is_dead(&self) -> bool {
        self.handle.is_closed() || self.disconnect.is_triggered()
    }
}

/// SSH 隧道管理器。
pub struct TunnelManager {
    cfg: Arc<Config>,
    /// 当前活跃会话。`None` 表示隧道当前不可用。
    current: Mutex<Option<Arc<Session>>>,
    /// 状态广播，供监控与请求侧等待。
    state_tx: watch::Sender<TunnelState>,
    state_rx: watch::Receiver<TunnelState>,
    /// epoch 分配器。
    next_epoch: AtomicU64,
    /// 请求"立刻重连"的唤醒信号。业务侧观察到会话失效时可以主动触发，
    /// 不必等监督循环的下一个轮询周期。
    reconnect_now: Notify,
    /// 关停标志。
    shutdown: AtomicBool,
    /// 累计成功建连次数，供测试与运维观察自愈行为。
    connects: AtomicU64,
}

impl TunnelManager {
    pub fn new(cfg: Arc<Config>) -> Arc<Self> {
        let (state_tx, state_rx) = watch::channel(TunnelState::Connecting);
        Arc::new(Self {
            cfg,
            current: Mutex::new(None),
            state_tx,
            state_rx,
            next_epoch: AtomicU64::new(1),
            reconnect_now: Notify::new(),
            shutdown: AtomicBool::new(false),
            connects: AtomicU64::new(0),
        })
    }

    pub fn state(&self) -> TunnelState {
        *self.state_rx.borrow()
    }

    pub fn subscribe(&self) -> watch::Receiver<TunnelState> {
        self.state_rx.clone()
    }

    /// 累计成功建连次数（首次连接计 1，每次自愈重连 +1）。
    pub fn connect_count(&self) -> u64 {
        self.connects.load(Ordering::Relaxed)
    }

    /// 取当前会话；隧道不可用时返回 `None`。
    pub async fn current(&self) -> Option<Arc<Session>> {
        let guard = self.current.lock().await;
        match guard.as_ref() {
            Some(s) if !s.is_dead() => Some(s.clone()),
            _ => None,
        }
    }

    /// 取当前会话，不可用则最多等待 `timeout`。
    ///
    /// 这是"断网自愈对上层可见的形态"：短暂断网期间调用方会在这里阻塞，
    /// 隧道恢复后立即拿到新会话，请求不会因为一次网络抖动而失败。
    pub async fn wait_for_session(&self, timeout: Duration) -> anyhow::Result<Arc<Session>> {
        if let Some(s) = self.current().await {
            return Ok(s);
        }
        // 会话不可用，提示监督循环立刻重试。
        self.reconnect_now.notify_one();

        let deadline = tokio::time::Instant::now() + timeout;
        let mut rx = self.subscribe();
        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                return Err(anyhow!("tunnel is shutting down"));
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(anyhow!(
                    "tunnel unavailable after waiting {:?}; last state: {:?}",
                    timeout,
                    self.state()
                ));
            }
            // 等状态变化，而不是轮询睡眠。
            match tokio::time::timeout(remaining, rx.changed()).await {
                Ok(Ok(())) => {
                    if let Some(s) = self.current().await {
                        return Ok(s);
                    }
                }
                Ok(Err(_)) => return Err(anyhow!("tunnel manager stopped")),
                Err(_) => {
                    return Err(anyhow!(
                        "tunnel unavailable after waiting {:?}; last state: {:?}",
                        timeout,
                        self.state()
                    ))
                }
            }
        }
    }

    /// 通知管理器"我发现会话已死"，触发立即重连。
    pub fn notify_broken(&self) {
        self.reconnect_now.notify_one();
    }

    /// 关停隧道，停止重连。
    pub async fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let mut guard = self.current.lock().await;
        if let Some(s) = guard.take() {
            // 尽力发送 disconnect，失败无所谓——进程即将退出。
            let _ = s
                .handle
                .disconnect(russh::Disconnect::ByApplication, "shutdown", "")
                .await;
        }
        let _ = self.state_tx.send(TunnelState::Closed);
        self.reconnect_now.notify_waiters();
    }

    /// 监督循环：负责建连、检测失效、退避重连。应作为独立 task 长期运行。
    pub async fn supervise(self: Arc<Self>) {
        let mut backoff = Backoff::new(self.cfg.reconnect.backoff_policy());
        // 健康巡检周期。取保活间隔的一半，保证至少在一个保活周期内察觉死链。
        let poll = (self.cfg.ssh.keepalive_interval / 2).max(Duration::from_millis(500));

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                debug!("supervisor exiting: shutdown requested");
                return;
            }

            // 已有健康会话：巡检等待，不做多余动作。
            if self.current().await.is_some() {
                tokio::select! {
                    _ = tokio::time::sleep(poll) => {}
                    _ = self.reconnect_now.notified() => {
                        debug!("supervisor woken by broken-session notification");
                    }
                }
                // 巡检发现死链则清空，进入下一轮重连。
                let dead = {
                    let mut guard = self.current.lock().await;
                    match guard.as_ref() {
                        Some(s) if s.is_dead() => {
                            warn!(epoch = s.epoch, "ssh session lost; will reconnect");
                            *guard = None;
                            true
                        }
                        _ => false,
                    }
                };
                if dead {
                    let _ = self
                        .state_tx
                        .send(TunnelState::Reconnecting { attempts: 0 });
                }
                continue;
            }

            // 无可用会话：尝试建连。
            match self.connect_once().await {
                Ok(session) => {
                    let epoch = session.epoch;
                    backoff.reset();
                    self.connects.fetch_add(1, Ordering::Relaxed);
                    *self.current.lock().await = Some(Arc::new(session));
                    info!(epoch, "ssh tunnel established");
                    let _ = self.state_tx.send(TunnelState::Up(epoch));
                }
                Err(e) => {
                    if !self.cfg.reconnect.enabled {
                        warn!(error = %e, "connect failed and reconnect is disabled");
                        let _ = self.state_tx.send(TunnelState::Closed);
                        return;
                    }
                    let delay = backoff.next_delay();
                    warn!(
                        error = %e,
                        attempts = backoff.attempts(),
                        delay_ms = delay.as_millis() as u64,
                        "ssh connect failed; backing off"
                    );
                    let _ = self.state_tx.send(TunnelState::Reconnecting {
                        attempts: backoff.attempts(),
                    });
                    // 退避期间仍响应关停与"立即重连"请求。
                    tokio::select! {
                        _ = tokio::time::sleep(delay) => {}
                        _ = self.reconnect_now.notified() => {
                            debug!("backoff interrupted by explicit reconnect request");
                        }
                    }
                }
            }
        }
    }

    /// 建立一条 SSH 会话并完成认证。
    async fn connect_once(&self) -> anyhow::Result<Session> {
        let ssh = &self.cfg.ssh;
        let epoch = self.next_epoch.fetch_add(1, Ordering::Relaxed);

        let russh_cfg = Arc::new(client::Config {
            // 让 russh 自己发保活：这是"保持连接"的第一道防线。
            keepalive_interval: Some(ssh.keepalive_interval),
            keepalive_max: ssh.keepalive_max,
            // 不设 inactivity_timeout：保活机制已负责判活，
            // 再叠加空闲超时会让长时间无流量的隧道被误杀。
            inactivity_timeout: None,
            nodelay: true,
            ..Default::default()
        });

        let disconnect = Arc::new(DisconnectSignal::default());
        let handler = ClientHandler::new(
            ssh.host.clone(),
            ssh.port,
            ssh.host_key.clone(),
            ssh.known_hosts.clone(),
            disconnect.clone(),
        );

        let addr = (ssh.host.as_str(), ssh.port);
        let mut handle = tokio::time::timeout(
            ssh.connect_timeout,
            client::connect(russh_cfg, addr, handler),
        )
        .await
        .map_err(|_| anyhow!("ssh connect to {}:{} timed out", ssh.host, ssh.port))?
        .with_context(|| format!("ssh connect to {}:{} failed", ssh.host, ssh.port))?;

        tokio::time::timeout(ssh.connect_timeout, self.authenticate(&mut handle))
            .await
            .map_err(|_| anyhow!("ssh authentication timed out"))??;

        Ok(Session {
            epoch,
            handle,
            disconnect,
        })
    }

    async fn authenticate(&self, handle: &mut Handle<ClientHandler>) -> anyhow::Result<()> {
        let ssh = &self.cfg.ssh;
        let result = match &ssh.auth {
            AuthMethod::Password { password } => handle
                .authenticate_password(ssh.user.clone(), password.clone())
                .await
                .context("password authentication failed")?,
            AuthMethod::PublicKey { path, passphrase } => {
                let key = russh::keys::load_secret_key(path, passphrase.as_deref())
                    .with_context(|| format!("failed to load private key {}", path.display()))?;
                // RSA 密钥必须协商哈希算法，否则服务端可能拒绝 ssh-rsa(SHA-1)。
                let hash_alg = if key.algorithm().is_rsa() {
                    handle
                        .best_supported_rsa_hash()
                        .await
                        .context("failed to negotiate RSA hash algorithm")?
                        .flatten()
                        .or(Some(HashAlg::Sha256))
                } else {
                    None
                };
                let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);
                handle
                    .authenticate_publickey(ssh.user.clone(), key)
                    .await
                    .context("publickey authentication failed")?
            }
            AuthMethod::Agent => {
                let mut agent = connect_ssh_agent()
                    .await
                    .context("failed to connect to ssh-agent")?;
                let identities = agent
                    .request_identities()
                    .await
                    .context("failed to list ssh-agent identities")?;
                if identities.is_empty() {
                    return Err(anyhow!("ssh-agent has no identities loaded"));
                }
                // agent 可能持有多把钥匙，服务端只接受其中一把，
                // 因此逐个尝试直到成功，全部失败才报错。
                let mut last: Option<client::AuthResult> = None;
                for identity in identities {
                    // 证书类身份需要走 authenticate_certificate_with，
                    // 这里只处理普通公钥，其余跳过并提示。
                    let key = match identity {
                        russh::keys::agent::AgentIdentity::PublicKey { key, .. } => key,
                        russh::keys::agent::AgentIdentity::Certificate { comment, .. } => {
                            debug!(%comment, "skipping certificate identity from ssh-agent");
                            continue;
                        }
                    };
                    match handle
                        .authenticate_publickey_with(ssh.user.clone(), key, None, &mut agent)
                        .await
                    {
                        Ok(r) if r.success() => {
                            last = Some(r);
                            break;
                        }
                        Ok(r) => last = Some(r),
                        Err(e) => {
                            debug!(error = %e, "agent identity rejected; trying next");
                        }
                    }
                }
                last.ok_or_else(|| anyhow!("no ssh-agent identity was accepted"))?
            }
        };

        if !result.success() {
            return Err(anyhow!("ssh authentication rejected for user {}", ssh.user));
        }
        Ok(())
    }
}

/// 主机密钥策略的判定结果。抽出成纯函数便于单测覆盖安全逻辑。
pub(crate) fn fingerprint_matches(pinned: &str, actual_sha256_b64: &str) -> bool {
    // 容忍用户带不带 `SHA256:` 前缀，也容忍尾部 `=` 填充差异。
    let norm = |s: &str| {
        s.trim()
            .trim_start_matches("SHA256:")
            .trim_end_matches('=')
            .to_string()
    };
    let a = norm(pinned);
    let b = norm(actual_sha256_b64);
    !a.is_empty() && a == b
}

/// 判断某个策略下"未知主机"是否可接受。
pub(crate) fn accepts_unknown_host(policy: &HostKeyPolicy) -> bool {
    matches!(policy, HostKeyPolicy::AcceptNew)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::config::{ListenConfig, ReconnectConfig, SshConfig, TunnelMode};
    use std::path::PathBuf;

    fn test_cfg(port: u16) -> Arc<Config> {
        Arc::new(Config {
            ssh: SshConfig {
                host: "127.0.0.1".into(),
                port,
                user: "nobody".into(),
                auth: AuthMethod::Password {
                    password: "x".into(),
                },
                host_key: HostKeyPolicy::AcceptNew,
                known_hosts: Some(PathBuf::from("/nonexistent/known_hosts")),
                keepalive_interval: Duration::from_secs(1),
                keepalive_max: 3,
                connect_timeout: Duration::from_millis(300),
            },
            mode: TunnelMode::DirectTcpip,
            listen: ListenConfig::default(),
            reconnect: ReconnectConfig {
                enabled: true,
                initial_delay: Duration::from_millis(10),
                max_delay: Duration::from_millis(50),
                multiplier: 2.0,
                jitter: 0.0,
                dial_wait: Duration::from_millis(200),
            },
            helper: Default::default(),
        })
    }

    #[test]
    fn pinned_fingerprint_comparison_is_lenient_about_prefix_and_padding() {
        let actual = "abc123XYZ+/def";
        assert!(fingerprint_matches("SHA256:abc123XYZ+/def", actual));
        assert!(fingerprint_matches("abc123XYZ+/def", actual));
        assert!(fingerprint_matches("  SHA256:abc123XYZ+/def==  ", actual));
        assert!(!fingerprint_matches("SHA256:wrongwrongwrong", actual));
        assert!(
            !fingerprint_matches("", actual),
            "empty pin must never match"
        );
    }

    #[test]
    fn only_accept_new_tolerates_unknown_hosts() {
        assert!(!accepts_unknown_host(&HostKeyPolicy::Strict));
        assert!(accepts_unknown_host(&HostKeyPolicy::AcceptNew));
        assert!(!accepts_unknown_host(&HostKeyPolicy::Pinned("x".into())));
    }

    #[tokio::test]
    async fn starts_in_connecting_state_with_no_session() {
        let m = TunnelManager::new(test_cfg(1));
        assert_eq!(m.state(), TunnelState::Connecting);
        assert!(m.current().await.is_none());
        assert_eq!(m.connect_count(), 0);
    }

    /// 连不上时必须持续退避重连，而不是放弃或 panic。
    #[tokio::test]
    async fn retries_with_backoff_against_a_dead_port() {
        // 端口 1 上不会有监听者，连接必然失败。
        let m = TunnelManager::new(test_cfg(1));
        let sup = tokio::spawn(m.clone().supervise());

        // 给它足够时间失败多次（初始 10ms，上限 50ms）。
        tokio::time::sleep(Duration::from_millis(400)).await;

        match m.state() {
            TunnelState::Reconnecting { attempts } => {
                assert!(attempts >= 2, "expected multiple retries, got {attempts}");
            }
            other => panic!("expected Reconnecting, got {other:?}"),
        }
        assert_eq!(m.connect_count(), 0, "nothing should have connected");

        m.shutdown().await;
        sup.abort();
    }

    /// 隧道不可用时 wait_for_session 必须在超时后返回错误而不是永久挂起。
    #[tokio::test]
    async fn wait_for_session_times_out_when_tunnel_is_down() {
        let m = TunnelManager::new(test_cfg(1));
        let sup = tokio::spawn(m.clone().supervise());

        let started = std::time::Instant::now();
        // Session 不实现 Debug（内含 russh Handle），所以手工解构而不用 expect_err。
        let err = match m.wait_for_session(Duration::from_millis(150)).await {
            Ok(_) => panic!("must not succeed without a server"),
            Err(e) => e,
        };
        let elapsed = started.elapsed();

        assert!(
            elapsed >= Duration::from_millis(140),
            "returned too early: {elapsed:?}"
        );
        assert!(
            err.to_string().contains("tunnel unavailable"),
            "unexpected error: {err}"
        );

        m.shutdown().await;
        sup.abort();
    }

    #[tokio::test]
    async fn shutdown_stops_reconnecting() {
        let m = TunnelManager::new(test_cfg(1));
        let sup = tokio::spawn(m.clone().supervise());
        tokio::time::sleep(Duration::from_millis(50)).await;
        m.shutdown().await;
        assert_eq!(m.state(), TunnelState::Closed);

        // 监督循环应当自行退出。
        let ended = tokio::time::timeout(Duration::from_secs(2), sup).await;
        assert!(ended.is_ok(), "supervisor did not exit after shutdown");

        // 关停后请求会话必须立即失败。
        let err = m.wait_for_session(Duration::from_secs(5)).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn disabled_reconnect_gives_up_after_first_failure() {
        let mut cfg = (*test_cfg(1)).clone();
        cfg.reconnect.enabled = false;
        let m = TunnelManager::new(Arc::new(cfg));
        let sup = tokio::spawn(m.clone().supervise());

        let ended = tokio::time::timeout(Duration::from_secs(3), sup).await;
        assert!(
            ended.is_ok(),
            "supervisor should exit when reconnect is off"
        );
        assert_eq!(m.state(), TunnelState::Closed);
    }
}
