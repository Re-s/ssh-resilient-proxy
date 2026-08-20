//! `direct-tcpip` 模式的 Dialer：零远端依赖的弹性转发。
//!
//! 每条代理连接对应一条 SSH `direct-tcpip` 通道，任何标准 sshd 都支持，
//! 无需在服务端安装或改动任何东西。
//!
//! # 这个模式下的"自愈"具体做到什么
//!
//! 隧道断开时，远端出口 TCP 由 sshd 持有并必然被关闭——这是 SSH 协议的
//! 结构性事实，纯客户端实现无法绕过。所以这里的弹性体现在**通道建立阶段**：
//!
//! * 隧道不可用时新请求在 `dial_wait` 内等待恢复，而不是立即失败；
//! * 通道打开失败若源于会话已死，则在新会话上**重放**该请求，
//!   对调用方完全透明——因为此时还没有任何应用数据流动，重放是幂等的；
//! * 一旦数据开始双向流动就不再重放：那会导致重复写入，破坏正确性。
//!
//! 已建立的长流要在断网后字节级续传，必须用 `Helper` 模式。

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use russh::ChannelStream;
use srp_proto::TargetAddr;
use tracing::{debug, warn};

use crate::frontend::{BoxedStream, DialError, Dialer};

use super::manager::TunnelManager;

/// 通道打开失败后的最大重放次数。
///
/// 2 次足够覆盖"恰好在打开瞬间断线"这一竞态：第一次失败触发重连，
/// 第二次在新会话上成功。再多就说明是持续性故障，应当如实报错。
const MAX_REPLAYS: u32 = 2;

pub struct DirectTcpipDialer {
    tunnel: Arc<TunnelManager>,
    dial_wait: Duration,
    /// 打开通道本身的超时。区别于 `dial_wait`（等隧道恢复）。
    open_timeout: Duration,
}

impl DirectTcpipDialer {
    pub fn new(tunnel: Arc<TunnelManager>, dial_wait: Duration) -> Self {
        Self {
            tunnel,
            dial_wait,
            open_timeout: Duration::from_secs(30),
        }
    }

    pub fn with_open_timeout(mut self, t: Duration) -> Self {
        self.open_timeout = t;
        self
    }
}

#[async_trait]
impl Dialer for DirectTcpipDialer {
    async fn dial(&self, addr: &TargetAddr) -> Result<BoxedStream, DialError> {
        let mut replays = 0u32;

        loop {
            // 等一条可用会话。断网期间这里阻塞，恢复后立刻继续。
            let session = match self.tunnel.wait_for_session(self.dial_wait).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(target = %addr, error = %e, "no ssh tunnel available for dial");
                    return Err(DialError::NetworkUnreachable);
                }
            };

            // 域名原样交给远端解析，DNS 在出口侧发生，避免本地污染。
            let host = addr.host_string();
            let port = addr.port() as u32;

            let opened = tokio::time::timeout(
                self.open_timeout,
                session
                    .handle
                    .channel_open_direct_tcpip(host.clone(), port, "127.0.0.1", 0),
            )
            .await;

            match opened {
                Ok(Ok(channel)) => {
                    debug!(target = %addr, epoch = session.epoch, "direct-tcpip channel opened");
                    let stream: ChannelStream<russh::client::Msg> = channel.into_stream();
                    return Ok(Box::new(stream));
                }
                Ok(Err(e)) => {
                    // 判断能否重放时**不能**只看 `session.is_dead()`：
                    // 断连瞬间 russh 往往先让这次调用返回错误，断连标志稍后才
                    // 由后台任务置位。那个窗口里 is_dead() 仍是 false，
                    // 本该重放的请求会直接失败。所以以"错误本身是否属于
                    // 连接层故障"为主，会话状态为辅。
                    if replays < MAX_REPLAYS && (is_transport_failure(&e) || session.is_dead()) {
                        replays += 1;
                        self.tunnel.notify_broken();
                        debug!(
                            target = %addr,
                            replay = replays,
                            error = %e,
                            "channel open failed at the transport layer; replaying on a fresh session"
                        );
                        // 让监督循环有机会先建好新会话，避免空转重试。
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                    warn!(target = %addr, error = %e, "direct-tcpip channel open failed");
                    return Err(classify_open_error(&e));
                }
                Err(_) => {
                    // 超时且会话已死：说明卡在一条正在崩塌的连接上，值得重放。
                    if replays < MAX_REPLAYS && session.is_dead() {
                        replays += 1;
                        self.tunnel.notify_broken();
                        debug!(target = %addr, replay = replays, "open timed out on a dead session; replaying");
                        continue;
                    }
                    warn!(target = %addr, "direct-tcpip channel open timed out");
                    return Err(DialError::TimedOut);
                }
            }
        }
    }
}

/// 判断一个错误是否属于"SSH 传输层故障"，即隧道本身坏了。
///
/// 区分这一点至关重要：
///
/// * **传输层故障**（连接断开、发送失败、IO 错误）意味着请求根本没被服务端
///   处理过，在新会话上重放是安全且必要的；
/// * **服务端明确拒绝**（`ChannelOpenFailure`）说明服务端收到了请求并给出了
///   答复——比如目标拒绝连接、被策略禁止。这类错误**绝不能**重放：
///   重放不会改变结果，只会掩盖真实原因并浪费一个 RTT。
pub(crate) fn is_transport_failure(e: &russh::Error) -> bool {
    match e {
        // 服务端给了明确答复，不是传输故障。
        russh::Error::ChannelOpenFailure(_) => false,
        // 连接已经或正在崩塌。KeepaliveTimeout 尤其关键：
        // 它正是"网络断了但 TCP 还没被内核判死"这一场景的信号。
        russh::Error::Disconnect
        | russh::Error::SendError
        | russh::Error::HUP
        | russh::Error::RecvError
        | russh::Error::ConnectionTimeout
        | russh::Error::KeepaliveTimeout
        | russh::Error::InactivityTimeout
        | russh::Error::IO(_) => true,
        // 其余（协议/密钥/配置错误）重放也不会变好，如实上报。
        _ => false,
    }
}

/// 把 russh 错误映射到入口协议能表达的失败原因。
///
/// sshd 在 `CHANNEL_OPEN_FAILURE` 里带的 reason code 会被 russh 归并，
/// 所以这里只能做保守区分：能明确的就明确，其余归为不可达。
pub(crate) fn classify_open_error(e: &russh::Error) -> DialError {
    match e {
        russh::Error::ChannelOpenFailure(reason) => match reason {
            russh::ChannelOpenFailure::AdministrativelyProhibited => DialError::Forbidden,
            russh::ChannelOpenFailure::ConnectFailed => DialError::ConnectionRefused,
            russh::ChannelOpenFailure::UnknownChannelType => DialError::Internal,
            russh::ChannelOpenFailure::ResourceShortage => DialError::Internal,
            // 服务端返回了未知 reason code。无法细分，按内部错误上报，
            // 具体 code 已由调用处的 warn! 日志记录。
            russh::ChannelOpenFailure::Other { .. } => DialError::Internal,
        },
        russh::Error::Disconnect
        | russh::Error::SendError
        | russh::Error::HUP
        | russh::Error::RecvError => DialError::NetworkUnreachable,
        russh::Error::ConnectionTimeout
        | russh::Error::KeepaliveTimeout
        | russh::Error::InactivityTimeout => DialError::TimedOut,
        russh::Error::IO(io) => match io.kind() {
            std::io::ErrorKind::TimedOut => DialError::TimedOut,
            std::io::ErrorKind::ConnectionRefused => DialError::ConnectionRefused,
            _ => DialError::NetworkUnreachable,
        },
        _ => DialError::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::config::{
        AuthMethod, Config, HostKeyPolicy, ListenConfig, ReconnectConfig, SshConfig, TunnelMode,
    };

    fn cfg_pointing_nowhere() -> Arc<Config> {
        Arc::new(Config {
            ssh: SshConfig {
                host: "127.0.0.1".into(),
                // 端口 1 上没有监听者，隧道永远建不起来。
                port: 1,
                user: "nobody".into(),
                auth: AuthMethod::Password {
                    password: "x".into(),
                },
                host_key: HostKeyPolicy::AcceptNew,
                known_hosts: Some("/nonexistent/kh".into()),
                keepalive_interval: Duration::from_secs(1),
                keepalive_max: 3,
                connect_timeout: Duration::from_millis(200),
            },
            mode: TunnelMode::DirectTcpip,
            listen: ListenConfig::default(),
            reconnect: ReconnectConfig {
                enabled: true,
                initial_delay: Duration::from_millis(10),
                max_delay: Duration::from_millis(30),
                multiplier: 2.0,
                jitter: 0.0,
                dial_wait: Duration::from_millis(120),
            },
            helper: Default::default(),
        })
    }

    #[test]
    fn maps_channel_open_failures_to_meaningful_dial_errors() {
        use russh::ChannelOpenFailure as F;
        assert_eq!(
            classify_open_error(&russh::Error::ChannelOpenFailure(
                F::AdministrativelyProhibited
            )),
            DialError::Forbidden
        );
        assert_eq!(
            classify_open_error(&russh::Error::ChannelOpenFailure(F::ConnectFailed)),
            DialError::ConnectionRefused
        );
        assert_eq!(
            classify_open_error(&russh::Error::Disconnect),
            DialError::NetworkUnreachable
        );
        assert_eq!(
            classify_open_error(&russh::Error::IO(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "t"
            ))),
            DialError::TimedOut
        );
    }

    /// 重放的判定标准：传输层故障可重放，服务端明确拒绝不可重放。
    ///
    /// 这个区分直接决定用户体验：把"目标拒绝连接"当成可重放会浪费 RTT 并
    /// 掩盖真实原因；把"连接断了"当成不可重放则让一次网络抖动变成用户可见的失败。
    #[test]
    fn only_transport_failures_are_replayable() {
        use russh::ChannelOpenFailure as F;

        // 服务端给了答复 —— 不可重放。
        for reason in [
            F::ConnectFailed,
            F::AdministrativelyProhibited,
            F::ResourceShortage,
            F::UnknownChannelType,
        ] {
            let e = russh::Error::ChannelOpenFailure(reason.clone());
            assert!(
                !is_transport_failure(&e),
                "server-side refusal {reason:?} must not be replayed"
            );
        }

        // 传输层坏了 —— 必须可重放。
        assert!(is_transport_failure(&russh::Error::Disconnect));
        assert!(is_transport_failure(&russh::Error::SendError));
        assert!(is_transport_failure(&russh::Error::HUP));
        assert!(is_transport_failure(&russh::Error::KeepaliveTimeout));
        assert!(is_transport_failure(&russh::Error::ConnectionTimeout));
        assert!(is_transport_failure(&russh::Error::IO(
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "gone")
        )));

        // 协议/配置类错误重放也不会变好。
        assert!(!is_transport_failure(&russh::Error::NoAuthMethod));
        assert!(!is_transport_failure(&russh::Error::WrongChannel));
    }

    #[test]
    fn keepalive_timeout_maps_to_timed_out() {
        assert_eq!(
            classify_open_error(&russh::Error::KeepaliveTimeout),
            DialError::TimedOut
        );
        assert_eq!(
            classify_open_error(&russh::Error::RecvError),
            DialError::NetworkUnreachable
        );
    }

    /// 隧道不可用时 dial 必须在 dial_wait 后失败，而不是永久挂起。
    #[tokio::test]
    async fn dial_fails_with_network_unreachable_when_tunnel_is_down() {
        let tunnel = TunnelManager::new(cfg_pointing_nowhere());
        let sup = tokio::spawn(tunnel.clone().supervise());
        let dialer = DirectTcpipDialer::new(tunnel.clone(), Duration::from_millis(120));

        let started = std::time::Instant::now();
        // BoxedStream 不实现 Debug，手工解构。
        let err = match dialer
            .dial(&TargetAddr::Domain("example.com".into(), 80))
            .await
        {
            Ok(_) => panic!("must fail without a tunnel"),
            Err(e) => e,
        };
        let elapsed = started.elapsed();

        assert_eq!(err, DialError::NetworkUnreachable);
        assert!(
            elapsed >= Duration::from_millis(100),
            "should have waited for the tunnel: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "should not hang indefinitely: {elapsed:?}"
        );

        tunnel.shutdown().await;
        sup.abort();
    }
}
