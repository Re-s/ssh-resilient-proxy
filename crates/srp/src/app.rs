//! 应用接线：把配置、隧道、入口监听器组装成一个可运行的代理。

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::frontend::http::HttpConnectServer;
use crate::frontend::socks5::Socks5Server;
use crate::frontend::Dialer;
use crate::tunnel::config::{Config, TunnelMode};
use crate::tunnel::helper::HelperDialer;
use crate::tunnel::{DirectTcpipDialer, TunnelManager};

/// 入口协议服务器。凭据在构造时固定，避免每条连接重复克隆。
#[derive(Clone)]
enum Frontend {
    Socks5(Arc<Socks5Server>),
    Http(Arc<HttpConnectServer>),
}

impl Frontend {
    fn name(&self) -> &'static str {
        match self {
            Self::Socks5(_) => "socks5",
            Self::Http(_) => "http-connect",
        }
    }
}

/// 运行代理直到收到关停信号。
pub async fn run(cfg: Config) -> Result<()> {
    // 安全告警必须在启动时可见，而不是埋在文档里。
    for w in cfg.security_warnings() {
        warn!("{w}");
    }

    let cfg = Arc::new(cfg);
    let tunnel = TunnelManager::new(cfg.clone());
    let supervisor = tokio::spawn(tunnel.clone().supervise());

    // 按模式选择 Dialer。两种模式对 frontend 完全等价——
    // 这正是 Dialer 抽象存在的意义。
    let dialer: Arc<dyn Dialer> = match cfg.mode {
        TunnelMode::DirectTcpip => {
            info!("mode = direct-tcpip (no remote binary required)");
            Arc::new(DirectTcpipDialer::new(
                tunnel.clone(),
                cfg.reconnect.dial_wait,
            ))
        }
        TunnelMode::Helper => {
            info!("mode = helper (byte-level resume across reconnects)");
            HelperDialer::spawn(tunnel.clone(), cfg.helper.clone(), cfg.reconnect.dial_wait)
        }
    };

    let creds = match (&cfg.listen.username, &cfg.listen.password) {
        (Some(u), Some(p)) => Some((u.clone(), p.clone())),
        _ => None,
    };

    let mut listeners = Vec::new();
    if let Some(addr) = &cfg.listen.socks5 {
        let fe = Frontend::Socks5(Arc::new(Socks5Server::new(creds.clone())));
        listeners.push((fe, bind(addr).await?));
    }
    if let Some(addr) = &cfg.listen.http {
        let fe = Frontend::Http(Arc::new(HttpConnectServer::new(creds.clone())));
        listeners.push((fe, bind(addr).await?));
    }

    let mut tasks = Vec::new();
    for (fe, listener) in listeners {
        let dialer = dialer.clone();
        tasks.push(tokio::spawn(async move {
            accept_loop(fe, listener, dialer).await;
        }));
    }

    // 等关停信号。
    wait_for_shutdown().await;
    info!("shutdown signal received; closing tunnel");

    tunnel.shutdown().await;
    for t in tasks {
        t.abort();
    }
    supervisor.abort();
    Ok(())
}

async fn bind(addr: &str) -> Result<TcpListener> {
    TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind listener on {addr}"))
}

/// 接受循环。
///
/// 单条连接的失败绝不能拖垮监听器：每个连接独立 spawn，错误只记日志。
async fn accept_loop(fe: Frontend, listener: TcpListener, dialer: Arc<dyn Dialer>) {
    let local = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".into());
    info!(frontend = fe.name(), %local, "frontend listening");

    // accept 连续失败时退避，避免 fd 耗尽场景下的忙循环刷满 CPU 与日志。
    let mut consecutive_errors = 0u32;

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                consecutive_errors = 0;
                // Nagle 会给交互式流量增加延迟，代理场景一律关掉。
                let _ = stream.set_nodelay(true);

                let dialer = dialer.clone();
                let fe = fe.clone();
                tokio::spawn(async move {
                    let result = match &fe {
                        Frontend::Socks5(s) => s.serve_conn(stream, dialer).await,
                        Frontend::Http(s) => s.serve_conn(stream, dialer).await,
                    };
                    if let Err(e) = result {
                        // 客户端提前断开是常态，不值得 warn。
                        tracing::debug!(%peer, error = %e, "connection ended with an error");
                    }
                });
            }
            Err(e) => {
                consecutive_errors = consecutive_errors.saturating_add(1);
                error!(error = %e, consecutive_errors, "accept failed");
                let backoff = Duration::from_millis((50u64 << consecutive_errors.min(6)).min(2000));
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

/// 等待 SIGINT / SIGTERM。
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "failed to install SIGTERM handler; only Ctrl-C will work");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::{BoxedStream, DialError};
    use srp_proto::TargetAddr;

    struct RejectAll;

    #[async_trait::async_trait]
    impl Dialer for RejectAll {
        async fn dial(&self, _addr: &TargetAddr) -> Result<BoxedStream, DialError> {
            Err(DialError::NetworkUnreachable)
        }
    }

    /// accept 循环必须在单条连接失败后继续服务后续连接。
    #[tokio::test]
    async fn accept_loop_survives_failing_connections() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let fe = Frontend::Socks5(Arc::new(Socks5Server::new(None)));
        let task = tokio::spawn(accept_loop(fe, listener, Arc::new(RejectAll)));

        // 连续两条连接都会因为 dial 失败而结束，监听器必须都能服务。
        for _ in 0..2 {
            let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
            // SOCKS5 方法协商 + CONNECT 1.2.3.4:80
            c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut resp = [0u8; 2];
            c.read_exact(&mut resp).await.unwrap();
            assert_eq!(resp, [0x05, 0x00]);

            c.write_all(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50])
                .await
                .unwrap();
            let mut reply = [0u8; 10];
            c.read_exact(&mut reply).await.unwrap();
            // 0x03 = network unreachable
            assert_eq!(reply[1], 0x03, "expected network-unreachable reply");
        }

        task.abort();
    }

    #[tokio::test]
    async fn bind_reports_a_useful_error_for_a_bad_address() {
        let err = bind("256.256.256.256:1").await.expect_err("must fail");
        assert!(
            err.to_string().contains("failed to bind listener"),
            "unexpected error: {err}"
        );
    }
}
