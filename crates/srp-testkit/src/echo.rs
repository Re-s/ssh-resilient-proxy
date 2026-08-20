//! 一个最小的 TCP 回显服务器，用于验证 `direct-tcpip` 端到端链路。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Context as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// TCP 回显服务器的门面类型。
pub struct TcpEchoServer;

impl TcpEchoServer {
    /// 在 `127.0.0.1:0` 上启动一个回显服务器。
    pub async fn start() -> anyhow::Result<TcpEchoServerHandle> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .context("回显服务器绑定失败")?;
        let addr = listener.local_addr().context("读取回显服务器地址失败")?;
        let accepted = Arc::new(AtomicU64::new(0));

        let counter = Arc::clone(&accepted);
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::debug!("回显服务器 accept 结束: {e}");
                        return;
                    }
                };
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    loop {
                        match socket.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if socket.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    // 对端 EOF 后回一个 FIN，让 direct-tcpip 的 EOF 传播可被观察。
                    let _ = socket.shutdown().await;
                });
            }
        });

        Ok(TcpEchoServerHandle {
            addr,
            accepted,
            task: Some(task),
        })
    }
}

/// 回显服务器句柄。
pub struct TcpEchoServerHandle {
    /// 实际监听地址。
    pub addr: SocketAddr,
    accepted: Arc<AtomicU64>,
    task: Option<JoinHandle<()>>,
}

impl TcpEchoServerHandle {
    /// 累计接受的连接数。
    pub fn accepted_count(&self) -> u64 {
        self.accepted.load(Ordering::SeqCst)
    }

    /// 关停回显服务器。
    pub async fn shutdown(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for TcpEchoServerHandle {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
