//! `srp-testkit`：为 `ssh-resilient-proxy` 的集成测试提供可控的 SSH 服务端与网络故障注入设施。
//!
//! 本机没有系统 sshd 也无法安装，因此这里用 `russh` 的 server 端在进程内实现了一个
//! 测试专用 SSH 服务器（[`TestSshServer`]），并配套提供：
//!
//! * [`FlakyProxy`]：插在客户端与真实服务端之间的 TCP 代理，可随时切断连接、进入黑洞模式；
//! * [`TcpEchoServer`]：用于验证 `direct-tcpip` 端到端链路的回显服务器；
//! * [`TestClientHandler`]：一个最小的 `russh::client::Handler`，支持校验或忽略主机公钥；
//! * [`generate_ed25519_key`]：绕过 `rand` 版本陷阱生成 Ed25519 私钥（详见该函数文档）。
//!
//! # 最小示例：启动服务器 + russh 客户端 + direct-tcpip 通道
//!
//! ```
//! use std::sync::Arc;
//!
//! use russh::keys::PrivateKeyWithHashAlg;
//! use srp_testkit::{
//!     generate_ed25519_key, TcpEchoServer, TestClientHandler, TestServerConfig, TestSshServer,
//! };
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//!
//! # fn main() -> anyhow::Result<()> {
//! # tokio::runtime::Runtime::new()?.block_on(async {
//! // 1. 生成客户端密钥，并把公钥登记为服务器唯一接受的 authorized_key
//! let client_key = Arc::new(generate_ed25519_key()?);
//! let server = TestSshServer::start(TestServerConfig {
//!     username: "tester".into(),
//!     authorized_key: Some(client_key.public_key().clone()),
//!     ..Default::default()
//! })
//! .await?;
//!
//! // 2. 一个真实的 TCP 目标，供 direct-tcpip 转发过去
//! let echo = TcpEchoServer::start().await?;
//!
//! // 3. 用 russh client 连上去（校验主机公钥）并做 publickey 认证
//! let config = Arc::new(russh::client::Config::default());
//! let handler = TestClientHandler::expect_host_key(server.host_key.clone());
//! let mut session = russh::client::connect(config, server.addr, handler).await?;
//! let auth = session
//!     .authenticate_publickey(
//!         "tester",
//!         PrivateKeyWithHashAlg::new(client_key.clone(), None),
//!     )
//!     .await?;
//! assert!(auth.success());
//!
//! // 4. 打开 direct-tcpip 通道，数据会被服务端真实桥接到 echo 服务器
//! let channel = session
//!     .channel_open_direct_tcpip(
//!         echo.addr.ip().to_string(),
//!         echo.addr.port() as u32,
//!         "127.0.0.1",
//!         0,
//!     )
//!     .await?;
//! let mut stream = channel.into_stream();
//! stream.write_all(b"ping").await?;
//! let mut buf = [0u8; 4];
//! stream.read_exact(&mut buf).await?;
//! assert_eq!(&buf, b"ping");
//!
//! server.shutdown().await;
//! echo.shutdown().await;
//! # Ok::<_, anyhow::Error>(())
//! # })
//! # }
//! ```

mod client_util;
mod echo;
mod flaky_proxy;
mod net_util;
mod ssh_server;

pub use client_util::TestClientHandler;
pub use echo::{TcpEchoServer, TcpEchoServerHandle};
pub use flaky_proxy::{FlakyProxy, FlakyProxyHandle};
pub use ssh_server::{generate_ed25519_key, TestServerConfig, TestSshServer, TestSshServerHandle};

/// 初始化测试用的 tracing 订阅器（重复调用安全，可用 `RUST_LOG` 控制级别）。
///
/// 集成测试排查问题时调用一次即可；已经安装过全局订阅器时静默返回。
pub fn init_test_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_test_writer()
        .try_init();
}
