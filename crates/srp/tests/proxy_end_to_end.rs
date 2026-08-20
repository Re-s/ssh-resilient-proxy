//! 端到端集成测试：真实 TCP socket 上跑完整的入口协议 → Dialer → 目标链路。
//!
//! 这里刻意**不使用** SSH，而是把 `Dialer` 换成直连实现。理由是分层解耦：
//! 入口协议的正确性、错误码映射、双向转发、并发行为都与"隧道怎么建"无关，
//! 用直连 Dialer 测能得到确定性的结果，不受网络与 SSH 时序干扰。
//! SSH 相关的自愈行为由 tunnel 模块自己的测试与 srp-testkit 覆盖。

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use srp::frontend::socks5::Socks5Server;
use srp::frontend::{BoxedStream, DialError, Dialer};
use srp_proto::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// 直连 Dialer：把 `TargetAddr` 直接连出去。
///
/// 同时统计调用次数，用来断言"每条代理连接恰好触发一次 dial"。
struct DirectDialer {
    calls: AtomicU32,
}

impl DirectDialer {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicU32::new(0),
        })
    }
}

#[async_trait]
impl Dialer for DirectDialer {
    async fn dial(&self, addr: &TargetAddr) -> Result<BoxedStream, DialError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let host = addr.host_string();
        let port = addr.port();
        match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect((host, port))).await {
            Ok(Ok(s)) => Ok(Box::new(s)),
            Ok(Err(e)) => Err(DialError::from_io(&e)),
            Err(_) => Err(DialError::TimedOut),
        }
    }
}

/// 起一个 echo 服务器，返回其地址。
async fn spawn_echo() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });
    addr
}

/// 起一个 SOCKS5 代理，返回其监听地址。
async fn spawn_socks5(
    dialer: Arc<DirectDialer>,
    creds: Option<(String, String)>,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind socks");
    let addr = listener.local_addr().unwrap();
    let server = Arc::new(Socks5Server::new(creds));
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let server = server.clone();
            let dialer = dialer.clone();
            tokio::spawn(async move {
                let _ = server.serve_conn(stream, dialer).await;
            });
        }
    });
    addr
}

/// 完成 SOCKS5 无认证握手并发起 CONNECT，返回 REP 字节。
async fn socks5_connect(
    proxy: std::net::SocketAddr,
    target: std::net::SocketAddr,
) -> (TcpStream, u8) {
    let mut c = TcpStream::connect(proxy).await.expect("connect proxy");
    c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greet = [0u8; 2];
    c.read_exact(&mut greet).await.unwrap();
    assert_eq!(greet, [0x05, 0x00], "expected no-auth acceptance");

    let ip = match target.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        other => panic!("test helper only handles IPv4, got {other}"),
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip);
    req.extend_from_slice(&target.port().to_be_bytes());
    c.write_all(&req).await.unwrap();

    let mut reply = [0u8; 10];
    c.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05, "bad SOCKS version in reply");
    (c, reply[1])
}

#[tokio::test]
async fn socks5_relays_data_to_a_real_target() {
    let echo = spawn_echo().await;
    let dialer = DirectDialer::new();
    let proxy = spawn_socks5(dialer.clone(), None).await;

    let (mut c, rep) = socks5_connect(proxy, echo).await;
    assert_eq!(rep, 0x00, "CONNECT should succeed");

    c.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    c.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping", "echo payload must round-trip");

    assert_eq!(dialer.calls.load(Ordering::SeqCst), 1);
}

/// 大载荷：验证分块转发与背压路径不会损坏字节流。
#[tokio::test]
async fn socks5_relays_a_large_payload_intact() {
    let echo = spawn_echo().await;
    let dialer = DirectDialer::new();
    let proxy = spawn_socks5(dialer, None).await;

    let (c, rep) = socks5_connect(proxy, echo).await;
    assert_eq!(rep, 0x00);

    // 1 MiB 伪随机数据，足以跨越多个 TCP 段与内部缓冲边界。
    let payload: Vec<u8> = (0..1024 * 1024u32)
        .map(|i| (i.wrapping_mul(31) % 251) as u8)
        .collect();
    let expected = payload.clone();

    let (mut rd, mut wr) = c.into_split();
    let writer = tokio::spawn(async move {
        wr.write_all(&payload).await.unwrap();
        wr.shutdown().await.unwrap();
    });

    let mut got = Vec::with_capacity(expected.len());
    tokio::time::timeout(Duration::from_secs(30), rd.read_to_end(&mut got))
        .await
        .expect("relay timed out")
        .expect("read");

    writer.await.unwrap();
    assert_eq!(got.len(), expected.len(), "byte count mismatch");
    assert_eq!(got, expected, "payload corrupted in transit");
}

/// 目标拒绝连接必须映射成 SOCKS5 的 0x05。
#[tokio::test]
async fn refused_target_maps_to_connection_refused_reply() {
    // 绑定后立刻 drop，得到一个几乎必然无人监听的端口。
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        drop(l);
        a
    };

    let dialer = DirectDialer::new();
    let proxy = spawn_socks5(dialer, None).await;
    let (_c, rep) = socks5_connect(proxy, dead).await;
    assert_eq!(
        rep, 0x05,
        "expected REP 0x05 connection refused, got {rep:#04x}"
    );
}

/// 认证配置生效：错误凭据必须被拒。
#[tokio::test]
async fn userpass_auth_is_enforced() {
    let dialer = DirectDialer::new();
    let proxy = spawn_socks5(dialer, Some(("user".into(), "pass".into()))).await;

    // 只提供"无认证"方法时必须收到 0xFF。
    let mut c = TcpStream::connect(proxy).await.unwrap();
    c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greet = [0u8; 2];
    c.read_exact(&mut greet).await.unwrap();
    assert_eq!(greet, [0x05, 0xFF], "no-auth must be refused");

    // 正确凭据应通过。
    let mut c = TcpStream::connect(proxy).await.unwrap();
    c.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut greet = [0u8; 2];
    c.read_exact(&mut greet).await.unwrap();
    assert_eq!(greet, [0x05, 0x02]);

    let mut auth = vec![0x01, 4];
    auth.extend_from_slice(b"user");
    auth.push(4);
    auth.extend_from_slice(b"pass");
    c.write_all(&auth).await.unwrap();
    let mut resp = [0u8; 2];
    c.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x01, 0x00], "correct credentials must be accepted");

    // 错误密码必须被拒。
    let mut c = TcpStream::connect(proxy).await.unwrap();
    c.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut greet = [0u8; 2];
    c.read_exact(&mut greet).await.unwrap();
    let mut auth = vec![0x01, 4];
    auth.extend_from_slice(b"user");
    auth.push(5);
    auth.extend_from_slice(b"wrong");
    c.write_all(&auth).await.unwrap();
    let mut resp = [0u8; 2];
    c.read_exact(&mut resp).await.unwrap();
    assert_ne!(resp[1], 0x00, "wrong password must be rejected");
}

/// 并发连接：单条连接的失败不得影响其他连接。
#[tokio::test]
async fn concurrent_connections_are_independent() {
    let echo = spawn_echo().await;
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        drop(l);
        a
    };

    let dialer = DirectDialer::new();
    let proxy = spawn_socks5(dialer.clone(), None).await;

    let mut tasks = Vec::new();
    for i in 0..20 {
        // 一半连到 echo，一半连到死端口，交错进行。
        let target = if i % 2 == 0 { echo } else { dead };
        tasks.push(tokio::spawn(async move {
            let (mut c, rep) = socks5_connect(proxy, target).await;
            if target == echo {
                assert_eq!(rep, 0x00, "echo connection should succeed");
                c.write_all(b"x").await.unwrap();
                let mut b = [0u8; 1];
                c.read_exact(&mut b).await.unwrap();
                assert_eq!(&b, b"x");
            } else {
                assert_eq!(rep, 0x05, "dead port should be refused");
            }
        }));
    }

    for t in tasks {
        tokio::time::timeout(Duration::from_secs(20), t)
            .await
            .expect("task timed out")
            .expect("task panicked");
    }
    assert_eq!(dialer.calls.load(Ordering::SeqCst), 20);
}

/// 半关闭语义：客户端 shutdown 写端后仍应能读到目标剩余数据。
#[tokio::test]
async fn half_close_lets_the_target_finish_sending() {
    // 一个"读到 EOF 后才回复"的服务器，专门验证 FIN 正确传播。
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut got = Vec::new();
        // 必须先读到 EOF，说明客户端的 shutdown 传到了这里。
        s.read_to_end(&mut got).await.unwrap();
        s.write_all(format!("received {} bytes", got.len()).as_bytes())
            .await
            .unwrap();
        s.shutdown().await.unwrap();
    });

    let dialer = DirectDialer::new();
    let proxy = spawn_socks5(dialer, None).await;
    let (c, rep) = socks5_connect(proxy, addr).await;
    assert_eq!(rep, 0x00);

    let (mut rd, mut wr) = c.into_split();
    wr.write_all(b"hello world").await.unwrap();
    wr.shutdown().await.unwrap();

    let mut reply = String::new();
    tokio::time::timeout(Duration::from_secs(10), rd.read_to_string(&mut reply))
        .await
        .expect("half-close was not propagated to the target")
        .expect("read");

    assert_eq!(
        reply, "received 11 bytes",
        "target must observe EOF and still be able to reply"
    );
}
