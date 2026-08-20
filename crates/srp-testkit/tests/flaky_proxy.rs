//! `FlakyProxy` 自测：透传、cut_now、blackhole、accepted_count 与限速。

use std::sync::Arc;
use std::time::Duration;

use russh::keys::PrivateKeyWithHashAlg;
use srp_testkit::{
    generate_ed25519_key, FlakyProxy, TcpEchoServer, TestClientHandler, TestServerConfig,
    TestSshServer,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const TIMEOUT: Duration = Duration::from_secs(20);

#[tokio::test]
async fn proxy_forwards_plain_tcp_and_counts_connections() -> anyhow::Result<()> {
    tokio::time::timeout(TIMEOUT, async {
        let echo = TcpEchoServer::start().await?;
        let proxy = FlakyProxy::start(echo.addr).await?;
        assert_eq!(proxy.upstream_addr(), echo.addr);
        assert_eq!(proxy.accepted_count(), 0);

        for round in 0..3u8 {
            let mut client = TcpStream::connect(proxy.listen_addr).await?;
            let payload = format!("round-{round}");
            client.write_all(payload.as_bytes()).await?;
            let mut buf = vec![0u8; payload.len()];
            client.read_exact(&mut buf).await?;
            assert_eq!(buf, payload.as_bytes());
            client.shutdown().await?;
        }

        // accepted_count 在连接进入转发时自增
        assert_eq!(proxy.accepted_count(), 3, "三次连接应被计数三次");
        assert_eq!(proxy.rejected_count(), 0);
        assert!(proxy.bytes_client_to_upstream() >= 21);
        assert!(proxy.bytes_upstream_to_client() >= 21);

        proxy.shutdown().await;
        echo.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn cut_now_breaks_live_connection_but_new_ones_work() -> anyhow::Result<()> {
    tokio::time::timeout(TIMEOUT, async {
        let echo = TcpEchoServer::start().await?;
        let proxy = FlakyProxy::start(echo.addr).await?;

        let mut client = TcpStream::connect(proxy.listen_addr).await?;
        client.write_all(b"alive").await?;
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"alive");
        assert_eq!(proxy.live_connection_count(), 1);

        proxy.cut_now();

        // 被 RST 之后：读要么返回 0（EOF）要么直接报错，但一定不能挂住
        let mut sink = Vec::new();
        let read_result =
            tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut sink)).await;
        assert!(read_result.is_ok(), "cut_now 后读应立刻返回而不是挂住");
        drop(client);

        // 新连接仍可正常建立
        let mut client2 = TcpStream::connect(proxy.listen_addr).await?;
        client2.write_all(b"again").await?;
        let mut buf2 = [0u8; 5];
        client2.read_exact(&mut buf2).await?;
        assert_eq!(&buf2, b"again");
        assert_eq!(proxy.accepted_count(), 2);

        proxy.shutdown().await;
        echo.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn blackhole_rejects_new_connections_then_recovers() -> anyhow::Result<()> {
    tokio::time::timeout(TIMEOUT, async {
        let echo = TcpEchoServer::start().await?;
        let proxy = FlakyProxy::start(echo.addr).await?;

        // 先建一条正常连接
        let mut client = TcpStream::connect(proxy.listen_addr).await?;
        client.write_all(b"pre").await?;
        let mut buf = [0u8; 3];
        client.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"pre");

        // 进入黑洞：现有连接被切断
        proxy.blackhole(true);
        assert!(proxy.is_blackhole());
        let mut sink = Vec::new();
        let read_result =
            tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut sink)).await;
        assert!(read_result.is_ok(), "黑洞开启后现有连接应立即断开");
        drop(client);

        // 黑洞期间的新连接：TCP 层可能握手成功，但立刻被 RST，
        // 所以任何一次读写一定会失败（不会挂住、不会拿到回显）。
        let attempt = tokio::time::timeout(Duration::from_secs(5), async {
            let mut c = TcpStream::connect(proxy.listen_addr).await?;
            c.write_all(b"during-blackhole").await?;
            let mut b = [0u8; 1];
            c.read_exact(&mut b).await?;
            Ok::<_, std::io::Error>(())
        })
        .await;
        match attempt {
            Ok(Ok(())) => anyhow::bail!("黑洞期间竟然完成了一次回显往返"),
            Ok(Err(_)) => {}
            Err(_) => anyhow::bail!("黑洞期间的连接应快速失败而不是超时"),
        }
        assert!(
            proxy.rejected_count() >= 1,
            "黑洞期间的连接应被计入 rejected"
        );
        let accepted_after_blackhole = proxy.accepted_count();

        // 退出黑洞：恢复正常
        proxy.blackhole(false);
        assert!(!proxy.is_blackhole());
        let mut client2 = TcpStream::connect(proxy.listen_addr).await?;
        client2.write_all(b"post").await?;
        let mut buf2 = [0u8; 4];
        client2.read_exact(&mut buf2).await?;
        assert_eq!(&buf2, b"post");
        assert_eq!(
            proxy.accepted_count(),
            accepted_after_blackhole + 1,
            "恢复后的连接应被正常计数"
        );

        proxy.shutdown().await;
        echo.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn throttle_slows_transfer_without_losing_data() -> anyhow::Result<()> {
    tokio::time::timeout(TIMEOUT, async {
        let echo = TcpEchoServer::start().await?;
        let proxy = FlakyProxy::start(echo.addr).await?;
        // 每次最多 8 字节，每块之后 5ms
        proxy.set_throttle(8, Duration::from_millis(5));

        let payload: Vec<u8> = (0..64u8).collect();
        let mut client = TcpStream::connect(proxy.listen_addr).await?;
        client.write_all(&payload).await?;
        let mut buf = vec![0u8; payload.len()];
        client.read_exact(&mut buf).await?;
        assert_eq!(buf, payload, "限速不应改变数据内容");

        proxy.set_throttle(0, Duration::ZERO);
        proxy.shutdown().await;
        echo.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn ssh_through_proxy_survives_reconnect_after_cut() -> anyhow::Result<()> {
    tokio::time::timeout(TIMEOUT, async {
        let key = Arc::new(generate_ed25519_key()?);
        let server = TestSshServer::start(TestServerConfig {
            username: "tester".into(),
            authorized_key: Some(key.public_key().clone()),
            ..Default::default()
        })
        .await?;
        let echo = TcpEchoServer::start().await?;
        let proxy = FlakyProxy::start(server.addr).await?;

        // 客户端通过代理连 SSH 服务器，并把数据经 direct-tcpip 打到 echo
        let connect_once = || async {
            let config = Arc::new(russh::client::Config {
                nodelay: true,
                ..Default::default()
            });
            let handler = TestClientHandler::expect_host_key(server.host_key.clone());
            let mut session = russh::client::connect(config, proxy.listen_addr, handler).await?;
            let auth = session
                .authenticate_publickey(
                    "tester",
                    PrivateKeyWithHashAlg::new(Arc::clone(&key), None),
                )
                .await?;
            anyhow::ensure!(auth.success(), "通过代理的 publickey 认证失败");
            Ok::<_, anyhow::Error>(session)
        };

        let session = connect_once().await?;
        let channel = session
            .channel_open_direct_tcpip(
                echo.addr.ip().to_string(),
                u32::from(echo.addr.port()),
                "127.0.0.1",
                0,
            )
            .await?;
        let mut stream = channel.into_stream();
        stream.write_all(b"through-proxy").await?;
        let mut buf = [0u8; 13];
        stream.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"through-proxy");
        assert_eq!(proxy.accepted_count(), 1);

        // 断网
        proxy.cut_now();
        let mut closed = false;
        for _ in 0..100 {
            if session.is_closed() {
                closed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(closed, "代理 cut_now 之后 SSH 会话应被标记为关闭");
        drop(stream);
        drop(session);

        // 自愈：重新建连并重新打通 direct-tcpip
        let session2 = connect_once().await?;
        let channel2 = session2
            .channel_open_direct_tcpip(
                echo.addr.ip().to_string(),
                u32::from(echo.addr.port()),
                "127.0.0.1",
                0,
            )
            .await?;
        let mut stream2 = channel2.into_stream();
        stream2.write_all(b"healed").await?;
        let mut buf2 = [0u8; 6];
        stream2.read_exact(&mut buf2).await?;
        assert_eq!(&buf2, b"healed");
        assert_eq!(proxy.accepted_count(), 2, "重连应体现为第二次 accept");

        proxy.shutdown().await;
        echo.shutdown().await;
        server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}
