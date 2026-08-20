//! `TestSshServer` 自测：认证、direct-tcpip、exec 桥接、强杀连接。

use std::sync::Arc;
use std::time::Duration;

use russh::keys::PrivateKeyWithHashAlg;
use russh::ChannelMsg;
use srp_testkit::{
    generate_ed25519_key, TcpEchoServer, TestClientHandler, TestServerConfig, TestSshServer,
    TestSshServerHandle,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 所有单测都套一层超时，避免网络 I/O 卡死整个测试进程。
const TIMEOUT: Duration = Duration::from_secs(20);

/// 连接并做 publickey 认证，返回已认证的客户端会话。
async fn connect_publickey(
    server: &TestSshServerHandle,
    key: Arc<russh::keys::PrivateKey>,
    username: &str,
) -> anyhow::Result<russh::client::Handle<TestClientHandler>> {
    let config = Arc::new(russh::client::Config {
        nodelay: true,
        ..Default::default()
    });
    let handler = TestClientHandler::expect_host_key(server.host_key.clone());
    let mut session = russh::client::connect(config, server.addr, handler).await?;
    let auth = session
        .authenticate_publickey(username, PrivateKeyWithHashAlg::new(key, None))
        .await?;
    anyhow::ensure!(auth.success(), "publickey 认证意外失败");
    Ok(session)
}

#[tokio::test]
async fn publickey_auth_accepts_authorized_key_and_rejects_others() -> anyhow::Result<()> {
    tokio::time::timeout(TIMEOUT, async {
        let good_key = Arc::new(generate_ed25519_key()?);
        let bad_key = Arc::new(generate_ed25519_key()?);

        let server = TestSshServer::start(TestServerConfig {
            username: "tester".into(),
            password: Some("hunter2".into()),
            authorized_key: Some(good_key.public_key().clone()),
            ..Default::default()
        })
        .await?;

        // 1. 正确的 key：认证成功
        let session = connect_publickey(&server, Arc::clone(&good_key), "tester").await?;
        assert!(!session.is_closed());
        drop(session);

        // 2. 错误的 key：认证失败
        let config = Arc::new(russh::client::Config::default());
        let handler = TestClientHandler::expect_host_key(server.host_key.clone());
        let mut session = russh::client::connect(config, server.addr, handler).await?;
        let auth = session
            .authenticate_publickey("tester", PrivateKeyWithHashAlg::new(bad_key, None))
            .await?;
        assert!(!auth.success(), "未授权的公钥竟然通过了认证");

        // 3. 正确的 key 但错误的用户名：同样失败
        let auth = session
            .authenticate_publickey("intruder", PrivateKeyWithHashAlg::new(good_key, None))
            .await?;
        assert!(!auth.success(), "错误的用户名竟然通过了认证");

        // 4. password 路径也能走通
        let auth = session.authenticate_password("tester", "hunter2").await?;
        assert!(auth.success(), "password 认证应当成功");

        // 5. 错误密码被拒
        let config = Arc::new(russh::client::Config::default());
        let handler = TestClientHandler::accept_any_host_key();
        let mut session = russh::client::connect(config, server.addr, handler).await?;
        let auth = session.authenticate_password("tester", "wrong").await?;
        assert!(!auth.success(), "错误密码竟然通过了认证");

        server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn host_key_mismatch_is_rejected_by_client() -> anyhow::Result<()> {
    tokio::time::timeout(TIMEOUT, async {
        let key = Arc::new(generate_ed25519_key()?);
        let server = TestSshServer::start(TestServerConfig {
            username: "tester".into(),
            authorized_key: Some(key.public_key().clone()),
            ..Default::default()
        })
        .await?;

        // 拿一把与服务器无关的公钥当作期望值，客户端应当拒绝握手。
        let other = generate_ed25519_key()?;
        let config = Arc::new(russh::client::Config::default());
        let handler = TestClientHandler::expect_host_key(other.public_key().clone());
        let result = russh::client::connect(config, server.addr, handler).await;
        assert!(result.is_err(), "host key 不匹配时客户端应当拒绝连接");

        server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn direct_tcpip_bridges_to_real_tcp_target() -> anyhow::Result<()> {
    tokio::time::timeout(TIMEOUT, async {
        let key = Arc::new(generate_ed25519_key()?);
        let server = TestSshServer::start(TestServerConfig {
            username: "tester".into(),
            authorized_key: Some(key.public_key().clone()),
            ..Default::default()
        })
        .await?;
        let echo = TcpEchoServer::start().await?;

        let session = connect_publickey(&server, key, "tester").await?;
        let channel = session
            .channel_open_direct_tcpip(
                echo.addr.ip().to_string(),
                u32::from(echo.addr.port()),
                "127.0.0.1",
                12345,
            )
            .await?;

        let mut stream = channel.into_stream();
        stream.write_all(b"hello direct-tcpip").await?;
        let mut buf = [0u8; 18];
        stream.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"hello direct-tcpip");

        // 第二轮：验证通道可以持续双向传输
        stream.write_all(b"second round").await?;
        let mut buf2 = [0u8; 12];
        stream.read_exact(&mut buf2).await?;
        assert_eq!(&buf2, b"second round");

        // 客户端 EOF 应传播到目标，目标 FIN 回来使读到 0
        stream.shutdown().await?;
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await?;
        assert!(rest.is_empty(), "EOF 之后不应再有数据: {rest:?}");

        assert_eq!(echo.accepted_count(), 1);
        echo.shutdown().await;
        server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn direct_tcpip_is_refused_when_disabled() -> anyhow::Result<()> {
    tokio::time::timeout(TIMEOUT, async {
        let key = Arc::new(generate_ed25519_key()?);
        let server = TestSshServer::start(TestServerConfig {
            username: "tester".into(),
            authorized_key: Some(key.public_key().clone()),
            allow_direct_tcpip: false,
            ..Default::default()
        })
        .await?;
        let echo = TcpEchoServer::start().await?;

        let session = connect_publickey(&server, key, "tester").await?;
        let result = session
            .channel_open_direct_tcpip(
                echo.addr.ip().to_string(),
                u32::from(echo.addr.port()),
                "127.0.0.1",
                0,
            )
            .await;
        assert!(result.is_err(), "allow_direct_tcpip=false 时应拒绝开通道");
        assert_eq!(echo.accepted_count(), 0, "被拒的通道不应连到目标");

        echo.shutdown().await;
        server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn exec_cat_echoes_stdin_back_over_channel() -> anyhow::Result<()> {
    tokio::time::timeout(TIMEOUT, async {
        let key = Arc::new(generate_ed25519_key()?);
        let server = TestSshServer::start(TestServerConfig {
            username: "tester".into(),
            authorized_key: Some(key.public_key().clone()),
            ..Default::default()
        })
        .await?;

        let session = connect_publickey(&server, key, "tester").await?;
        let mut channel = session.channel_open_session().await?;
        channel.exec(true, "cat").await?;

        // 等 channel_success，确认服务端确实起了子进程
        let mut got_success = false;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Success => {
                    got_success = true;
                    break;
                }
                ChannelMsg::Failure => anyhow::bail!("exec 请求被服务端拒绝"),
                _ => {}
            }
        }
        assert!(got_success, "没有收到 exec 的 channel_success");

        channel.data(&b"helper-mode-probe"[..]).await?;
        channel.eof().await?;

        // 收集 stdout（Data）直到 EOF / Close
        let mut stdout = Vec::new();
        let mut exit_status = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }

        assert_eq!(
            String::from_utf8_lossy(&stdout),
            "helper-mode-probe",
            "cat 应把 stdin 原样返回"
        );
        assert_eq!(exit_status, Some(0), "cat 正常退出应返回 0");

        server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn exec_stderr_arrives_as_extended_data() -> anyhow::Result<()> {
    tokio::time::timeout(TIMEOUT, async {
        let key = Arc::new(generate_ed25519_key()?);
        let server = TestSshServer::start(TestServerConfig {
            username: "tester".into(),
            authorized_key: Some(key.public_key().clone()),
            ..Default::default()
        })
        .await?;

        let session = connect_publickey(&server, key, "tester").await?;
        let mut channel = session.channel_open_session().await?;
        channel
            .exec(true, "printf out; printf err 1>&2; exit 3")
            .await?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_status = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Success => {}
                ChannelMsg::Failure => anyhow::bail!("exec 请求被服务端拒绝"),
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext } => {
                    assert_eq!(ext, 1, "stderr 必须走 extended_data(1)");
                    stderr.extend_from_slice(&data);
                }
                ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }

        assert_eq!(String::from_utf8_lossy(&stdout), "out");
        assert_eq!(String::from_utf8_lossy(&stderr), "err");
        assert_eq!(exit_status, Some(3), "退出码应被原样透传");

        server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn exec_override_replaces_requested_command() -> anyhow::Result<()> {
    tokio::time::timeout(TIMEOUT, async {
        let key = Arc::new(generate_ed25519_key()?);
        let server = TestSshServer::start(TestServerConfig {
            username: "tester".into(),
            authorized_key: Some(key.public_key().clone()),
            exec_override: Some("printf overridden".into()),
            ..Default::default()
        })
        .await?;

        let session = connect_publickey(&server, key, "tester").await?;
        let mut channel = session.channel_open_session().await?;
        channel.exec(true, "this-command-does-not-exist").await?;

        let mut stdout = Vec::new();
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }
        assert_eq!(String::from_utf8_lossy(&stdout), "overridden");

        server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn exec_is_refused_when_disabled() -> anyhow::Result<()> {
    tokio::time::timeout(TIMEOUT, async {
        let key = Arc::new(generate_ed25519_key()?);
        let server = TestSshServer::start(TestServerConfig {
            username: "tester".into(),
            authorized_key: Some(key.public_key().clone()),
            allow_exec: false,
            ..Default::default()
        })
        .await?;

        let session = connect_publickey(&server, key, "tester").await?;
        let result = session.channel_open_session().await;
        assert!(result.is_err(), "allow_exec=false 时 session 通道应被拒绝");

        server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn kill_all_connections_breaks_client_and_allows_reconnect() -> anyhow::Result<()> {
    tokio::time::timeout(TIMEOUT, async {
        let key = Arc::new(generate_ed25519_key()?);
        let server = TestSshServer::start(TestServerConfig {
            username: "tester".into(),
            authorized_key: Some(key.public_key().clone()),
            ..Default::default()
        })
        .await?;
        let echo = TcpEchoServer::start().await?;

        let session = connect_publickey(&server, Arc::clone(&key), "tester").await?;
        // 开一个通道，确认链路先是好的
        let channel = session
            .channel_open_direct_tcpip(
                echo.addr.ip().to_string(),
                u32::from(echo.addr.port()),
                "127.0.0.1",
                0,
            )
            .await?;
        let mut stream = channel.into_stream();
        stream.write_all(b"before").await?;
        let mut buf = [0u8; 6];
        stream.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"before");
        assert_eq!(server.live_connection_count(), 1);

        // 强杀所有连接
        server.kill_all_connections();

        // 客户端应当观察到断开：通道读到 EOF 或错误
        let mut sink = Vec::new();
        let read_result = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut sink),
        )
        .await;
        assert!(
            read_result.is_ok(),
            "连接被强杀后读操作应立即返回，而不是挂住"
        );

        // 会话句柄也应被标记为关闭
        let mut closed = false;
        for _ in 0..100 {
            if session.is_closed() {
                closed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            closed,
            "kill_all_connections 之后 session.is_closed() 应为 true"
        );
        drop(stream);
        drop(session);

        // 监听端口仍在工作：新连接能建立并正常使用
        let session2 = connect_publickey(&server, key, "tester").await?;
        let channel2 = session2
            .channel_open_direct_tcpip(
                echo.addr.ip().to_string(),
                u32::from(echo.addr.port()),
                "127.0.0.1",
                0,
            )
            .await?;
        let mut stream2 = channel2.into_stream();
        stream2.write_all(b"after").await?;
        let mut buf2 = [0u8; 5];
        stream2.read_exact(&mut buf2).await?;
        assert_eq!(&buf2, b"after");

        assert_eq!(server.accepted_count(), 2, "应当记录到两次连接");

        echo.shutdown().await;
        server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn pause_accept_blocks_new_connections_until_resumed() -> anyhow::Result<()> {
    tokio::time::timeout(TIMEOUT, async {
        let key = Arc::new(generate_ed25519_key()?);
        let server = TestSshServer::start(TestServerConfig {
            username: "tester".into(),
            authorized_key: Some(key.public_key().clone()),
            ..Default::default()
        })
        .await?;

        server.pause_accept();
        assert!(server.is_paused());

        let config = Arc::new(russh::client::Config::default());
        let handler = TestClientHandler::accept_any_host_key();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            russh::client::connect(config, server.addr, handler),
        )
        .await;
        match result {
            Ok(Ok(_)) => anyhow::bail!("pause_accept 期间竟然握手成功"),
            Ok(Err(_)) => {}
            Err(_) => anyhow::bail!("pause_accept 期间连接应快速失败而不是超时"),
        }
        assert!(server.rejected_count() >= 1);

        server.resume_accept();
        let session = connect_publickey(&server, key, "tester").await?;
        assert!(!session.is_closed());

        server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn reused_host_key_survives_server_restart() -> anyhow::Result<()> {
    tokio::time::timeout(TIMEOUT, async {
        let client_key = Arc::new(generate_ed25519_key()?);
        let host_key = generate_ed25519_key()?;
        let expected_host_pub = host_key.public_key().clone();

        let server = TestSshServer::start(TestServerConfig {
            username: "tester".into(),
            authorized_key: Some(client_key.public_key().clone()),
            host_key: Some(host_key.clone()),
            ..Default::default()
        })
        .await?;
        assert_eq!(server.host_key, expected_host_pub);
        let addr = server.addr;
        server.shutdown().await;

        // 用同一把 host key 在同一个端口重启，客户端的 known-host 校验仍应通过
        let server2 = TestSshServer::start(TestServerConfig {
            username: "tester".into(),
            authorized_key: Some(client_key.public_key().clone()),
            host_key: Some(host_key),
            listen_addr: Some(addr),
            ..Default::default()
        })
        .await?;
        assert_eq!(server2.addr, addr);
        assert_eq!(server2.host_key, expected_host_pub);

        let session = connect_publickey(&server2, client_key, "tester").await?;
        assert!(!session.is_closed());

        server2.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}
