//! 真实 SSH 链路上的端到端自愈测试。
//!
//! ```text
//!   Dialer → TunnelManager → FlakyProxy → 测试 SSH 服务器 → echo
//!                                 ↑
//!                           在这里切断连接
//! ```

use std::sync::Arc;
use std::time::Duration;

use srp::tunnel::config::{AuthMethod, HelperConfig, ListenConfig, ReconnectConfig, SshConfig};
use srp::tunnel::{Config, DirectTcpipDialer, HostKeyPolicy, TunnelManager, TunnelMode};
use srp_testkit::{
    generate_ed25519_key, FlakyProxy, TcpEchoServer, TestServerConfig, TestSshServer,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn wait_until<F>(label: &str, timeout: Duration, mut cond: F)
where
    F: FnMut() -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for: {label}");
}

struct Rig {
    server: srp_testkit::TestSshServerHandle,
    proxy: srp_testkit::FlakyProxyHandle,
    echo: srp_testkit::TcpEchoServerHandle,
    tunnel: Arc<TunnelManager>,
    _tmp: tempfile::TempDir,
}

fn make_config(
    host: String,
    port: u16,
    key_path: std::path::PathBuf,
    fingerprint: String,
) -> Arc<Config> {
    Arc::new(Config {
        ssh: SshConfig {
            host,
            port,
            user: "tester".into(),
            auth: AuthMethod::PublicKey {
                path: key_path,
                passphrase: None,
            },
            host_key: HostKeyPolicy::Pinned(fingerprint),
            known_hosts: None,
            connect_timeout: Duration::from_secs(5),
            keepalive_interval: Duration::from_secs(1),
            keepalive_max: 2,
        },
        mode: TunnelMode::DirectTcpip,
        listen: ListenConfig::default(),
        reconnect: ReconnectConfig {
            initial_delay: Duration::from_millis(50),
            max_delay: Duration::from_millis(300),
            dial_wait: Duration::from_secs(8),
            ..Default::default()
        },
        helper: HelperConfig::default(),
    })
}

impl Rig {
    async fn start() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");

        let client_key = generate_ed25519_key().expect("client key");
        let key_path = tmp.path().join("id_ed25519");
        let pem = client_key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("encode private key");
        std::fs::write(&key_path, pem.as_bytes()).expect("write key");

        let echo = TcpEchoServer::start().await.expect("echo");
        let server = TestSshServer::start(TestServerConfig {
            username: "tester".into(),
            authorized_key: Some(client_key.public_key().clone()),
            ..Default::default()
        })
        .await
        .expect("ssh server");

        let proxy = FlakyProxy::start(server.addr).await.expect("proxy");

        let fingerprint = server
            .host_key
            .fingerprint(russh::keys::ssh_key::HashAlg::Sha256)
            .to_string();

        let cfg = make_config(
            proxy.listen_addr.ip().to_string(),
            proxy.listen_addr.port(),
            key_path.clone(),
            fingerprint,
        );

        let tunnel = TunnelManager::new(cfg);
        let t = tunnel.clone();
        tokio::spawn(async move { t.supervise().await });

        Self {
            server,
            proxy,
            echo,
            tunnel,
            _tmp: tmp,
        }
    }

    fn dialer(&self) -> DirectTcpipDialer {
        DirectTcpipDialer::new(self.tunnel.clone(), Duration::from_secs(8))
    }

    async fn wait_connected(&self) {
        let t = self.tunnel.clone();
        wait_until("tunnel to come up", Duration::from_secs(15), || {
            t.state().is_up()
        })
        .await;
    }

    async fn echo_roundtrip(&self, payload: &[u8]) {
        use srp::frontend::Dialer;
        let addr = srp_proto::TargetAddr::V4(
            match self.echo.addr.ip() {
                std::net::IpAddr::V4(v4) => v4.octets(),
                _ => panic!("echo server should be v4"),
            },
            self.echo.addr.port(),
        );
        let dialer = self.dialer();
        let mut stream = dialer.dial(&addr).await.expect("dial through tunnel");
        stream.write_all(payload).await.expect("write");
        let mut got = vec![0u8; payload.len()];
        stream.read_exact(&mut got).await.expect("read echo");
        assert_eq!(got, payload, "payload corrupted through the tunnel");
    }

    async fn shutdown(self) {
        self.tunnel.shutdown().await;
        self.proxy.shutdown().await;
        self.server.shutdown().await;
        self.echo.shutdown().await;
    }
}

#[tokio::test]
async fn baseline_traffic_flows_through_a_real_ssh_tunnel() {
    let rig = Rig::start().await;
    rig.wait_connected().await;
    rig.echo_roundtrip(b"hello over real ssh").await;
    assert_eq!(
        rig.tunnel.connect_count(),
        1,
        "a healthy link must not reconnect"
    );
    rig.shutdown().await;
}

#[tokio::test]
async fn tunnel_self_heals_after_the_link_is_cut() {
    let rig = Rig::start().await;
    rig.wait_connected().await;
    rig.echo_roundtrip(b"before the cut").await;
    let before = rig.tunnel.connect_count();

    rig.proxy.cut_now();

    let t = rig.tunnel.clone();
    wait_until(
        "tunnel to reconnect after the cut",
        Duration::from_secs(20),
        || t.connect_count() > before,
    )
    .await;
    rig.wait_connected().await;

    rig.echo_roundtrip(b"after the heal").await;
    rig.shutdown().await;
}

#[tokio::test]
async fn repeated_cuts_keep_healing() {
    let rig = Rig::start().await;
    rig.wait_connected().await;

    for round in 0..3u32 {
        let before = rig.tunnel.connect_count();
        rig.proxy.cut_now();

        let t = rig.tunnel.clone();
        wait_until(
            &format!("reconnect after cut {round}"),
            Duration::from_secs(20),
            || t.connect_count() > before,
        )
        .await;
        rig.wait_connected().await;
        rig.echo_roundtrip(format!("round {round}").as_bytes())
            .await;
    }

    assert!(
        rig.tunnel.connect_count() >= 4,
        "expected at least 4 connections (1 initial + 3 heals), got {}",
        rig.tunnel.connect_count()
    );
    rig.shutdown().await;
}

#[tokio::test]
async fn keepalive_detects_a_silently_dropping_link() {
    let rig = Rig::start().await;
    rig.wait_connected().await;
    let before = rig.tunnel.connect_count();

    rig.proxy.swallow_data(true);

    // 等连接被保活机制判定为死链（1s 间隔 × 2 次失败 ≈ 3s）。
    let t = rig.tunnel.clone();
    wait_until(
        "tunnel to detect the silently dropping link",
        Duration::from_secs(10),
        || !t.state().is_up(),
    )
    .await;

    // 连接已死，恢复链路让新握手可以通过。
    rig.proxy.swallow_data(false);

    // 等重连成功。
    wait_until(
        "tunnel to reconnect after silent link detection",
        Duration::from_secs(15),
        || t.connect_count() > before,
    )
    .await;
    rig.wait_connected().await;
    rig.echo_roundtrip(b"recovered from a silent link").await;
    rig.shutdown().await;
}

#[tokio::test]
async fn requests_during_an_outage_queue_and_then_succeed() {
    let rig = Rig::start().await;
    rig.wait_connected().await;

    rig.proxy.blackhole(true);

    let payload = b"queued during the outage";
    let dialer = rig.dialer();
    let echo_addr = rig.echo.addr;
    let task = tokio::spawn(async move {
        use srp::frontend::Dialer;
        let addr = srp_proto::TargetAddr::V4(
            match echo_addr.ip() {
                std::net::IpAddr::V4(v4) => v4.octets(),
                _ => unreachable!(),
            },
            echo_addr.port(),
        );
        let mut s = dialer.dial(&addr).await?;
        s.write_all(payload).await.ok();
        let mut got = vec![0u8; payload.len()];
        s.read_exact(&mut got).await.ok();
        Ok::<Vec<u8>, srp::frontend::DialError>(got)
    });

    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        !task.is_finished(),
        "the dial should still be waiting for the tunnel, not failing fast"
    );

    rig.proxy.blackhole(false);
    let got = tokio::time::timeout(Duration::from_secs(15), task)
        .await
        .expect("queued dial timed out")
        .expect("task panicked")
        .expect("queued dial should succeed once the tunnel is back");
    assert_eq!(got, payload, "queued request returned corrupted data");

    rig.shutdown().await;
}

#[tokio::test]
async fn large_transfer_after_healing_is_byte_exact() {
    let rig = Rig::start().await;
    rig.wait_connected().await;

    let before = rig.tunnel.connect_count();
    rig.proxy.cut_now();
    let t = rig.tunnel.clone();
    wait_until("reconnect", Duration::from_secs(20), || {
        t.connect_count() > before
    })
    .await;
    rig.wait_connected().await;

    let payload: Vec<u8> = (0..512 * 1024).map(|i| (i % 251) as u8).collect();
    rig.echo_roundtrip(&payload).await;
    rig.shutdown().await;
}

#[tokio::test]
async fn self_healing_never_accepts_a_wrong_host_key() {
    let tmp = tempfile::tempdir().unwrap();
    let client_key = generate_ed25519_key().unwrap();
    let key_path = tmp.path().join("id");
    std::fs::write(
        &key_path,
        client_key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();

    let server = TestSshServer::start(TestServerConfig {
        username: "tester".into(),
        authorized_key: Some(client_key.public_key().clone()),
        ..Default::default()
    })
    .await
    .unwrap();

    let other = generate_ed25519_key().unwrap();
    let wrong_fp = other
        .public_key()
        .fingerprint(russh::keys::ssh_key::HashAlg::Sha256)
        .to_string();

    let cfg = make_config(
        server.addr.ip().to_string(),
        server.addr.port(),
        key_path,
        wrong_fp,
    );

    let tunnel = TunnelManager::new(cfg);
    let t = tunnel.clone();
    tokio::spawn(async move { t.supervise().await });

    tokio::time::sleep(Duration::from_secs(3)).await;

    assert_eq!(
        tunnel.connect_count(),
        0,
        "a wrong host key must never yield a usable session"
    );
    assert!(
        !tunnel.state().is_up(),
        "tunnel must not report Up with a mismatched host key"
    );

    use srp::frontend::Dialer;
    let dialer = DirectTcpipDialer::new(tunnel.clone(), Duration::from_millis(500));
    let err = match dialer
        .dial(&srp_proto::TargetAddr::V4([127, 0, 0, 1], 9))
        .await
    {
        Ok(_) => panic!("dial must not succeed when the host key is rejected"),
        Err(e) => e,
    };
    assert_eq!(err, srp::frontend::DialError::NetworkUnreachable);

    tunnel.shutdown().await;
    server.shutdown().await;
}
