//! SOCKS5 服务端入口（RFC 1928 + RFC 1929）。
//!
//! 只做协议翻译：握手 → 得出 [`TargetAddr`] → 交给 [`Dialer`] → 回写 REP → 转发。
//! 域名一律原样上送，不在本地解析：DNS 解析留给远端出口，可以绕过本地 DNS 污染，
//! 也让隧道断线重连后的重放保持幂等（本地解析出的 IP 可能在重放时已经失效）。

use std::sync::Arc;

use anyhow::{bail, Context as _};
use bytes::{BufMut as _, BytesMut};
use srp_proto::TargetAddr;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use super::{ct_eq, relay, validate_domain, DialError, Dialer};

/// 协议版本。
const VER_SOCKS5: u8 = 0x05;
/// RFC 1929 的子协商版本，与 SOCKS 版本号无关，容易看混所以单列一个常量。
const VER_USERPASS: u8 = 0x01;

const METHOD_NONE: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_UNACCEPTABLE: u8 = 0xFF;

const CMD_CONNECT: u8 = 0x01;
const CMD_BIND: u8 = 0x02;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_NOT_ALLOWED: u8 = 0x02;
const REP_NET_UNREACHABLE: u8 = 0x03;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONN_REFUSED: u8 = 0x05;
const REP_TTL_EXPIRED: u8 = 0x06;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

/// 域名长度上限由 1 字节长度前缀决定，读取时先按上限收，再交给 proto 校验内容。
const MAX_DOMAIN_LEN: usize = 255;

/// SOCKS5 入口。
///
/// 凭据在构造时固定，所以一个实例可以被所有连接共享：把认证配置放进每次调用的
/// 参数里，很容易出现某条路径忘传而静默降级成"无认证代理"。
pub struct Socks5Server {
    /// `Some` 表示强制 RFC 1929 用户名/密码认证，`None` 表示接受无认证。
    credentials: Option<(String, String)>,
}

impl Socks5Server {
    pub fn new(credentials: Option<(String, String)>) -> Self {
        Self { credentials }
    }

    fn required_method(&self) -> u8 {
        if self.credentials.is_some() {
            METHOD_USERPASS
        } else {
            METHOD_NONE
        }
    }

    /// 处理一条客户端连接，直到隧道结束。
    ///
    /// 返回 `Ok(())` 表示"这条连接按协议正常收场"——包括已经用 REP 错误码明确
    /// 告知客户端的拒绝（认证失败、命令不支持、dial 失败）。这类结果不该冒泡成
    /// 错误，否则调用方会为每个正常的"目标拒绝连接"打一条错误日志。
    /// 只有客户端违反协议或 socket 本身出问题才返回 `Err`。
    pub async fn serve_conn<S, D>(&self, mut stream: S, dialer: Arc<D>) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
        D: Dialer + ?Sized,
    {
        if !self.negotiate_method(&mut stream).await? {
            return Ok(());
        }
        if !self.authenticate(&mut stream).await? {
            return Ok(());
        }

        let addr = match self.read_request(&mut stream).await? {
            Some(a) => a,
            None => return Ok(()),
        };

        let upstream = match dialer.dial(&addr).await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(target = %addr, reason = %e, "socks5 upstream dial failed");
                send_reply(&mut stream, rep_for(e)).await?;
                return Ok(());
            }
        };

        send_reply(&mut stream, REP_SUCCESS).await?;
        let (c2s, s2c) = relay(stream, upstream).await?;
        tracing::debug!(target = %addr, sent = c2s, received = s2c, "socks5 tunnel closed");
        Ok(())
    }

    /// 方法协商。返回 `false` 表示已回 0xFF、调用方应直接关闭连接。
    async fn negotiate_method<S>(&self, stream: &mut S) -> anyhow::Result<bool>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut head = [0u8; 2];
        stream
            .read_exact(&mut head)
            .await
            .context("read socks5 greeting")?;
        if head[0] != VER_SOCKS5 {
            bail!("unsupported socks version 0x{:02x}", head[0]);
        }
        // NMETHODS = 0 的问候没有任何可选方法，属于畸形请求而不是"协商失败"。
        if head[1] == 0 {
            bail!("socks5 greeting advertises zero methods");
        }

        let mut methods = vec![0u8; head[1] as usize];
        stream
            .read_exact(&mut methods)
            .await
            .context("read socks5 method list")?;

        let want = self.required_method();
        if methods.contains(&want) {
            stream
                .write_all(&[VER_SOCKS5, want])
                .await
                .context("write method choice")?;
            Ok(true)
        } else {
            // 必须先把 0xFF 写出去再关，否则客户端只能看到一个无解释的 RST。
            stream
                .write_all(&[VER_SOCKS5, METHOD_UNACCEPTABLE])
                .await
                .context("write method rejection")?;
            tracing::debug!(offered = ?methods, required = want, "socks5 method negotiation failed");
            Ok(false)
        }
    }

    /// RFC 1929 子协商。无需认证时直接通过。返回 `false` 表示认证失败、连接应关闭。
    async fn authenticate<S>(&self, stream: &mut S) -> anyhow::Result<bool>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let Some((user, pass)) = self.credentials.as_ref() else {
            return Ok(true);
        };

        let mut head = [0u8; 2];
        stream
            .read_exact(&mut head)
            .await
            .context("read userpass header")?;
        if head[0] != VER_USERPASS {
            bail!(
                "unsupported userpass subnegotiation version 0x{:02x}",
                head[0]
            );
        }
        let mut got_user = vec![0u8; head[1] as usize];
        stream
            .read_exact(&mut got_user)
            .await
            .context("read username")?;

        let mut plen = [0u8; 1];
        stream
            .read_exact(&mut plen)
            .await
            .context("read password length")?;
        let mut got_pass = vec![0u8; plen[0] as usize];
        stream
            .read_exact(&mut got_pass)
            .await
            .context("read password")?;

        // 两个字段都比较完再判定，避免用户名错误时提前返回而暴露时间差。
        let ok = ct_eq(&got_user, user.as_bytes()) & ct_eq(&got_pass, pass.as_bytes());
        // 非 0 状态即失败，RFC 未定义具体值，用 0x01 表示通用拒绝。
        let status = if ok { 0x00 } else { 0x01 };
        stream
            .write_all(&[VER_USERPASS, status])
            .await
            .context("write auth result")?;
        if !ok {
            tracing::debug!("socks5 userpass authentication rejected");
        }
        Ok(ok)
    }

    /// 解析 CONNECT 请求。返回 `None` 表示已回错误码、连接应关闭。
    async fn read_request<S>(&self, stream: &mut S) -> anyhow::Result<Option<TargetAddr>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut head = [0u8; 3];
        stream
            .read_exact(&mut head)
            .await
            .context("read socks5 request header")?;
        if head[0] != VER_SOCKS5 {
            bail!("unsupported socks version 0x{:02x} in request", head[0]);
        }

        // 命令与地址类型的校验顺序有讲究：先判命令，因为 BIND/UDP 的地址部分
        // 语义不同，没必要为一个注定被拒的命令去解析地址。
        match head[1] {
            CMD_CONNECT => {}
            CMD_BIND | CMD_UDP_ASSOCIATE => {
                tracing::debug!(cmd = head[1], "socks5 command not supported");
                send_reply(stream, REP_CMD_NOT_SUPPORTED).await?;
                return Ok(None);
            }
            other => {
                tracing::debug!(cmd = other, "unknown socks5 command");
                send_reply(stream, REP_CMD_NOT_SUPPORTED).await?;
                return Ok(None);
            }
        }

        match self.read_addr(stream).await? {
            Some(addr) => Ok(Some(addr)),
            None => {
                send_reply(stream, REP_ATYP_NOT_SUPPORTED).await?;
                Ok(None)
            }
        }
    }

    /// 读地址。返回 `None` 仅代表 ATYP 不认识（由调用方回 0x08）。
    ///
    /// SOCKS5 的 ATYP 取值与 `TargetAddr::KIND_*` 同构，所以这里只负责按类型
    /// 读够字节，解码与内容校验（UTF-8、非空域名）复用 srp-proto，不重写一遍。
    async fn read_addr<S>(&self, stream: &mut S) -> anyhow::Result<Option<TargetAddr>>
    where
        S: AsyncRead + Unpin,
    {
        let mut atyp = [0u8; 1];
        stream
            .read_exact(&mut atyp)
            .await
            .context("read address type")?;

        let body_len = match atyp[0] {
            TargetAddr::KIND_V4 => 4 + 2,
            TargetAddr::KIND_V6 => 16 + 2,
            TargetAddr::KIND_DOMAIN => {
                let mut len = [0u8; 1];
                stream
                    .read_exact(&mut len)
                    .await
                    .context("read domain length")?;
                if len[0] == 0 {
                    bail!("socks5 request carries empty domain name");
                }
                let n = len[0] as usize;
                debug_assert!(n <= MAX_DOMAIN_LEN);
                // 把长度前缀重新拼回去交给 decode，省得在这里复制一份域名解析逻辑。
                let mut buf = BytesMut::with_capacity(2 + n + 2);
                buf.put_u8(TargetAddr::KIND_DOMAIN);
                buf.put_u8(len[0]);
                let mut rest = vec![0u8; n + 2];
                stream
                    .read_exact(&mut rest)
                    .await
                    .context("read domain and port")?;
                buf.put_slice(&rest);
                let addr = TargetAddr::decode(&mut buf).context("decode socks5 domain address")?;
                if let TargetAddr::Domain(d, _) = &addr {
                    validate_domain(d).map_err(|why| anyhow::anyhow!("bad domain: {why}"))?;
                }
                return Ok(Some(addr));
            }
            _ => return Ok(None),
        };

        let mut buf = BytesMut::with_capacity(1 + body_len);
        buf.put_u8(atyp[0]);
        let mut rest = vec![0u8; body_len];
        stream
            .read_exact(&mut rest)
            .await
            .context("read address body")?;
        buf.put_slice(&rest);
        Ok(Some(
            TargetAddr::decode(&mut buf).context("decode socks5 address")?,
        ))
    }
}

/// 便利入口：无认证的默认配置。
pub async fn serve_conn<S, D>(stream: S, dialer: Arc<D>) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    D: Dialer + ?Sized,
{
    Socks5Server::new(None).serve_conn(stream, dialer).await
}

fn rep_for(e: DialError) -> u8 {
    match e {
        DialError::HostUnreachable => REP_HOST_UNREACHABLE,
        DialError::ConnectionRefused => REP_CONN_REFUSED,
        DialError::NetworkUnreachable => REP_NET_UNREACHABLE,
        DialError::TimedOut => REP_TTL_EXPIRED,
        DialError::Forbidden => REP_NOT_ALLOWED,
        DialError::Internal => REP_GENERAL_FAILURE,
    }
}

/// 回一条 REP。
///
/// BND.ADDR/BND.PORT 一律填 `0.0.0.0:0`：CONNECT 的绑定地址对客户端几乎无用，
/// 而暴露出口的真实地址等于泄漏隧道拓扑；RFC 也没有要求它必须是真实地址。
/// 固定 10 字节还让回复能一次 write 出去，不会被拆成两个小包。
async fn send_reply<S>(stream: &mut S, rep: u8) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let frame = [VER_SOCKS5, rep, 0x00, TargetAddr::KIND_V4, 0, 0, 0, 0, 0, 0];
    stream.write_all(&frame).await.context("write socks5 reply")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::test_support::MockDialer;
    use tokio::io::duplex;

    /// 期望的成功回复，测试里出现多次，抽成常量避免手抄出错。
    const OK_REPLY: [u8; 10] = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

    fn connect_req(atyp: u8, body: &[u8], port: u16) -> Vec<u8> {
        let mut v = vec![VER_SOCKS5, CMD_CONNECT, 0x00, atyp];
        v.extend_from_slice(body);
        v.extend_from_slice(&port.to_be_bytes());
        v
    }

    fn domain_req(host: &str, port: u16) -> Vec<u8> {
        let mut body = vec![host.len() as u8];
        body.extend_from_slice(host.as_bytes());
        connect_req(TargetAddr::KIND_DOMAIN, &body, port)
    }

    #[tokio::test]
    async fn no_auth_connect_succeeds_for_all_address_kinds() {
        let cases: Vec<(Vec<u8>, TargetAddr)> = vec![
            (
                domain_req("example.com", 443),
                TargetAddr::Domain("example.com".into(), 443),
            ),
            (
                connect_req(TargetAddr::KIND_V4, &[1, 2, 3, 4], 80),
                TargetAddr::V4([1, 2, 3, 4], 80),
            ),
            (
                connect_req(TargetAddr::KIND_V6, &[0u8; 16], 8443),
                TargetAddr::V6([0u8; 16], 8443),
            ),
        ];

        for (req, expected) in cases {
            let (dialer, peer) = MockDialer::success();
            let (mut client, server) = duplex(4096);
            let d = dialer.clone();
            let task = tokio::spawn(async move { serve_conn(server, d).await });

            client
                .write_all(&[VER_SOCKS5, 1, METHOD_NONE])
                .await
                .unwrap();
            let mut choice = [0u8; 2];
            client.read_exact(&mut choice).await.unwrap();
            assert_eq!(choice, [VER_SOCKS5, METHOD_NONE]);

            client.write_all(&req).await.unwrap();
            let mut reply = [0u8; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, OK_REPLY, "unexpected reply for {expected}");

            // copy_bidirectional 要等两个方向都 EOF，两端都得关掉才会返回。
            drop(client);
            drop(peer);
            task.await.unwrap().unwrap();
            assert_eq!(dialer.dialed(), vec![expected]);
        }
    }

    #[tokio::test]
    async fn userpass_auth_accepts_correct_credentials() {
        let (dialer, peer) = MockDialer::success();
        let (mut client, server) = duplex(4096);
        let srv = Socks5Server::new(Some(("neko".into(), "s3cret".into())));
        let d = dialer.clone();
        let task = tokio::spawn(async move { srv.serve_conn(server, d).await });

        client
            .write_all(&[VER_SOCKS5, 2, METHOD_NONE, METHOD_USERPASS])
            .await
            .unwrap();
        let mut choice = [0u8; 2];
        client.read_exact(&mut choice).await.unwrap();
        // 即使客户端也提供了 0x00，配置了凭据就必须选 0x02，否则等于静默放开认证。
        assert_eq!(choice, [VER_SOCKS5, METHOD_USERPASS]);

        client
            .write_all(&[
                VER_USERPASS,
                4,
                b'n',
                b'e',
                b'k',
                b'o',
                6,
                b's',
                b'3',
                b'c',
                b'r',
                b'e',
                b't',
            ])
            .await
            .unwrap();
        let mut auth = [0u8; 2];
        client.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, [VER_USERPASS, 0x00]);

        client
            .write_all(&domain_req("srv.internal", 22))
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, OK_REPLY);

        drop(client);
        drop(peer);
        task.await.unwrap().unwrap();
        assert_eq!(
            dialer.dialed(),
            vec![TargetAddr::Domain("srv.internal".into(), 22)]
        );
    }

    #[tokio::test]
    async fn userpass_auth_rejects_wrong_password() {
        let dialer = MockDialer::failing(DialError::Internal);
        let (mut client, server) = duplex(4096);
        let srv = Socks5Server::new(Some(("neko".into(), "s3cret".into())));
        let d = dialer.clone();
        let task = tokio::spawn(async move { srv.serve_conn(server, d).await });

        client
            .write_all(&[VER_SOCKS5, 1, METHOD_USERPASS])
            .await
            .unwrap();
        let mut choice = [0u8; 2];
        client.read_exact(&mut choice).await.unwrap();
        assert_eq!(choice, [VER_SOCKS5, METHOD_USERPASS]);

        client
            .write_all(&[VER_USERPASS, 4, b'n', b'e', b'k', b'o', 3, b'b', b'a', b'd'])
            .await
            .unwrap();
        let mut auth = [0u8; 2];
        client.read_exact(&mut auth).await.unwrap();
        assert_ne!(auth[1], 0x00, "failed auth must报非零状态");

        // 认证失败后不得继续读请求，更不能碰 dialer。
        let mut tail = [0u8; 1];
        assert_eq!(client.read(&mut tail).await.unwrap(), 0);
        task.await.unwrap().unwrap();
        assert!(dialer.dialed().is_empty());
    }

    #[tokio::test]
    async fn method_negotiation_failure_returns_ff() {
        let dialer = MockDialer::failing(DialError::Internal);
        let (mut client, server) = duplex(4096);
        let srv = Socks5Server::new(Some(("u".into(), "p".into())));
        let d = dialer.clone();
        let task = tokio::spawn(async move { srv.serve_conn(server, d).await });

        // 客户端只支持无认证，而服务端要求 0x02。
        client
            .write_all(&[VER_SOCKS5, 1, METHOD_NONE])
            .await
            .unwrap();
        let mut choice = [0u8; 2];
        client.read_exact(&mut choice).await.unwrap();
        assert_eq!(choice, [VER_SOCKS5, METHOD_UNACCEPTABLE]);

        let mut tail = [0u8; 1];
        assert_eq!(client.read(&mut tail).await.unwrap(), 0);
        task.await.unwrap().unwrap();
        assert!(dialer.dialed().is_empty());
    }

    #[tokio::test]
    async fn unsupported_commands_return_0x07() {
        for cmd in [CMD_BIND, CMD_UDP_ASSOCIATE, 0x09] {
            let dialer = MockDialer::failing(DialError::Internal);
            let (mut client, server) = duplex(4096);
            let d = dialer.clone();
            let task = tokio::spawn(async move { serve_conn(server, d).await });

            client
                .write_all(&[VER_SOCKS5, 1, METHOD_NONE])
                .await
                .unwrap();
            let mut choice = [0u8; 2];
            client.read_exact(&mut choice).await.unwrap();

            let mut req = vec![VER_SOCKS5, cmd, 0x00, TargetAddr::KIND_V4, 1, 2, 3, 4];
            req.extend_from_slice(&80u16.to_be_bytes());
            client.write_all(&req).await.unwrap();

            let mut reply = [0u8; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[1], REP_CMD_NOT_SUPPORTED, "cmd 0x{cmd:02x}");

            drop(client);
            task.await.unwrap().unwrap();
            assert!(dialer.dialed().is_empty());
        }
    }

    #[tokio::test]
    async fn dial_errors_map_to_reply_codes() {
        let cases = [
            (DialError::HostUnreachable, REP_HOST_UNREACHABLE),
            (DialError::ConnectionRefused, REP_CONN_REFUSED),
            (DialError::NetworkUnreachable, REP_NET_UNREACHABLE),
            (DialError::TimedOut, REP_TTL_EXPIRED),
            (DialError::Forbidden, REP_NOT_ALLOWED),
            (DialError::Internal, REP_GENERAL_FAILURE),
        ];

        for (err, want) in cases {
            let dialer = MockDialer::failing(err);
            let (mut client, server) = duplex(4096);
            let task = tokio::spawn(async move { serve_conn(server, dialer).await });

            client
                .write_all(&[VER_SOCKS5, 1, METHOD_NONE])
                .await
                .unwrap();
            let mut choice = [0u8; 2];
            client.read_exact(&mut choice).await.unwrap();

            client
                .write_all(&domain_req("nope.invalid", 443))
                .await
                .unwrap();
            let mut reply = [0u8; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[1], want, "{err:?}");
            // 失败回复的地址字段也必须齐全，否则客户端会卡在读上。
            assert_eq!(reply[3], TargetAddr::KIND_V4);

            drop(client);
            task.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn relays_payload_in_both_directions() {
        let (dialer, mut peer) = MockDialer::success();
        let (mut client, server) = duplex(4096);
        let task = tokio::spawn(async move { serve_conn(server, dialer).await });

        client
            .write_all(&[VER_SOCKS5, 1, METHOD_NONE])
            .await
            .unwrap();
        let mut choice = [0u8; 2];
        client.read_exact(&mut choice).await.unwrap();
        client.write_all(&domain_req("echo.test", 7)).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, OK_REPLY);

        client.write_all(b"ping").await.unwrap();
        let mut up = [0u8; 4];
        peer.read_exact(&mut up).await.unwrap();
        assert_eq!(&up, b"ping");

        peer.write_all(b"pong").await.unwrap();
        let mut down = [0u8; 4];
        client.read_exact(&mut down).await.unwrap();
        assert_eq!(&down, b"pong");

        drop(client);
        drop(peer);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn rejects_unknown_address_type() {
        let dialer = MockDialer::failing(DialError::Internal);
        let (mut client, server) = duplex(4096);
        let d = dialer.clone();
        let task = tokio::spawn(async move { serve_conn(server, d).await });

        client
            .write_all(&[VER_SOCKS5, 1, METHOD_NONE])
            .await
            .unwrap();
        let mut choice = [0u8; 2];
        client.read_exact(&mut choice).await.unwrap();
        client
            .write_all(&[VER_SOCKS5, CMD_CONNECT, 0x00, 0x07, 0, 0])
            .await
            .unwrap();

        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], REP_ATYP_NOT_SUPPORTED);
        drop(client);
        task.await.unwrap().unwrap();
        assert!(dialer.dialed().is_empty());
    }

    #[tokio::test]
    async fn rejects_wrong_socks_version() {
        let dialer = MockDialer::failing(DialError::Internal);
        let (mut client, server) = duplex(4096);
        let task = tokio::spawn(async move { serve_conn(server, dialer).await });

        // SOCKS4 的问候：必须当成协议错误上报，而不是尝试兼容。
        client.write_all(&[0x04, 0x01, 0x00, 0x50]).await.unwrap();
        drop(client);
        let err = task.await.unwrap().expect_err("socks4 must be rejected");
        assert!(
            err.to_string().contains("unsupported socks version"),
            "{err:#}"
        );
    }
}
