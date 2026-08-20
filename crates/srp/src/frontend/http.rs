//! HTTP CONNECT 代理入口。
//!
//! 只实现 CONNECT 隧道，不做普通 HTTP 转发：转发明文 HTTP 需要完整的报文解析、
//! 连接复用与缓存语义，攻击面远大于收益，而本项目的目标是把字节安全送到远端出口。
//! 因此 GET/POST 之类一律以 405 拒绝，并在响应体里说明只支持 CONNECT。

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use anyhow::Context as _;
use base64::Engine as _;
use srp_proto::TargetAddr;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use super::{ct_eq, relay, validate_domain, DialError, Dialer};

/// 请求头总大小上限。
///
/// 没有上限的话，一个不发 `\r\n\r\n` 的客户端就能让我们无限增长缓冲区——
/// 单连接就能打爆内存。16 KiB 足够容纳任何合法的 CONNECT 请求头。
const MAX_HEAD_BYTES: usize = 16 * 1024;

/// 单次 read 的块大小。头部通常一个包就到齐，这个尺寸只是避免逐字节系统调用。
const READ_CHUNK: usize = 4 * 1024;

/// HTTP CONNECT 入口。凭据在构造时固定，理由同 SOCKS5：避免某条调用路径忘传而静默放开认证。
pub struct HttpConnectServer {
    credentials: Option<(String, String)>,
}

/// 解析好的请求头。
struct Head {
    target: TargetAddr,
    /// `Proxy-Authorization` 的原始值（若有）。
    proxy_auth: Option<String>,
    /// 头部之后被一并读进来的字节。
    ///
    /// CONNECT 的客户端通常会等 200 再说话，但"通常"不是保证：TLS 抢跑
    /// （把 ClientHello 跟请求头粘在一个包里）是真实存在的优化。这些字节属于隧道
    /// 载荷，丢掉就会造成握手莫名失败，所以必须原样交给上游。
    leftover: Vec<u8>,
}

impl HttpConnectServer {
    pub fn new(credentials: Option<(String, String)>) -> Self {
        Self { credentials }
    }

    /// 处理一条客户端连接。
    ///
    /// `Ok(())` 表示这条连接按 HTTP 语义正常收场（隧道跑完、发出 407 挑战、
    /// 或已用 5xx 明确告知 dial 失败）。`Err` 只在客户端用错协议
    /// （非 CONNECT、请求行畸形、头部超限）或 socket 本身故障时返回，
    /// 这样调用方的错误日志里只剩下真正需要人看的东西。
    pub async fn serve_conn<S, D>(&self, mut stream: S, dialer: Arc<D>) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
        D: Dialer + ?Sized,
    {
        let head = match self.read_head(&mut stream).await {
            Ok(h) => h,
            Err(rejection) => return rejection.emit(&mut stream).await,
        };

        if let Err(rejection) = self.authorize(head.proxy_auth.as_deref()) {
            return rejection.emit(&mut stream).await;
        }

        let mut upstream = match dialer.dial(&head.target).await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(target = %head.target, reason = %e, "http connect upstream dial failed");
                return Rejection::from_dial(e).emit(&mut stream).await;
            }
        };

        stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .context("write 200 response")?;

        // 抢跑的载荷必须在进入 copy 循环之前补给上游，否则上游会一直等一个
        // 已经躺在我们缓冲区里的握手包。
        if !head.leftover.is_empty() {
            upstream
                .write_all(&head.leftover)
                .await
                .context("flush pre-read payload to upstream")?;
        }

        let (c2s, s2c) = relay(stream, upstream).await?;
        tracing::debug!(target = %head.target, sent = c2s, received = s2c, "http connect tunnel closed");
        Ok(())
    }

    /// 读取并解析请求头。
    async fn read_head<S>(&self, stream: &mut S) -> Result<Head, Rejection>
    where
        S: AsyncRead + Unpin,
    {
        let mut buf = Vec::with_capacity(READ_CHUNK);
        let mut chunk = [0u8; READ_CHUNK];

        // 已扫描过、确定不可能是分隔符起点的前缀长度。每轮 read 之后只需从这里
        // 继续扫，既避免 O(n²) 重复扫描，也保证 "\r\n\r" + "\n" 这种跨包切分
        // 不被漏掉——注意这个偏移必须在 read *之前* 按旧长度算好，
        // 若按新长度回退 3 字节，一次读完的头部末尾分隔符反而会被跳过。
        let mut scanned = 0usize;

        let head_end = loop {
            if let Some(pos) = find_crlf_crlf(&buf[scanned..]) {
                break scanned + pos + 4;
            }
            scanned = buf.len().saturating_sub(3);
            if buf.len() > MAX_HEAD_BYTES {
                return Err(Rejection::HeadTooLarge);
            }
            let n = match stream.read(&mut chunk).await {
                Ok(0) => {
                    return Err(Rejection::Fatal(anyhow::anyhow!(
                        "client closed connection before end of request headers"
                    )))
                }
                Ok(n) => n,
                Err(e) => {
                    return Err(Rejection::Fatal(
                        anyhow::Error::new(e).context("read request headers"),
                    ))
                }
            };
            buf.extend_from_slice(&chunk[..n]);
        };

        // 先判超限再解析：超限的头部本来就不该被信任。
        if head_end > MAX_HEAD_BYTES {
            return Err(Rejection::HeadTooLarge);
        }

        let leftover = buf[head_end..].to_vec();
        let head_text = std::str::from_utf8(&buf[..head_end])
            .map_err(|_| Rejection::BadRequest("request headers are not valid UTF-8"))?;

        let mut lines = head_text.split("\r\n");
        let request_line = lines
            .next()
            .ok_or(Rejection::BadRequest("missing request line"))?;
        let target = parse_request_line(request_line)?;

        let mut proxy_auth = None;
        for line in lines {
            if line.is_empty() {
                break;
            }
            let Some((name, value)) = line.split_once(':') else {
                return Err(Rejection::BadRequest("malformed header line"));
            };
            // 头名大小写不敏感（RFC 9110），照抄客户端的写法比较是常见 bug。
            if name.trim().eq_ignore_ascii_case("proxy-authorization") {
                proxy_auth = Some(value.trim().to_string());
            }
        }

        Ok(Head {
            target,
            proxy_auth,
            leftover,
        })
    }

    /// 校验 `Proxy-Authorization: Basic <base64>`。
    fn authorize(&self, header: Option<&str>) -> Result<(), Rejection> {
        let Some((user, pass)) = self.credentials.as_ref() else {
            return Ok(());
        };
        // 未提供与提供错误都回同一个 407 挑战：区分二者会白送一个"用户名是否存在"的信号。
        let Some(raw) = header else {
            return Err(Rejection::AuthRequired);
        };
        let Some((scheme, payload)) = raw.split_once(' ') else {
            return Err(Rejection::AuthRequired);
        };
        if !scheme.eq_ignore_ascii_case("basic") {
            return Err(Rejection::AuthRequired);
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(payload.trim())
            .map_err(|_| Rejection::AuthRequired)?;
        // 密码里允许出现 ':'，所以只在第一个冒号处切分。
        let Some(sep) = decoded.iter().position(|b| *b == b':') else {
            return Err(Rejection::AuthRequired);
        };
        let ok =
            ct_eq(&decoded[..sep], user.as_bytes()) & ct_eq(&decoded[sep + 1..], pass.as_bytes());
        if ok {
            Ok(())
        } else {
            Err(Rejection::AuthRequired)
        }
    }
}

/// 便利入口：无认证的默认配置。
pub async fn serve_conn<S, D>(stream: S, dialer: Arc<D>) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    D: Dialer + ?Sized,
{
    HttpConnectServer::new(None)
        .serve_conn(stream, dialer)
        .await
}

/// 需要回给客户端的拒绝。
///
/// 把"状态码"与"是否算错误"绑在一个类型上，避免每个分支各自手写响应字符串——
/// 那样很容易漏掉 `Connection: close` 或 `Content-Length` 而让客户端挂住。
enum Rejection {
    AuthRequired,
    HeadTooLarge,
    BadRequest(&'static str),
    MethodNotAllowed(String),
    Forbidden,
    GatewayTimeout,
    BadGateway(DialError),
    /// 连响应都发不出去的底层故障。
    Fatal(anyhow::Error),
}

impl Rejection {
    fn from_dial(e: DialError) -> Self {
        match e {
            DialError::Forbidden => Self::Forbidden,
            DialError::TimedOut => Self::GatewayTimeout,
            other => Self::BadGateway(other),
        }
    }

    /// 写出响应并决定这条连接算成功收场还是错误。
    async fn emit<S>(self, stream: &mut S) -> anyhow::Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        let (status, extra, body, fatal): (&str, &str, String, Option<String>) = match self {
            Self::Fatal(e) => return Err(e),
            Self::AuthRequired => (
                "407 Proxy Authentication Required",
                "Proxy-Authenticate: Basic realm=\"srp\"\r\n",
                "proxy authentication required\n".to_string(),
                None,
            ),
            Self::HeadTooLarge => (
                "431 Request Header Fields Too Large",
                "",
                format!("request headers exceed {MAX_HEAD_BYTES} bytes\n"),
                Some(format!(
                    "request headers exceed the {MAX_HEAD_BYTES} byte limit"
                )),
            ),
            Self::BadRequest(why) => (
                "400 Bad Request",
                "",
                format!("{why}\n"),
                Some(format!("malformed CONNECT request: {why}")),
            ),
            Self::MethodNotAllowed(method) => (
                "405 Method Not Allowed",
                "Allow: CONNECT\r\n",
                "this proxy only supports CONNECT tunnels\n".to_string(),
                Some(format!(
                    "this proxy only supports CONNECT tunnels, got method {method}"
                )),
            ),
            Self::Forbidden => (
                "403 Forbidden",
                "",
                "rejected by proxy policy\n".to_string(),
                None,
            ),
            Self::GatewayTimeout => (
                "504 Gateway Timeout",
                "",
                "upstream connection timed out\n".to_string(),
                None,
            ),
            Self::BadGateway(e) => (
                "502 Bad Gateway",
                "",
                format!("upstream connection failed: {e}\n"),
                None,
            ),
        };

        // 一次拼好再写：分多次 write 会把一个小响应拆成好几个包，也更容易漏字段。
        let resp = format!(
            "HTTP/1.1 {status}\r\n{extra}Content-Type: text/plain; charset=utf-8\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
            len = body.len(),
        );
        stream
            .write_all(resp.as_bytes())
            .await
            .context("write error response")?;
        stream.flush().await.context("flush error response")?;

        match fatal {
            // 协议误用值得让调用方看到原因，但客户端已经收到了规范的响应。
            Some(msg) => Err(anyhow::anyhow!(msg)),
            None => Ok(()),
        }
    }
}

fn find_crlf_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// 解析 `CONNECT host:port HTTP/1.1`。
fn parse_request_line(line: &str) -> Result<TargetAddr, Rejection> {
    let mut parts = line.split(' ').filter(|p| !p.is_empty());
    let method = parts
        .next()
        .ok_or(Rejection::BadRequest("empty request line"))?;
    let authority = parts
        .next()
        .ok_or(Rejection::BadRequest("missing request target"))?;
    let version = parts
        .next()
        .ok_or(Rejection::BadRequest("missing HTTP version"))?;

    // 方法判定放在认证之前：非 CONNECT 请求无论凭据对不对都服务不了，
    // 回 407 只会诱导客户端做一次没有意义的重试。
    if method != "CONNECT" {
        return Err(Rejection::MethodNotAllowed(method.to_string()));
    }
    if !matches!(version, "HTTP/1.1" | "HTTP/1.0") {
        return Err(Rejection::BadRequest("unsupported HTTP version"));
    }

    parse_authority(authority)
}

/// 解析 authority-form 目标（`host:port` / `[v6]:port`）。
fn parse_authority(s: &str) -> Result<TargetAddr, Rejection> {
    let (host, port_str) = if let Some(rest) = s.strip_prefix('[') {
        // IPv6 字面量里全是冒号，只能靠 ']' 定界，不能用 rsplit_once(':')。
        let (inside, tail) = rest
            .split_once(']')
            .ok_or(Rejection::BadRequest("unterminated IPv6 literal in target"))?;
        let port = tail
            .strip_prefix(':')
            .ok_or(Rejection::BadRequest("CONNECT target must include a port"))?;
        (inside, port)
    } else {
        s.rsplit_once(':')
            .ok_or(Rejection::BadRequest("CONNECT target must include a port"))?
    };

    let port: u16 = port_str
        .parse()
        .map_err(|_| Rejection::BadRequest("invalid port in CONNECT target"))?;
    // 端口 0 无法真正连接，早拒比让上游报一个含义模糊的错误更清晰。
    if port == 0 {
        return Err(Rejection::BadRequest("port 0 is not connectable"));
    }

    // IP 字面量直接归一成 V4/V6，这样上游不必再为一个本就是 IP 的"域名"跑 DNS。
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return Ok(TargetAddr::V4(v4.octets(), port));
    }
    if let Ok(v6) = host.parse::<Ipv6Addr>() {
        return Ok(TargetAddr::V6(v6.octets(), port));
    }
    // 方括号形式只可能是 IP 字面量，落到这里说明里面的内容是坏的。
    if s.starts_with('[') {
        return Err(Rejection::BadRequest("invalid IPv6 literal in target"));
    }
    validate_domain(host).map_err(|_| Rejection::BadRequest("invalid host name in target"))?;
    Ok(TargetAddr::Domain(host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::test_support::{read_http_head, MockDialer};
    use tokio::io::duplex;

    fn basic(user: &str, pass: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
    }

    #[tokio::test]
    async fn connect_succeeds_and_relays_both_directions() {
        let (dialer, mut peer) = MockDialer::success();
        let (mut client, server) = duplex(4096);
        let d = dialer.clone();
        let task = tokio::spawn(async move { serve_conn(server, d).await });

        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();

        let head = read_http_head(&mut client).await;
        assert_eq!(head, "HTTP/1.1 200 Connection established\r\n\r\n");
        assert_eq!(
            dialer.dialed(),
            vec![TargetAddr::Domain("example.com".into(), 443)]
        );

        client.write_all(b"hello").await.unwrap();
        let mut up = [0u8; 5];
        peer.read_exact(&mut up).await.unwrap();
        assert_eq!(&up, b"hello");

        peer.write_all(b"world").await.unwrap();
        let mut down = [0u8; 5];
        client.read_exact(&mut down).await.unwrap();
        assert_eq!(&down, b"world");

        drop(client);
        drop(peer);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn early_payload_after_headers_reaches_upstream() {
        let (dialer, mut peer) = MockDialer::success();
        let (mut client, server) = duplex(4096);
        let task = tokio::spawn(async move { serve_conn(server, dialer).await });

        // 抢跑：请求头与载荷粘在一次写里。
        client
            .write_all(b"CONNECT h.test:443 HTTP/1.1\r\n\r\nCLIENTHELLO")
            .await
            .unwrap();

        let head = read_http_head(&mut client).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");

        let mut up = [0u8; 11];
        peer.read_exact(&mut up).await.unwrap();
        assert_eq!(&up, b"CLIENTHELLO");
        // 两端都关，copy_bidirectional 才会收工。

        drop(client);
        drop(peer);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn basic_auth_success_and_407_on_failure() {
        let creds = || Some(("neko".to_string(), "s3cret".to_string()));

        // 正确凭据。
        let (dialer, peer) = MockDialer::success();
        let (mut client, server) = duplex(4096);
        let srv = HttpConnectServer::new(creds());
        let task = tokio::spawn(async move { srv.serve_conn(server, dialer).await });
        client
            .write_all(
                format!(
                    "CONNECT a.test:443 HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n",
                    basic("neko", "s3cret")
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        assert!(read_http_head(&mut client)
            .await
            .starts_with("HTTP/1.1 200"));
        drop(client);
        drop(peer);
        task.await.unwrap().unwrap();

        // 错误密码、以及完全不带头，都必须得到同一个 407 挑战。
        for auth_header in [
            format!("Proxy-Authorization: Basic {}\r\n", basic("neko", "wrong")),
            String::new(),
        ] {
            let dialer = MockDialer::failing(DialError::Internal);
            let (mut client, server) = duplex(4096);
            let srv = HttpConnectServer::new(creds());
            let d = dialer.clone();
            let task = tokio::spawn(async move { srv.serve_conn(server, d).await });

            client
                .write_all(format!("CONNECT a.test:443 HTTP/1.1\r\n{auth_header}\r\n").as_bytes())
                .await
                .unwrap();

            let head = read_http_head(&mut client).await;
            assert!(head.starts_with("HTTP/1.1 407"), "{head}");
            assert!(
                head.contains("Proxy-Authenticate: Basic realm=\"srp\""),
                "missing challenge header: {head}"
            );
            drop(client);
            task.await.unwrap().unwrap();
            assert!(dialer.dialed().is_empty(), "must not dial before auth");
        }
    }

    #[tokio::test]
    async fn parses_ipv6_literal_target() {
        let (dialer, peer) = MockDialer::success();
        let (mut client, server) = duplex(4096);
        let d = dialer.clone();
        let task = tokio::spawn(async move { serve_conn(server, d).await });

        client
            .write_all(b"CONNECT [::1]:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        assert!(read_http_head(&mut client)
            .await
            .starts_with("HTTP/1.1 200"));
        drop(client);
        drop(peer);
        task.await.unwrap().unwrap();

        let mut octets = [0u8; 16];
        octets[15] = 1;
        assert_eq!(dialer.dialed(), vec![TargetAddr::V6(octets, 443)]);
    }

    #[tokio::test]
    async fn parses_ipv4_literal_target() {
        let (dialer, peer) = MockDialer::success();
        let (mut client, server) = duplex(4096);
        let d = dialer.clone();
        let task = tokio::spawn(async move { serve_conn(server, d).await });

        client
            .write_all(b"CONNECT 10.0.0.7:8443 HTTP/1.0\r\n\r\n")
            .await
            .unwrap();
        assert!(read_http_head(&mut client)
            .await
            .starts_with("HTTP/1.1 200"));
        drop(client);
        drop(peer);
        task.await.unwrap().unwrap();
        assert_eq!(dialer.dialed(), vec![TargetAddr::V4([10, 0, 0, 7], 8443)]);
    }

    #[tokio::test]
    async fn oversized_headers_return_431() {
        let dialer = MockDialer::failing(DialError::Internal);
        // duplex 缓冲要大于我们写入的量，否则测试自己会阻塞在 write 上。
        let (mut client, server) = duplex(256 * 1024);
        let d = dialer.clone();
        let task = tokio::spawn(async move { serve_conn(server, d).await });

        let mut req = b"CONNECT a.test:443 HTTP/1.1\r\n".to_vec();
        // 故意不发结尾空行：模拟"只灌头不收尾"的内存耗尽尝试。
        for i in 0..600 {
            req.extend_from_slice(format!("X-Pad-{i}: {}\r\n", "a".repeat(40)).as_bytes());
        }
        assert!(req.len() > MAX_HEAD_BYTES);
        // 服务端可能已经回完 431 并关闭，这一侧的写失败是预期的。
        let _ = client.write_all(&req).await;

        let head = read_http_head(&mut client).await;
        assert!(head.starts_with("HTTP/1.1 431"), "{head}");
        let err = task.await.unwrap().expect_err("oversized head is misuse");
        assert!(err.to_string().contains("byte limit"), "{err:#}");
        assert!(dialer.dialed().is_empty());
    }

    #[tokio::test]
    async fn non_connect_method_returns_405() {
        let dialer = MockDialer::failing(DialError::Internal);
        let (mut client, server) = duplex(4096);
        let d = dialer.clone();
        let task = tokio::spawn(async move { serve_conn(server, d).await });

        client
            .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();

        let head = read_http_head(&mut client).await;
        assert!(head.starts_with("HTTP/1.1 405"), "{head}");
        assert!(head.contains("Allow: CONNECT"), "{head}");

        let err = task.await.unwrap().expect_err("non-CONNECT is misuse");
        assert!(
            err.to_string().contains("only supports CONNECT tunnels"),
            "{err:#}"
        );
        assert!(dialer.dialed().is_empty());
    }

    #[tokio::test]
    async fn missing_port_returns_400() {
        let dialer = MockDialer::failing(DialError::Internal);
        let (mut client, server) = duplex(4096);
        let d = dialer.clone();
        let task = tokio::spawn(async move { serve_conn(server, d).await });

        client
            .write_all(b"CONNECT example.com HTTP/1.1\r\n\r\n")
            .await
            .unwrap();

        let head = read_http_head(&mut client).await;
        assert!(head.starts_with("HTTP/1.1 400"), "{head}");
        let err = task.await.unwrap().expect_err("missing port is misuse");
        assert!(err.to_string().contains("must include a port"), "{err:#}");
        assert!(dialer.dialed().is_empty());
    }

    #[tokio::test]
    async fn dial_failures_map_to_status_codes() {
        let cases = [
            (DialError::Forbidden, "HTTP/1.1 403"),
            (DialError::TimedOut, "HTTP/1.1 504"),
            (DialError::ConnectionRefused, "HTTP/1.1 502"),
            (DialError::HostUnreachable, "HTTP/1.1 502"),
            (DialError::NetworkUnreachable, "HTTP/1.1 502"),
            (DialError::Internal, "HTTP/1.1 502"),
        ];

        for (err, want) in cases {
            let dialer = MockDialer::failing(err);
            let (mut client, server) = duplex(4096);
            let task = tokio::spawn(async move { serve_conn(server, dialer).await });

            client
                .write_all(b"CONNECT down.test:443 HTTP/1.1\r\n\r\n")
                .await
                .unwrap();
            let head = read_http_head(&mut client).await;
            assert!(head.starts_with(want), "{err:?} -> {head}");
            drop(client);
            // dial 失败已经如实告知客户端，不该再冒泡成错误。
            task.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn header_terminator_split_across_reads_is_detected() {
        let (dialer, peer) = MockDialer::success();
        let (mut client, server) = duplex(4096);
        let task = tokio::spawn(async move { serve_conn(server, dialer).await });

        // 把 "\r\n\r\n" 切成两半分别发送，验证跨 read 回扫是有效的。
        client
            .write_all(b"CONNECT s.test:443 HTTP/1.1\r\n\r")
            .await
            .unwrap();
        client.flush().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        client.write_all(b"\n").await.unwrap();

        let head = read_http_head(&mut client).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        drop(client);
        drop(peer);
        task.await.unwrap().unwrap();
    }

    #[test]
    fn authority_parser_rejects_broken_ipv6_forms() {
        assert!(parse_authority("[::1:443").is_err());
        assert!(parse_authority("[::1]").is_err());
        assert!(parse_authority("[not-an-ip]:443").is_err());
        assert!(parse_authority("host:0").is_err());
        assert!(parse_authority("host:abc").is_err());
    }
}
