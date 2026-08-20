//! 入口（frontend）协议层：SOCKS5 与 HTTP CONNECT。
//!
//! 这一层刻意只认识"入口协议"，完全不认识"隧道怎么建"。它把"给我一条到
//! `addr` 的连接"收敛成 [`Dialer`] 这一个抽象，于是同一份握手代码可以跑在
//! SSH 隧道、本地直连、甚至纯内存流之上——单元测试不需要真实 socket，就是
//! 这个解耦换来的直接好处。反过来说，隧道侧的重连/续传逻辑也不必知道客户端
//! 用的是 SOCKS5 还是 HTTP。

// lib 目标里这些条目是 pub API，不会告警；但同一份源码还被 bin 目标（main.rs）
// 编译一次，而那里 `pub` 不抑制 dead_code——main 尚未接线，于是每个条目都会报一遍。
// 在模块级别允许一次，避免这批虚假告警淹没真实警告。main 接线完成后可删掉。
#![allow(dead_code)]

use std::io;

use async_trait::async_trait;
use srp_proto::TargetAddr;
use tokio::io::{AsyncRead, AsyncWrite};

pub mod http;
pub mod socks5;

/// 上游连接失败的原因，用于映射到入口协议的错误码。
///
/// 这里刻意不携带 `io::Error`：入口协议只需要一个可枚举的类别去填 SOCKS5 的
/// REP 字节或 HTTP 状态码，携带源错误只会让 frontend 有机会泄漏内部细节给客户端。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialError {
    /// 目标主机不可达 / DNS 失败
    HostUnreachable,
    /// 目标拒绝连接
    ConnectionRefused,
    /// 网络不可达（隧道整体不可用）
    NetworkUnreachable,
    /// 超时
    TimedOut,
    /// 策略拒绝
    Forbidden,
    /// 其他内部错误
    Internal,
}

impl DialError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HostUnreachable => "host unreachable",
            Self::ConnectionRefused => "connection refused",
            Self::NetworkUnreachable => "network unreachable",
            Self::TimedOut => "timed out",
            Self::Forbidden => "forbidden by policy",
            Self::Internal => "internal error",
        }
    }

    /// 由本地 `io::Error` 推断原因。
    ///
    /// 直连 Dialer 和远端 helper 都要做这个映射，放在类型自己身上可以保证两边
    /// 对同一个 errno 给出同一个入口错误码，避免"同样的失败在 SOCKS5 和 HTTP
    /// 下表现不一致"这类难查的问题。
    pub fn from_io(err: &io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            io::ErrorKind::TimedOut => Self::TimedOut,
            io::ErrorKind::HostUnreachable => Self::HostUnreachable,
            io::ErrorKind::NetworkUnreachable | io::ErrorKind::NetworkDown => {
                Self::NetworkUnreachable
            }
            io::ErrorKind::PermissionDenied => Self::Forbidden,
            _ => Self::Internal,
        }
    }
}

impl std::fmt::Display for DialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 一条已建立的上游双向流。
pub trait UpstreamStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> UpstreamStream for T {}

/// `Dialer` 返回的装箱流。
///
/// 用 `Box<dyn ...>` 而不是关联类型，是为了让 [`Dialer`] 保持 dyn 兼容：
/// 运行时要根据配置在"SSH 隧道 / 直连 / 拒绝一切"之间切换实现，
/// 关联类型会把这个选择推到编译期，逼着调用方到处传泛型参数。
/// 一次装箱只发生在每条连接建立时，代价可以忽略。
pub type BoxedStream = Box<dyn UpstreamStream>;

/// 隧道抽象：frontend 通过它请求一条到 `addr` 的上游连接。
#[async_trait]
pub trait Dialer: Send + Sync + 'static {
    async fn dial(&self, addr: &TargetAddr) -> Result<BoxedStream, DialError>;
}

/// 域名合法性检查。
///
/// 两个入口都必须过这一关：`TargetAddr::Domain` 在线协议里用 1 字节长度前缀编码，
/// 超过 255 字节会被静默截断成"另一个主机名"——请求被悄悄改写比直接失败危险得多，
/// 所以必须在入口拒绝。顺带挡掉控制字符与空格，避免把畸形主机名透传给远端出口的解析器。
pub(crate) fn validate_domain(host: &str) -> Result<(), &'static str> {
    if host.is_empty() {
        return Err("empty host name");
    }
    if host.len() > 255 {
        return Err("host name longer than 255 bytes");
    }
    if host.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err("host name contains control characters");
    }
    Ok(())
}

/// 双向转发，直到任意一侧读到 EOF。
///
/// 抽出来共用，是为了让 SOCKS5 与 HTTP 两个入口在"连接怎么收尾"上不可能出现分叉。
pub(crate) async fn relay<A, B>(mut a: A, mut b: B) -> anyhow::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::io::copy_bidirectional(&mut a, &mut b).await {
        Ok(v) => Ok(v),
        // 对端直接掀桌子（RST、或半关闭后继续写）在代理场景里是常态而非故障。
        // 若把它当错误上报，日志会被这类噪声刷满，真正的问题反而被埋掉。
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::NotConnected
            ) =>
        {
            Ok((0, 0))
        }
        Err(e) => Err(anyhow::Error::new(e).context("bidirectional relay failed")),
    }
}

/// 常量时间比较。
///
/// 凭据校验一旦提前 return，就会把"前缀匹配到第几个字节"变成可测量的时间差；
/// 代理常暴露在本机之外，这个便宜的防护值得默认打开。
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
pub(crate) mod test_support {
    //! 测试用的假 Dialer：socks5 与 http 两组测试共用，避免各写一份而出现
    //! "两边对 Dialer 的期望悄悄分叉"的情况。

    use std::sync::Mutex;

    use super::{BoxedStream, DialError, Dialer};
    use async_trait::async_trait;
    use srp_proto::TargetAddr;
    use tokio::io::{duplex, AsyncRead, AsyncReadExt as _, DuplexStream};

    pub struct MockDialer {
        /// 只允许被取用一次：多余的 dial 直接失败，这样"意外重复 dial"会在测试里暴露。
        outcome: Mutex<Option<Result<DuplexStream, DialError>>>,
        dialed: Mutex<Vec<TargetAddr>>,
    }

    impl MockDialer {
        /// 返回 (dialer, 上游的另一端)。测试用后者观察/注入字节。
        pub fn success() -> (std::sync::Arc<Self>, DuplexStream) {
            let (upstream, peer) = duplex(64 * 1024);
            let d = std::sync::Arc::new(Self {
                outcome: Mutex::new(Some(Ok(upstream))),
                dialed: Mutex::new(Vec::new()),
            });
            (d, peer)
        }

        pub fn failing(err: DialError) -> std::sync::Arc<Self> {
            std::sync::Arc::new(Self {
                outcome: Mutex::new(Some(Err(err))),
                dialed: Mutex::new(Vec::new()),
            })
        }

        pub fn dialed(&self) -> Vec<TargetAddr> {
            self.dialed.lock().expect("dialed lock").clone()
        }
    }

    #[async_trait]
    impl Dialer for MockDialer {
        async fn dial(&self, addr: &TargetAddr) -> Result<BoxedStream, DialError> {
            self.dialed.lock().expect("dialed lock").push(addr.clone());
            // 先把守卫释放再返回，避免把 MutexGuard 带进 await 点。
            let outcome = self.outcome.lock().expect("outcome lock").take();
            match outcome {
                Some(Ok(s)) => Ok(Box::new(s)),
                Some(Err(e)) => Err(e),
                None => Err(DialError::Internal),
            }
        }
    }

    /// 读取一段以 CRLFCRLF 结尾的 HTTP 头（或读到 EOF 为止）。
    /// 逐字节读是为了不越过头部边界，把隧道里的数据也吞掉。
    pub async fn read_http_head<S: AsyncRead + Unpin>(s: &mut S) -> String {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match s.read(&mut byte).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    buf.push(byte[0]);
                    if buf.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
            }
        }
        String::from_utf8(buf).expect("http head is utf-8")
    }
}
