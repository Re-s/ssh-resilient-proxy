//! 目标地址表示。与 SOCKS5 的地址类型保持同构，便于零成本转换。

use bytes::{Buf, BufMut, BytesMut};

use crate::ProtoError;

/// 代理请求的目标地址。
///
/// 域名保持原样透传（不在本地解析），这样 DNS 解析发生在远端出口，
/// 避免本地 DNS 污染，也让断线重连后的重放保持幂等。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetAddr {
    V4([u8; 4], u16),
    V6([u8; 16], u16),
    Domain(String, u16),
}

impl TargetAddr {
    pub const KIND_V4: u8 = 1;
    pub const KIND_DOMAIN: u8 = 3;
    pub const KIND_V6: u8 = 4;

    pub fn port(&self) -> u16 {
        match self {
            Self::V4(_, p) | Self::V6(_, p) => *p,
            Self::Domain(_, p) => *p,
        }
    }

    /// 用于 `channel_open_direct_tcpip` 的主机字符串。
    pub fn host_string(&self) -> String {
        match self {
            Self::V4(o, _) => std::net::Ipv4Addr::from(*o).to_string(),
            Self::V6(o, _) => std::net::Ipv6Addr::from(*o).to_string(),
            Self::Domain(d, _) => d.clone(),
        }
    }

    /// 编码后占用的字节数。
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::V4(..) => 1 + 4 + 2,
            Self::V6(..) => 1 + 16 + 2,
            Self::Domain(d, _) => 1 + 1 + d.len() + 2,
        }
    }

    pub fn encode(&self, dst: &mut BytesMut) {
        match self {
            Self::V4(o, p) => {
                dst.put_u8(Self::KIND_V4);
                dst.put_slice(o);
                dst.put_u16(*p);
            }
            Self::V6(o, p) => {
                dst.put_u8(Self::KIND_V6);
                dst.put_slice(o);
                dst.put_u16(*p);
            }
            Self::Domain(d, p) => {
                dst.put_u8(Self::KIND_DOMAIN);
                dst.put_u8(d.len() as u8);
                dst.put_slice(d.as_bytes());
                dst.put_u16(*p);
            }
        }
    }

    /// 从缓冲区解析。调用方保证 `src` 是一个完整帧的载荷切片。
    pub fn decode(src: &mut impl Buf) -> Result<Self, ProtoError> {
        if src.remaining() < 1 {
            return Err(ProtoError::Truncated);
        }
        let kind = src.get_u8();
        match kind {
            Self::KIND_V4 => {
                if src.remaining() < 6 {
                    return Err(ProtoError::Truncated);
                }
                let mut o = [0u8; 4];
                src.copy_to_slice(&mut o);
                Ok(Self::V4(o, src.get_u16()))
            }
            Self::KIND_V6 => {
                if src.remaining() < 18 {
                    return Err(ProtoError::Truncated);
                }
                let mut o = [0u8; 16];
                src.copy_to_slice(&mut o);
                Ok(Self::V6(o, src.get_u16()))
            }
            Self::KIND_DOMAIN => {
                if src.remaining() < 1 {
                    return Err(ProtoError::Truncated);
                }
                let len = src.get_u8() as usize;
                if src.remaining() < len + 2 {
                    return Err(ProtoError::Truncated);
                }
                let mut buf = vec![0u8; len];
                src.copy_to_slice(&mut buf);
                let domain = String::from_utf8(buf).map_err(|_| ProtoError::BadDomain)?;
                if domain.is_empty() {
                    return Err(ProtoError::BadDomain);
                }
                Ok(Self::Domain(domain, src.get_u16()))
            }
            other => Err(ProtoError::BadAddrKind(other)),
        }
    }
}

impl std::fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V4(o, p) => write!(f, "{}:{}", std::net::Ipv4Addr::from(*o), p),
            Self::V6(o, p) => write!(f, "[{}]:{}", std::net::Ipv6Addr::from(*o), p),
            Self::Domain(d, p) => write!(f, "{d}:{p}"),
        }
    }
}

impl From<std::net::SocketAddr> for TargetAddr {
    fn from(v: std::net::SocketAddr) -> Self {
        match v {
            std::net::SocketAddr::V4(a) => Self::V4(a.ip().octets(), a.port()),
            std::net::SocketAddr::V6(a) => Self::V6(a.ip().octets(), a.port()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(a: TargetAddr) {
        let mut buf = BytesMut::new();
        a.encode(&mut buf);
        assert_eq!(buf.len(), a.encoded_len(), "encoded_len mismatch for {a:?}");
        let mut cursor = buf.clone();
        let out = TargetAddr::decode(&mut cursor).expect("decode");
        assert_eq!(out, a);
        assert_eq!(cursor.remaining(), 0, "leftover bytes");
    }

    #[test]
    fn roundtrips_all_kinds() {
        roundtrip(TargetAddr::V4([127, 0, 0, 1], 8080));
        roundtrip(TargetAddr::V6([0u8; 16], 443));
        roundtrip(TargetAddr::Domain("example.com".into(), 80));
    }

    #[test]
    fn rejects_truncated_and_bad_kind() {
        let mut b = BytesMut::from(&[TargetAddr::KIND_V4, 1, 2][..]);
        assert!(matches!(
            TargetAddr::decode(&mut b),
            Err(ProtoError::Truncated)
        ));

        let mut b = BytesMut::from(&[9u8, 0, 0][..]);
        assert!(matches!(
            TargetAddr::decode(&mut b),
            Err(ProtoError::BadAddrKind(9))
        ));
    }

    #[test]
    fn rejects_non_utf8_domain() {
        let mut buf = BytesMut::new();
        buf.put_u8(TargetAddr::KIND_DOMAIN);
        buf.put_u8(2);
        buf.put_slice(&[0xff, 0xfe]);
        buf.put_u16(80);
        assert!(matches!(
            TargetAddr::decode(&mut buf),
            Err(ProtoError::BadDomain)
        ));
    }

    #[test]
    fn host_string_matches_display_for_domain() {
        let a = TargetAddr::Domain("srv.internal".into(), 22);
        assert_eq!(a.host_string(), "srv.internal");
        assert_eq!(a.to_string(), "srv.internal:22");
        assert_eq!(a.port(), 22);
    }
}
