//! 出口目标允许列表。
//!
//! helper 跑在远端，等于把"任意 TCP 出站"的能力交给了客户端，所以必须能被
//! 收紧到一组显式目标。规则语法刻意保持最小：
//!
//! * `host:port` —— 精确主机 + 精确端口
//! * `host`      —— 精确主机 + 任意端口
//! * `*:port`    —— 任意主机 + 精确端口
//! * host 允许前导 `*.`，通配子域名（`*.example.com` 匹配 `a.example.com`，
//!   但不匹配 apex `example.com`，与 TLS 通配证书语义一致）
//! * `[::1]:443` / `::1` —— IPv6 字面量（带端口时必须加方括号）
//!
//! 匹配对 host 大小写不敏感，并忽略域名末尾的根点（`example.com.`）。

use std::net::IpAddr;

use anyhow::{bail, Context, Result};
use srp_proto::TargetAddr;

/// 规则中的主机部分。
#[derive(Debug, Clone, PartialEq, Eq)]
enum HostRule {
    /// `*`：任意主机。
    Any,
    /// 精确域名（已归一化为小写、无尾点）。
    Exact(String),
    /// `*.parent`：parent 的子域名（不含 parent 本身）。
    Suffix(String),
    /// IP 字面量。按数值比较，避免 `::1` 与 `0:0:0:0:0:0:0:1` 之类的写法差异。
    Ip(IpAddr),
}

/// 单条允许规则。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowRule {
    host: HostRule,
    /// `None` 表示任意端口。
    port: Option<u16>,
}

impl AllowRule {
    fn matches(&self, addr: &TargetAddr) -> bool {
        if let Some(p) = self.port {
            if p != addr.port() {
                return false;
            }
        }
        match &self.host {
            HostRule::Any => true,
            HostRule::Ip(want) => target_ip(addr).is_some_and(|ip| ip == *want),
            HostRule::Exact(want) => host_key(addr) == *want,
            HostRule::Suffix(parent) => {
                let key = host_key(addr);
                // 必须是真子域：`a.example.com` 命中，`example.com` 与
                // `notexample.com` 都不命中。
                key.len() > parent.len() + 1
                    && key.ends_with(parent.as_str())
                    && key.as_bytes()[key.len() - parent.len() - 1] == b'.'
            }
        }
    }
}

/// 允许列表。空列表 = 允许所有目标（由调用方负责在 stderr 告警）。
#[derive(Debug, Clone, Default)]
pub struct AllowList {
    rules: Vec<AllowRule>,
}

impl AllowList {
    /// 解析命令行给出的模式串。任何一条非法都直接失败，不做静默忽略——
    /// 静默忽略一条 allow 规则等于悄悄放宽安全策略。
    pub fn parse<S: AsRef<str>>(patterns: &[S]) -> Result<Self> {
        let mut rules = Vec::with_capacity(patterns.len());
        for p in patterns {
            rules.push(parse_rule(p.as_ref())?);
        }
        Ok(Self { rules })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// 是否放行该目标。
    pub fn permits(&self, addr: &TargetAddr) -> bool {
        if self.rules.is_empty() {
            return true;
        }
        self.rules.iter().any(|r| r.matches(addr))
    }
}

fn parse_rule(pattern: &str) -> Result<AllowRule> {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        bail!("empty allow pattern");
    }
    let (host, port) = split_host_port(pattern)?;
    if host.is_empty() {
        bail!("allow pattern {pattern:?} has an empty host");
    }
    let host = if host == "*" {
        HostRule::Any
    } else if let Some(parent) = host.strip_prefix("*.") {
        let parent = normalize_host(parent);
        if parent.is_empty() || parent.contains('*') {
            bail!("allow pattern {pattern:?} has an invalid wildcard host");
        }
        HostRule::Suffix(parent)
    } else if let Ok(ip) = host.parse::<IpAddr>() {
        HostRule::Ip(ip)
    } else {
        let host = normalize_host(host);
        if host.contains('*') {
            bail!("allow pattern {pattern:?}: `*` is only allowed as `*` or a leading `*.`");
        }
        HostRule::Exact(host)
    };
    Ok(AllowRule { host, port })
}

/// 拆出 host 与可选 port。
///
/// 不能简单地按第一个 `:` 切分：裸 IPv6 字面量里全是冒号。规则是——
/// 方括号形式显式给出 host；否则只有"最后一段是数字端口且剩下的部分不含冒号"
/// 时才认定带端口，其余情况整串都当 host。
fn split_host_port(pattern: &str) -> Result<(&str, Option<u16>)> {
    if let Some(rest) = pattern.strip_prefix('[') {
        let end = rest
            .find(']')
            .with_context(|| format!("allow pattern {pattern:?} misses a closing `]`"))?;
        let host = &rest[..end];
        let tail = &rest[end + 1..];
        if tail.is_empty() {
            return Ok((host, None));
        }
        let port = tail
            .strip_prefix(':')
            .with_context(|| format!("allow pattern {pattern:?} has trailing junk after `]`"))?;
        let port: u16 = port
            .parse()
            .with_context(|| format!("allow pattern {pattern:?} has an invalid port"))?;
        return Ok((host, Some(port)));
    }
    if let Some((host, port)) = pattern.rsplit_once(':') {
        if !host.contains(':') {
            let port: u16 = port
                .parse()
                .with_context(|| format!("allow pattern {pattern:?} has an invalid port"))?;
            return Ok((host, Some(port)));
        }
    }
    Ok((pattern, None))
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// 目标的可比较主机名（小写、无尾点）。
fn host_key(addr: &TargetAddr) -> String {
    match addr {
        TargetAddr::Domain(d, _) => normalize_host(d),
        other => other.host_string(),
    }
}

/// 目标的数值 IP（域名形式的 IP 字面量也算）。
fn target_ip(addr: &TargetAddr) -> Option<IpAddr> {
    match addr {
        TargetAddr::V4(o, _) => Some(IpAddr::from(*o)),
        TargetAddr::V6(o, _) => Some(IpAddr::from(*o)),
        TargetAddr::Domain(d, _) => d.parse::<IpAddr>().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dom(host: &str, port: u16) -> TargetAddr {
        TargetAddr::Domain(host.to_string(), port)
    }

    #[test]
    fn empty_list_permits_everything() {
        let list = AllowList::default();
        assert!(list.is_empty());
        assert!(list.permits(&dom("anything.example", 1)));
        assert!(list.permits(&TargetAddr::V4([8, 8, 8, 8], 53)));
    }

    #[test]
    fn host_port_rule_is_exact() {
        let list = AllowList::parse(&["example.com:443"]).unwrap();
        assert!(!list.is_empty());
        assert!(list.permits(&dom("example.com", 443)));
        assert!(
            list.permits(&dom("EXAMPLE.com.", 443)),
            "大小写与尾点应归一化"
        );
        assert!(!list.permits(&dom("example.com", 80)), "端口必须相等");
        assert!(!list.permits(&dom("evil.com", 443)));
    }

    #[test]
    fn bare_host_rule_allows_any_port() {
        let list = AllowList::parse(&["example.com"]).unwrap();
        assert!(list.permits(&dom("example.com", 1)));
        assert!(list.permits(&dom("example.com", 65535)));
        assert!(!list.permits(&dom("a.example.com", 1)));
    }

    #[test]
    fn star_port_rule_allows_any_host() {
        let list = AllowList::parse(&["*:22"]).unwrap();
        assert!(list.permits(&dom("whatever.internal", 22)));
        assert!(list.permits(&TargetAddr::V4([127, 0, 0, 1], 22)));
        assert!(!list.permits(&TargetAddr::V4([127, 0, 0, 1], 23)));
    }

    #[test]
    fn wildcard_matches_subdomains_only() {
        let list = AllowList::parse(&["*.example.com:443"]).unwrap();
        assert!(list.permits(&dom("a.example.com", 443)));
        assert!(list.permits(&dom("deep.nested.example.com", 443)));
        assert!(!list.permits(&dom("example.com", 443)), "apex 不算子域");
        assert!(
            !list.permits(&dom("notexample.com", 443)),
            "必须在点边界上匹配"
        );
        assert!(!list.permits(&dom("a.example.com", 80)));
    }

    #[test]
    fn ip_rules_compare_numerically() {
        let list = AllowList::parse(&["127.0.0.1:8080", "[::1]:9090", "10.0.0.7"]).unwrap();
        assert!(list.permits(&TargetAddr::V4([127, 0, 0, 1], 8080)));
        assert!(!list.permits(&TargetAddr::V4([127, 0, 0, 1], 8081)));
        assert!(
            list.permits(&dom("127.0.0.1", 8080)),
            "域名形式的 IP 字面量也应命中"
        );

        let mut v6 = [0u8; 16];
        v6[15] = 1;
        assert!(list.permits(&TargetAddr::V6(v6, 9090)));
        assert!(!list.permits(&TargetAddr::V6(v6, 9091)));

        assert!(
            list.permits(&TargetAddr::V4([10, 0, 0, 7], 12345)),
            "无端口规则放行任意端口"
        );
    }

    #[test]
    fn bare_ipv6_without_brackets_is_a_host() {
        let list = AllowList::parse(&["::1"]).unwrap();
        let mut v6 = [0u8; 16];
        v6[15] = 1;
        assert!(list.permits(&TargetAddr::V6(v6, 443)));
    }

    #[test]
    fn any_matching_rule_permits() {
        let list = AllowList::parse(&["a.internal:80", "b.internal:80"]).unwrap();
        assert!(list.permits(&dom("b.internal", 80)));
        assert!(!list.permits(&dom("c.internal", 80)));
    }

    #[test]
    fn rejects_malformed_patterns() {
        for bad in [
            "",
            "   ",
            "host:port",
            "host:99999",
            "[::1",
            "[::1]junk",
            ":443",
            "a*b.com",
        ] {
            assert!(
                AllowList::parse(&[bad]).is_err(),
                "pattern {bad:?} should be rejected"
            );
        }
    }
}
