//! 隧道配置与主机密钥校验策略。

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use super::backoff::BackoffPolicy;

/// 主机密钥校验策略。
///
/// 默认 `Strict`：未知主机直接拒绝。这一点没有妥协余地——代理会承载
/// 全部流量，接受未知主机密钥等于把中间人攻击的门敞开。
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKeyPolicy {
    /// 必须在 known_hosts 中且匹配，否则拒绝连接。
    #[default]
    Strict,
    /// 首次见到的主机自动写入 known_hosts；已记录的主机若不匹配则拒绝。
    /// 仅在首次连接可信网络时使用。
    AcceptNew,
    /// 只接受这个指纹（SHA256 base64，形如 `SHA256:xxxx` 或裸 base64）。
    /// 适合容器/CI 等无 known_hosts 文件的场景，比 AcceptNew 更安全。
    Pinned(String),
}

/// 认证方式。
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthMethod {
    /// 私钥认证。`passphrase` 为空表示未加密私钥。
    PublicKey {
        path: PathBuf,
        #[serde(default)]
        passphrase: Option<String>,
    },
    /// 密码认证。
    Password { password: String },
    /// 走 ssh-agent。
    Agent,
}

/// 隧道模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelMode {
    /// 纯客户端模式：每条代理连接对应一条 SSH `direct-tcpip` 通道。
    ///
    /// 零远端依赖，任何标准 sshd 都能用。代价是 SSH 断线时远端出口 TCP
    /// 必然被 sshd 关闭，已建立的长流无法字节级续传。
    #[default]
    DirectTcpip,
    /// helper 模式：在远端运行 `srp-helper`，通过自定义帧协议实现
    /// 字节级续传。需要远端账号能执行上传的二进制。
    Helper,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SshConfig {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub user: String,
    pub auth: AuthMethod,
    #[serde(default)]
    pub host_key: HostKeyPolicy,
    /// known_hosts 路径；None 表示用 `~/.ssh/known_hosts`。
    #[serde(default)]
    pub known_hosts: Option<PathBuf>,

    /// SSH 层保活探测间隔。这是"保持连接"的主力：NAT 与状态防火墙
    /// 会静默丢弃空闲连接，主动探测让我们**尽早**发现死链而不是等到
    /// 用户请求时才失败。
    #[serde(default = "default_keepalive", with = "humantime_serde")]
    pub keepalive_interval: Duration,
    /// 连续多少次保活无应答就判定连接已死。
    #[serde(default = "default_keepalive_max")]
    pub keepalive_max: usize,
    /// TCP 连接与认证的总超时。
    #[serde(default = "default_connect_timeout", with = "humantime_serde")]
    pub connect_timeout: Duration,
}

fn default_port() -> u16 {
    22
}
fn default_keepalive() -> Duration {
    Duration::from_secs(15)
}
fn default_keepalive_max() -> usize {
    3
}
fn default_connect_timeout() -> Duration {
    Duration::from_secs(20)
}

/// 完整的运行时配置。
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub ssh: SshConfig,
    #[serde(default)]
    pub mode: TunnelMode,
    #[serde(default)]
    pub listen: ListenConfig,
    #[serde(default)]
    pub reconnect: ReconnectConfig,
    #[serde(default)]
    pub helper: HelperConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListenConfig {
    /// SOCKS5 监听地址。
    #[serde(default = "default_socks")]
    pub socks5: Option<String>,
    /// HTTP CONNECT 监听地址。
    #[serde(default)]
    pub http: Option<String>,
    /// 入口认证凭据。**不设置意味着本机任何进程都能使用这个代理**，
    /// 监听在非回环地址时必须设置。
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            socks5: default_socks(),
            http: None,
            username: None,
            password: None,
        }
    }
}

fn default_socks() -> Option<String> {
    Some("127.0.0.1:1080".to_string())
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReconnectConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_initial", with = "humantime_serde")]
    pub initial_delay: Duration,
    #[serde(default = "default_max_delay", with = "humantime_serde")]
    pub max_delay: Duration,
    #[serde(default = "default_multiplier")]
    pub multiplier: f64,
    #[serde(default = "default_jitter")]
    pub jitter: f64,
    /// 隧道不可用时，新到达的代理请求最多等待多久再放弃。
    ///
    /// 这是"断网自愈"对上层的可见效果：短暂断网期间新连接会排队等待
    /// 隧道恢复，而不是立刻报错。
    #[serde(default = "default_dial_wait", with = "humantime_serde")]
    pub dial_wait: Duration,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            initial_delay: default_initial(),
            max_delay: default_max_delay(),
            multiplier: default_multiplier(),
            jitter: default_jitter(),
            dial_wait: default_dial_wait(),
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_initial() -> Duration {
    Duration::from_millis(250)
}
fn default_max_delay() -> Duration {
    Duration::from_secs(30)
}
fn default_multiplier() -> f64 {
    2.0
}
fn default_jitter() -> f64 {
    0.2
}
fn default_dial_wait() -> Duration {
    Duration::from_secs(30)
}

impl ReconnectConfig {
    pub fn backoff_policy(&self) -> BackoffPolicy {
        BackoffPolicy {
            initial: self.initial_delay,
            max: self.max_delay,
            multiplier: self.multiplier,
            jitter: self.jitter,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct HelperConfig {
    /// 远端 helper 的调用命令。留空则使用 `remote_path`。
    #[serde(default)]
    pub command: Option<String>,
    /// helper 二进制在远端的路径。
    #[serde(default = "default_remote_path")]
    pub remote_path: String,
    /// 每条流的重传缓冲大小。直接决定断线可恢复的数据量：
    /// 重连时若缺口超过它，该流只能重置。
    #[serde(default = "default_stream_window")]
    pub stream_window: u64,
    /// 远端目标允许列表，转换为 helper 的 `--allow` 参数。
    #[serde(default)]
    pub allow: Vec<String>,
}

impl Default for HelperConfig {
    fn default() -> Self {
        Self {
            command: None,
            remote_path: default_remote_path(),
            stream_window: default_stream_window(),
            allow: Vec::new(),
        }
    }
}

fn default_remote_path() -> String {
    "srp-helper".to_string()
}
fn default_stream_window() -> u64 {
    srp_proto::DEFAULT_STREAM_WINDOW
}

impl HelperConfig {
    /// 构造在远端实际执行的命令行。
    pub fn build_command(&self) -> String {
        if let Some(c) = &self.command {
            return c.clone();
        }
        let mut cmd = shell_quote(&self.remote_path);
        cmd.push_str(&format!(" --stream-window {}", self.stream_window));
        for a in &self.allow {
            cmd.push_str(" --allow ");
            cmd.push_str(&shell_quote(a));
        }
        cmd
    }
}

/// 单引号包裹的 POSIX shell 转义。
///
/// 远端命令由 sshd 交给 `sh -c` 执行，配置里的路径与允许列表都是用户
/// 提供的值，直接拼接会导致命令注入。
pub fn shell_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            // 关闭引号、插入转义单引号、重新开引号。
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

impl Config {
    /// 校验配置的内在一致性与安全性。
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.ssh.host.trim().is_empty() {
            return Err(ConfigError::Invalid("ssh.host must not be empty".into()));
        }
        if self.ssh.user.trim().is_empty() {
            return Err(ConfigError::Invalid("ssh.user must not be empty".into()));
        }
        if self.listen.socks5.is_none() && self.listen.http.is_none() {
            return Err(ConfigError::Invalid(
                "at least one of listen.socks5 / listen.http must be set".into(),
            ));
        }
        if self.ssh.keepalive_max == 0 {
            return Err(ConfigError::Invalid(
                "ssh.keepalive_max must be >= 1".into(),
            ));
        }
        if self.reconnect.multiplier < 1.0 {
            return Err(ConfigError::Invalid(
                "reconnect.multiplier must be >= 1.0".into(),
            ));
        }
        if !(0.0..=1.0).contains(&self.reconnect.jitter) {
            return Err(ConfigError::Invalid(
                "reconnect.jitter must be within 0.0..=1.0".into(),
            ));
        }
        if self.mode == TunnelMode::Helper && self.helper.stream_window == 0 {
            return Err(ConfigError::Invalid(
                "helper.stream_window must be > 0".into(),
            ));
        }
        Ok(())
    }

    /// 返回需要提醒用户的安全问题。不阻止启动，但必须让用户看到。
    pub fn security_warnings(&self) -> Vec<String> {
        let mut w = Vec::new();
        let has_cred = self.listen.username.is_some() && self.listen.password.is_some();
        for (name, addr) in [
            ("listen.socks5", &self.listen.socks5),
            ("listen.http", &self.listen.http),
        ] {
            let Some(addr) = addr else { continue };
            if !is_loopback_listen(addr) && !has_cred {
                w.push(format!(
                    "{name} = {addr} 监听在非回环地址且未配置 listen.username/password：\
                     任何能访问该地址的主机都可以使用这个代理转发流量。"
                ));
            }
        }
        if self.ssh.host_key == HostKeyPolicy::AcceptNew {
            w.push(
                "ssh.host_key = accept_new：首次连接会无条件信任服务端密钥，\
                 存在中间人风险。确认指纹后建议改回 strict 或改用 pinned。"
                    .to_string(),
            );
        }
        if self.mode == TunnelMode::Helper && self.helper.allow.is_empty() {
            w.push("helper.allow 为空：远端 helper 将允许连接任意目标地址。".to_string());
        }
        w
    }
}

/// 判断监听地址是否仅限本机。
fn is_loopback_listen(addr: &str) -> bool {
    // 先尝试完整 socket 地址解析，再退化到取 host 部分。
    let host = match addr.rsplit_once(':') {
        Some((h, _)) => h.trim_matches(|c| c == '[' || c == ']'),
        None => addr,
    };
    if host == "localhost" {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        // 解析不出来（如空 host 或域名）时保守地按"非回环"处理并告警。
        Err(_) => false,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid configuration: {0}")]
    Invalid(String),
    #[error("failed to parse configuration: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("failed to read configuration file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl Config {
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        let cfg: Config = toml::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_toml_str(&text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
[ssh]
host = "example.com"
user = "alice"
auth = { type = "public_key", path = "/home/alice/.ssh/id_ed25519" }
"#;

    #[test]
    fn parses_minimal_config_with_sane_defaults() {
        let cfg = Config::from_toml_str(MINIMAL).expect("parse");
        assert_eq!(cfg.ssh.host, "example.com");
        assert_eq!(cfg.ssh.port, 22);
        assert_eq!(cfg.mode, TunnelMode::DirectTcpip);
        assert_eq!(
            cfg.ssh.host_key,
            HostKeyPolicy::Strict,
            "must default strict"
        );
        assert_eq!(cfg.listen.socks5.as_deref(), Some("127.0.0.1:1080"));
        assert!(cfg.reconnect.enabled);
        assert_eq!(cfg.ssh.keepalive_interval, Duration::from_secs(15));
    }

    #[test]
    fn parses_durations_and_helper_mode() {
        let cfg = Config::from_toml_str(
            r#"
mode = "helper"
[ssh]
host = "h"
user = "u"
auth = { type = "password", password = "p" }
keepalive_interval = "5s"
connect_timeout = "3s"
[reconnect]
initial_delay = "100ms"
max_delay = "1m"
[helper]
remote_path = "/opt/srp-helper"
allow = ["*.internal", "10.0.0.1:443"]
"#,
        )
        .expect("parse");
        assert_eq!(cfg.mode, TunnelMode::Helper);
        assert_eq!(cfg.ssh.keepalive_interval, Duration::from_secs(5));
        assert_eq!(cfg.reconnect.max_delay, Duration::from_secs(60));
        assert_eq!(cfg.helper.allow.len(), 2);
    }

    #[test]
    fn rejects_invalid_configs() {
        let bad = [
            // 没有任何监听入口
            r#"
[ssh]
host = "h"
user = "u"
auth = { type = "agent" }
[listen]
socks5 = ""
"#,
        ];
        // 上面那条 socks5="" 会被解析成 Some("")，不算无入口，所以单独构造。
        let _ = bad;

        let mut cfg = Config::from_toml_str(MINIMAL).unwrap();
        cfg.listen.socks5 = None;
        cfg.listen.http = None;
        assert!(cfg.validate().is_err(), "no listener must be rejected");

        let mut cfg = Config::from_toml_str(MINIMAL).unwrap();
        cfg.ssh.host = "  ".into();
        assert!(cfg.validate().is_err());

        let mut cfg = Config::from_toml_str(MINIMAL).unwrap();
        cfg.ssh.keepalive_max = 0;
        assert!(cfg.validate().is_err());

        let mut cfg = Config::from_toml_str(MINIMAL).unwrap();
        cfg.reconnect.jitter = 2.0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn warns_when_exposed_without_credentials() {
        let mut cfg = Config::from_toml_str(MINIMAL).unwrap();
        assert!(
            cfg.security_warnings().is_empty(),
            "loopback default must be quiet"
        );

        cfg.listen.socks5 = Some("0.0.0.0:1080".into());
        let w = cfg.security_warnings();
        assert_eq!(w.len(), 1, "must warn about open proxy: {w:?}");
        assert!(w[0].contains("0.0.0.0:1080"));

        cfg.listen.username = Some("u".into());
        cfg.listen.password = Some("p".into());
        assert!(cfg.security_warnings().is_empty(), "credentials silence it");
    }

    #[test]
    fn loopback_detection_handles_ipv6_and_localhost() {
        assert!(is_loopback_listen("127.0.0.1:1080"));
        assert!(is_loopback_listen("[::1]:1080"));
        assert!(is_loopback_listen("localhost:1080"));
        assert!(!is_loopback_listen("0.0.0.0:1080"));
        assert!(!is_loopback_listen("[::]:1080"));
        assert!(!is_loopback_listen("192.168.1.5:1080"));
    }

    /// 转义的正确性标准不是"输出里没有某个子串"，而是
    /// **交给真实 shell 后原样还原成一个参数**。所以直接用 `sh` 验证。
    #[test]
    fn shell_quote_survives_a_real_shell_roundtrip() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("it's"), r#"'it'\''s'"#);

        let payloads = [
            "plain",
            "it's",
            // 经典注入：闭合引号后追加命令
            "a'; rm -rf /; echo '",
            "$(touch /tmp/pwned)",
            "`id`",
            "a b\tc",
            "* ? [a-z]",
            "back\\slash",
            "new\nline",
            "\"double\"",
            "; | & > <",
        ];

        for p in payloads {
            let quoted = shell_quote(p);
            // printf %s 不加换行，输出必须与输入逐字节相同。
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("printf %s {quoted}"))
                .output()
                .expect("run sh");
            assert!(
                out.status.success(),
                "sh failed for {p:?} -> {quoted}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(
                String::from_utf8_lossy(&out.stdout),
                p,
                "quoting must round-trip exactly for {p:?} (quoted: {quoted})"
            );
        }

        // 注入若成功会创建这个文件；断言它不存在。
        assert!(
            !std::path::Path::new("/tmp/pwned").exists(),
            "command substitution escaped the quoting"
        );
    }

    #[test]
    fn helper_command_quotes_all_user_values() {
        let h = HelperConfig {
            command: None,
            remote_path: "/opt/my helper".into(),
            stream_window: 1024,
            allow: ["a b; touch /tmp/x".to_string()].into(),
        };
        let cmd = h.build_command();
        assert!(cmd.starts_with("'/opt/my helper'"));
        assert!(cmd.contains("--stream-window 1024"));
        assert!(cmd.contains(r"'a b; touch /tmp/x'"));
        assert!(!cmd.contains("; touch /tmp/x'\n"));

        let explicit = HelperConfig {
            command: Some("custom --flag".into()),
            ..Default::default()
        };
        assert_eq!(explicit.build_command(), "custom --flag");
    }
}
