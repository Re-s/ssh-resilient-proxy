//! `srp` 命令行入口。

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use srp::tunnel::config::{
    AuthMethod, Config, HelperConfig, HostKeyPolicy, ListenConfig, ReconnectConfig, SshConfig,
    TunnelMode,
};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "srp",
    version,
    about = "基于 SSH 的弹性 TCP 代理：保持连接、断网自愈、掉包恢复",
    long_about = "srp 通过一条 SSH 连接转发本地 SOCKS5 / HTTP CONNECT 流量。\n\
                  默认模式只使用标准 direct-tcpip 通道，无需改动 SSH 服务端。"
)]
struct Cli {
    /// 配置文件路径（TOML）。提供时其余连接参数被忽略。
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// 日志级别（也可用 RUST_LOG 环境变量）。
    #[arg(long, default_value = "info", value_name = "LEVEL")]
    log_level: String,

    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    connect: ConnectArgs,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// 校验配置文件并打印生效值，不建立任何连接。
    Check,
    /// 打印一份带注释的示例配置。
    Example,
    /// 自动检测 SSH 配置并写入 /etc/default/srp（需要 root 权限）。
    Setup,
}

#[derive(Parser, Debug, Default)]
struct ConnectArgs {
    /// SSH 目标，形如 `user@host` 或 `user@host:port`。
    #[arg(value_name = "USER@HOST[:PORT]")]
    target: Option<String>,

    /// 私钥路径。支持 `~/...`；未指定时自动发现 ~/.ssh/id_ed25519 等常见密钥。
    #[arg(short = 'i', long, value_name = "FILE")]
    identity: Option<PathBuf>,

    /// 私钥口令。建议改用 ssh-agent 而不是在命令行传口令。
    #[arg(
        long,
        env = "SRP_KEY_PASSPHRASE",
        value_name = "PASS",
        hide_env_values = true
    )]
    passphrase: Option<String>,

    /// 使用密码认证。从 SRP_SSH_PASSWORD 读取，避免出现在进程列表里。
    #[arg(
        long,
        env = "SRP_SSH_PASSWORD",
        value_name = "PASS",
        hide_env_values = true
    )]
    password: Option<String>,

    /// 强制使用 ssh-agent。
    #[arg(long, conflicts_with_all = ["identity", "password"])]
    agent: bool,

    /// SOCKS5 监听地址。
    #[arg(long, default_value = "127.0.0.1:1080", value_name = "ADDR")]
    socks5: String,

    /// 同时开启 HTTP CONNECT 入口。
    #[arg(long, value_name = "ADDR")]
    http: Option<String>,

    /// 关闭 SOCKS5 入口（只用 --http 时）。
    #[arg(long)]
    no_socks5: bool,

    /// 入口认证用户名。监听非回环地址时强烈建议设置。
    #[arg(long, value_name = "USER")]
    proxy_user: Option<String>,

    /// 入口认证密码。
    #[arg(
        long,
        env = "SRP_PROXY_PASSWORD",
        value_name = "PASS",
        hide_env_values = true
    )]
    proxy_password: Option<String>,

    /// 主机密钥策略：strict（默认）/ accept-new / 或直接给 SHA256 指纹固定。
    #[arg(long, default_value = "strict", value_name = "POLICY")]
    host_key: String,

    /// known_hosts 路径。
    #[arg(long, value_name = "FILE")]
    known_hosts: Option<PathBuf>,

    /// 启用 helper 模式：在远端运行 srp-helper 以获得字节级续传。
    #[arg(long)]
    helper: bool,

    /// helper 二进制在远端的路径。
    #[arg(long, default_value = "srp-helper", value_name = "PATH")]
    helper_path: String,

    /// helper 模式下允许的目标（可重复），如 `*.internal` 或 `10.0.0.1:443`。
    #[arg(long = "allow", value_name = "PATTERN")]
    allow: Vec<String>,

    /// SSH 保活间隔（秒）。
    #[arg(long, default_value_t = 15, value_name = "SECS")]
    keepalive: u64,

    /// 隧道不可用时新请求最多等待多少秒。
    #[arg(long, default_value_t = 30, value_name = "SECS")]
    dial_wait: u64,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log_level);

    match &cli.command {
        Some(Command::Example) => {
            print!("{}", EXAMPLE_CONFIG);
            return Ok(());
        }
        Some(Command::Setup) => return run_setup(),
        Some(Command::Check) => {
            let cfg = build_config(&cli)?;
            println!("✓ configuration is valid.");
            println!(
                "  ssh          : {}@{}:{}",
                cfg.ssh.user, cfg.ssh.host, cfg.ssh.port
            );
            println!(
                "  auth         : {}",
                match &cfg.ssh.auth {
                    AuthMethod::PublicKey { path, .. } => {
                        format!("publickey {}", path.display())
                    }
                    AuthMethod::Password { .. } => "password".into(),
                    AuthMethod::Agent => "ssh-agent".into(),
                }
            );
            println!("  mode         : {:?}", cfg.mode);
            println!("  host key     : {:?}", cfg.ssh.host_key);
            println!("  socks5       : {:?}", cfg.listen.socks5);
            println!("  http         : {:?}", cfg.listen.http);
            println!("  keepalive    : {:?}", cfg.ssh.keepalive_interval);
            println!("  dial wait    : {:?}", cfg.reconnect.dial_wait);
            for w in cfg.security_warnings() {
                println!("  ⚠ warning    : {w}");
            }
            return Ok(());
        }
        None => {}
    }

    let cfg = build_config(&cli)?;

    // 运行时按需构造，避免在 --check / --example 路径上启动线程池。
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start the async runtime")?
        .block_on(srp::app::run(cfg))
}

fn init_tracing(level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("srp={level},srp_proto={level}")));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        // 日志走 stderr，让 stdout 留给可能的结构化输出。
        .with_writer(std::io::stderr)
        .init();
}

/// 从 `~/.ssh/config` 中提取 Host 条目，作为可能的 SSH 目标。
///
/// 只提取有 HostName 的条目（跳过 * 通配符），
/// 格式为 `User@HostName:Port` 或 `User@HostName`。
fn discover_ssh_hosts() -> Vec<String> {
    let home = std::env::var_os("HOME").unwrap_or_default();
    let config_path = std::path::PathBuf::from(home).join(".ssh/config");
    let content = match std::fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let mut hosts = Vec::new();
    let mut current_host: Option<String> = None;
    let mut hostname: Option<String> = None;
    let mut user: Option<String> = None;
    let mut port: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            // 块结束，提交当前条目。
            if let (Some(h), Some(hn)) = (&current_host, &hostname) {
                if h != "*" && !hn.is_empty() {
                    let u = user.as_deref().unwrap_or("root");
                    let p = port.as_deref().unwrap_or("22");
                    let target = if p == "22" {
                        format!("{u}@{hn}")
                    } else {
                        format!("{u}@{hn}:{p}")
                    };
                    hosts.push(target);
                }
            }
            current_host = None;
            hostname = None;
            user = None;
            port = None;
            continue;
        }

        let parts: Vec<&str> = trimmed.splitn(2, |c: char| c.is_whitespace()).collect();
        let key = parts[0].to_lowercase();
        let val = parts.get(1).unwrap_or(&"").trim();

        match key.as_str() {
            "host" => {
                // 提交上一个条目。
                if let (Some(h), Some(hn)) = (&current_host, &hostname) {
                    if h != "*" && !hn.is_empty() {
                        let u = user.as_deref().unwrap_or("root");
                        let p = port.as_deref().unwrap_or("22");
                        let target = if p == "22" {
                            format!("{u}@{hn}")
                        } else {
                            format!("{u}@{hn}:{p}")
                        };
                        hosts.push(target);
                    }
                }
                current_host = Some(val.to_string());
                hostname = None;
                user = None;
                port = None;
            }
            "hostname" => hostname = Some(val.to_string()),
            "user" => user = Some(val.to_string()),
            "port" => port = Some(val.to_string()),
            _ => {}
        }
    }

    // 提交最后一个条目。
    if let (Some(h), Some(hn)) = (&current_host, &hostname) {
        if h != "*" && !hn.is_empty() {
            let u = user.as_deref().unwrap_or("root");
            let p = port.as_deref().unwrap_or("22");
            let target = if p == "22" {
                format!("{u}@{hn}")
            } else {
                format!("{u}@{hn}:{p}")
            };
            hosts.push(target);
        }
    }

    hosts
}

/// 交互式配置：检测 SSH 配置，让用户选择目标，写入 /etc/default/srp。
fn run_setup() -> Result<()> {
    use std::io::{self, Write};

    println!("🔧 srp 交互式配置");
    println!();

    // 检测 SSH 配置。
    let hosts = discover_ssh_hosts();
    if !hosts.is_empty() {
        println!("检测到 ~/.ssh/config 中的主机：");
        for (i, h) in hosts.iter().enumerate() {
            println!("  [{}] {}", i + 1, h);
        }
        println!("  [0] 手动输入");
        println!();

        print!("请选择编号（或直接输入目标）：");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        let target = if input == "0" || input.is_empty() {
            print!("SSH 目标（user@host:port）：");
            io::stdout().flush()?;
            let mut t = String::new();
            io::stdin().read_line(&mut t)?;
            t.trim().to_string()
        } else if let Ok(idx) = input.parse::<usize>() {
            if idx >= 1 && idx <= hosts.len() {
                hosts[idx - 1].clone()
            } else {
                anyhow::bail!("无效编号: {input}");
            }
        } else {
            // 直接输入的目标。
            input.to_string()
        };

        if target.is_empty() {
            anyhow::bail!("目标不能为空");
        }

        // 验证目标格式。
        let _ = parse_target(&target)
            .context("目标格式无效，应为 user@host[:port]")?;

        // 写入配置。
        let default_path = "/etc/default/srp";
        let content = format!(
            "# /etc/default/srp — 由 srp setup 自动生成\n\
             SRP_ARGS={}\n",
            target
        );

        match std::fs::write(default_path, &content) {
            Ok(()) => {
                println!();
                println!("✓ 已写入 {default_path}");
                println!();
                println!("接下来：");
                println!("  sudo systemctl daemon-reload");
                println!("  sudo systemctl restart srp");
                println!("  systemctl status srp");
            }
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                println!();
                println!("⚠ 权限不足，请手动执行：");
                println!();
                println!("  echo 'SRP_ARGS={target}' | sudo tee {default_path}");
                println!("  sudo systemctl daemon-reload");
                println!("  sudo systemctl restart srp");
            }
            Err(e) => return Err(e.into()),
        }
    } else {
        println!("未检测到 ~/.ssh/config。");
        println!();
        print!("SSH 目标（user@host:port）：");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let target = input.trim();

        if target.is_empty() {
            anyhow::bail!("目标不能为空");
        }

        let _ = parse_target(target)
            .context("目标格式无效，应为 user@host[:port]")?;

        let default_path = "/etc/default/srp";
        let content = format!("# /etc/default/srp\nSRP_ARGS={}\n", target);

        match std::fs::write(default_path, &content) {
            Ok(()) => {
                println!();
                println!("✓ 已写入 {default_path}");
                println!();
                println!("接下来：");
                println!("  sudo systemctl daemon-reload");
                println!("  sudo systemctl restart srp");
                println!("  systemctl status srp");
            }
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                println!();
                println!("⚠ 权限不足，请手动执行：");
                println!();
                println!("  echo 'SRP_ARGS={target}' | sudo tee {default_path}");
                println!("  sudo systemctl daemon-reload");
                println!("  sudo systemctl restart srp");
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

fn build_config(cli: &Cli) -> Result<Config> {
    if let Some(path) = &cli.config {
        return Config::load(path).context("failed to load configuration file");
    }

    let a = &cli.connect;
    let target = a.target.as_deref().context(
        "未指定 SSH 目标。\n\
             \n\
             快速开始：\n\
               srp root@10.0.0.1\n\
               srp alice@gateway --helper\n\
             \n\
             交互式配置（自动检测 ~/.ssh/config）：\n\
               srp setup\n\
             \n\
             完整示例：srp example > srp.toml && srp --config srp.toml",
    )?;
    let (user, host, port) = parse_target(target)?;

    let auth = if a.agent {
        AuthMethod::Agent
    } else if let Some(p) = &a.password {
        AuthMethod::Password {
            password: p.clone(),
        }
    } else if let Some(k) = &a.identity {
        AuthMethod::PublicKey {
            path: expand_tilde(k)?,
            passphrase: a.passphrase.clone(),
        }
    } else if let Some(path) = discover_default_identity() {
        // 与 OpenSSH 的日常体验对齐：没有明确要求 agent 时，先使用用户
        // 最常见的私钥。显式 --agent 仍保留为优先选择。
        AuthMethod::PublicKey {
            path,
            passphrase: a.passphrase.clone(),
        }
    } else {
        // 没有可发现的本地私钥时再尝试 agent；这样不会破坏只用 agent 的用户。
        AuthMethod::Agent
    };

    let host_key = match a.host_key.as_str() {
        "strict" => HostKeyPolicy::Strict,
        "accept-new" | "accept_new" => HostKeyPolicy::AcceptNew,
        other => HostKeyPolicy::Pinned(other.to_string()),
    };

    let cfg = Config {
        ssh: SshConfig {
            host,
            port,
            user,
            auth,
            host_key,
            known_hosts: a.known_hosts.clone(),
            keepalive_interval: std::time::Duration::from_secs(a.keepalive.max(1)),
            keepalive_max: 3,
            connect_timeout: std::time::Duration::from_secs(20),
        },
        mode: if a.helper {
            TunnelMode::Helper
        } else {
            TunnelMode::DirectTcpip
        },
        listen: ListenConfig {
            socks5: if a.no_socks5 {
                None
            } else {
                Some(a.socks5.clone())
            },
            http: a.http.clone(),
            username: a.proxy_user.clone(),
            password: a.proxy_password.clone(),
        },
        reconnect: ReconnectConfig {
            dial_wait: std::time::Duration::from_secs(a.dial_wait.max(1)),
            ..Default::default()
        },
        helper: HelperConfig {
            remote_path: a.helper_path.clone(),
            allow: a.allow.clone(),
            ..Default::default()
        },
    };

    cfg.validate()?;
    Ok(cfg)
}

/// 展开 CLI 中的 `~/...`。shell 通常会展开未加引号的 `~`，但用户加引号时
/// shell 不会处理；CLI 自己兼容两种写法，避免出现看似正确却找不到文件的路径。
fn expand_tilde(path: &std::path::Path) -> Result<PathBuf> {
    let raw = path.to_string_lossy();
    if raw == "~" || raw.starts_with("~/") {
        let home = std::env::var_os("HOME").context("cannot expand '~': HOME is not set")?;
        let suffix = raw.strip_prefix("~/").unwrap_or("");
        return Ok(PathBuf::from(home).join(suffix));
    }
    Ok(path.to_path_buf())
}

/// 按 OpenSSH 常见优先级查找私钥。
///
/// 不探测 `.pub`，也不递归扫描目录：前者不是私钥，后者既慢又可能误选密钥。
/// 用户要选择非标准密钥时仍显式传 `--identity`，这比猜测安全。
fn discover_default_identity() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let ssh = PathBuf::from(home).join(".ssh");
    ["id_ed25519", "id_ecdsa", "id_rsa", "id_dsa"]
        .into_iter()
        .map(|name| ssh.join(name))
        .find(|path| path.is_file())
}

/// 解析 `user@host[:port]`。
///
/// IPv6 字面量需要方括号（`user@[::1]:22`），否则冒号会与端口分隔符歧义。
fn parse_target(s: &str) -> Result<(String, String, u16)> {
    let (user, rest) = s
        .split_once('@')
        .context("SSH target must look like user@host[:port]")?;
    if user.is_empty() {
        anyhow::bail!("SSH target is missing the user part");
    }

    let (host, port) = if let Some(stripped) = rest.strip_prefix('[') {
        // IPv6 字面量
        let (addr, tail) = stripped
            .split_once(']')
            .context("unterminated IPv6 literal in SSH target")?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().context("invalid port in SSH target")?,
            None if tail.is_empty() => 22,
            None => anyhow::bail!("unexpected text after IPv6 literal in SSH target"),
        };
        (addr.to_string(), port)
    } else {
        match rest.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse().context("invalid port in SSH target")?,
            ),
            None => (rest.to_string(), 22),
        }
    };

    if host.is_empty() {
        anyhow::bail!("SSH target is missing the host part");
    }
    Ok((user.to_string(), host, port))
}

const EXAMPLE_CONFIG: &str = r#"# srp 配置示例

# 转发模式：
#   direct_tcpip（默认）—— 只用标准 SSH 通道，远端零依赖。
#   helper          —— 在远端运行 srp-helper，获得字节级续传。
mode = "direct_tcpip"

[ssh]
host = "gateway.example.com"
port = 22
user = "alice"

# 认证：public_key / password / agent 三者之一
auth = { type = "public_key", path = "/home/alice/.ssh/id_ed25519" }
# auth = { type = "agent" }
# auth = { type = "password", password = "..." }

# 主机密钥策略。strict 表示必须已在 known_hosts 中；
# 也可以写成 { Pinned = "SHA256:..." } 固定指纹（容器环境推荐）。
host_key = "strict"

# 保持连接：主动保活让死链在数十秒内暴露，而不是等请求失败才发现。
keepalive_interval = "15s"
keepalive_max = 3
connect_timeout = "20s"

[listen]
socks5 = "127.0.0.1:1080"
# http = "127.0.0.1:8080"
# 监听非回环地址时必须设置凭据，否则等于开放代理。
# username = "proxyuser"
# password = "proxypass"

[reconnect]
enabled = true
initial_delay = "250ms"
max_delay = "30s"
multiplier = 2.0
jitter = 0.2
# 断网期间新请求最多等待这么久，等隧道恢复后继续，而不是立刻报错。
dial_wait = "30s"

[helper]
remote_path = "srp-helper"
# 每条流的重传缓冲：直接决定断线可恢复的数据量。
stream_window = 4194304
# 远端允许连接的目标白名单，留空表示不限制。
allow = []
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_ported_targets() {
        assert_eq!(
            parse_target("alice@example.com").unwrap(),
            ("alice".into(), "example.com".into(), 22)
        );
        assert_eq!(
            parse_target("bob@10.0.0.1:2222").unwrap(),
            ("bob".into(), "10.0.0.1".into(), 2222)
        );
    }

    #[test]
    fn parses_ipv6_literals() {
        assert_eq!(
            parse_target("alice@[::1]").unwrap(),
            ("alice".into(), "::1".into(), 22)
        );
        assert_eq!(
            parse_target("alice@[2001:db8::1]:2222").unwrap(),
            ("alice".into(), "2001:db8::1".into(), 2222)
        );
    }

    #[test]
    fn rejects_malformed_targets() {
        for bad in [
            "no-at-sign",
            "@host",
            "user@",
            "user@host:notaport",
            "user@[::1",
            "user@[::1]junk",
        ] {
            assert!(parse_target(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn example_config_is_parseable() {
        let cfg = Config::from_toml_str(EXAMPLE_CONFIG)
            .expect("the shipped example config must be valid");
        assert_eq!(cfg.ssh.user, "alice");
        assert_eq!(cfg.mode, TunnelMode::DirectTcpip);
        assert_eq!(cfg.ssh.host_key, HostKeyPolicy::Strict);
    }

    #[test]
    fn cli_defaults_to_discovered_key_or_agent_and_strict_host_key() {
        let cli = Cli::parse_from(["srp", "alice@example.com"]);
        let cfg = build_config(&cli).expect("build");
        match cfg.ssh.auth {
            AuthMethod::PublicKey { path, .. } => assert!(path.is_file()),
            AuthMethod::Agent => assert!(discover_default_identity().is_none()),
            _ => panic!("implicit authentication must be a key or agent"),
        }
        assert_eq!(cfg.ssh.host_key, HostKeyPolicy::Strict);
        assert_eq!(cfg.listen.socks5.as_deref(), Some("127.0.0.1:1080"));
        assert_eq!(cfg.mode, TunnelMode::DirectTcpip);
    }

    #[test]
    fn quoted_tilde_identity_is_expanded() {
        let home = std::env::var_os("HOME").expect("HOME for test");
        let path = expand_tilde(std::path::Path::new("~/.ssh/id_ed25519")).unwrap();
        assert_eq!(path, PathBuf::from(home).join(".ssh/id_ed25519"));
    }

    #[test]
    fn pinned_fingerprint_is_recognised_from_cli() {
        let cli = Cli::parse_from(["srp", "alice@example.com", "--host-key", "SHA256:abc123"]);
        let cfg = build_config(&cli).unwrap();
        assert_eq!(
            cfg.ssh.host_key,
            HostKeyPolicy::Pinned("SHA256:abc123".into())
        );
    }

    #[test]
    fn helper_flag_switches_mode_and_passes_allow_list() {
        let cli = Cli::parse_from([
            "srp",
            "alice@example.com",
            "--helper",
            "--allow",
            "*.internal",
            "--allow",
            "10.0.0.1:443",
        ]);
        let cfg = build_config(&cli).unwrap();
        assert_eq!(cfg.mode, TunnelMode::Helper);
        assert_eq!(cfg.helper.allow, vec!["*.internal", "10.0.0.1:443"]);
    }

    #[test]
    fn disabling_both_listeners_is_rejected() {
        let cli = Cli::parse_from(["srp", "alice@example.com", "--no-socks5"]);
        assert!(
            build_config(&cli).is_err(),
            "a proxy with no entry point makes no sense"
        );
    }

    #[test]
    fn missing_target_is_reported_clearly() {
        let cli = Cli::parse_from(["srp"]);
        let err = build_config(&cli).expect_err("must fail");
        assert!(err.to_string().contains("未指定 SSH 目标"), "{err}");
    }
}
