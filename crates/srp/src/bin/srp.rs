//! `srp` 命令行入口。

use std::cell::RefCell;
use std::io::IsTerminal;
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

    /// SSH 保活间隔（秒）。最小值为 1，传 0 会被钳位为 1 并给出警告。
    #[arg(long, default_value_t = 15, value_name = "SECS")]
    keepalive: u64,

    /// 隧道不可用时新请求最多等待多少秒。
    #[arg(long, default_value_t = 30, value_name = "SECS")]
    dial_wait: u64,
}

thread_local! {
    /// 存储 build_config 阶段产生的 CLI 安全警告，供 check 子命令输出。
    static CLI_WARNINGS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// 取出 build_config 阶段收集的 CLI 安全警告。
fn take_cli_warnings() -> Vec<String> {
    CLI_WARNINGS.with(|w| std::mem::take(&mut *w.borrow_mut()))
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
            // 显示 config 层面的安全警告（只对有效地址生效）
            for w in cfg.security_warnings() {
                println!("  ⚠ warning    : {w}");
            }
            // 显示 build_config 阶段收集的 CLI 级别警告
            for w in take_cli_warnings() {
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

/// 检查主机名是否为常见的代码托管平台，这类主机通常不适合作为 SSH 代理跳板。
///
/// 过滤条件：
/// 1. 用户名为 `git`（GitHub/GitLab 等平台的默认 SSH 用户）
/// 2. 主机名匹配常见代码托管平台（包括子域名）：
///    - github.com, gitlab.com, bitbucket.org, codeberg.org, gitee.com 等
fn is_git_host(user: &str, hostname: &str) -> bool {
    // 用户名为 git 的条目通常是代码托管平台
    if user == "git" {
        return true;
    }

    // 常见代码托管平台的域名列表
    let git_platforms = [
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "codeberg.org",
        "gitee.com",
        "git.oschina.net",
        "coding.net",
        "gogs.io",
        "gitea.io",
    ];

    // 检查主机名是否匹配任何平台（包括子域名）
    for platform in git_platforms {
        if hostname == platform || hostname.ends_with(&format!(".{platform}")) {
            return true;
        }
    }

    false
}

/// 从 `~/.ssh/config` 中提取 Host 条目，作为可能的 SSH 目标。
///
/// 只提取有 HostName 的条目（跳过 * 通配符），
/// 格式为 `User@HostName:Port` 或 `User@HostName`。
/// 过滤掉明显不是代理跳板的条目（如 git 类主机）。
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
                    // 过滤 git 类主机，这类主机通常不适合作为 SSH 代理跳板
                    if !is_git_host(u, hn) {
                        let target = if p == "22" {
                            format!("{u}@{hn}")
                        } else {
                            format!("{u}@{hn}:{p}")
                        };
                        hosts.push(target);
                    }
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
                        // 过滤 git 类主机，这类主机通常不适合作为 SSH 代理跳板
                        if !is_git_host(u, hn) {
                            let target = if p == "22" {
                                format!("{u}@{hn}")
                            } else {
                                format!("{u}@{hn}:{p}")
                            };
                            hosts.push(target);
                        }
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
            // 过滤 git 类主机，这类主机通常不适合作为 SSH 代理跳板
            if !is_git_host(u, hn) {
                let target = if p == "22" {
                    format!("{u}@{hn}")
                } else {
                    format!("{u}@{hn}:{p}")
                };
                hosts.push(target);
            }
        }
    }

    hosts
}

/// 交互式配置：检测 SSH 配置，让用户选择目标，写入 /etc/default/srp。
/// 写入 systemd 环境文件，失败时给出可直接复制的补救命令。
fn write_setup_config(target: &str) -> Result<()> {
    use std::io::ErrorKind;

    let path = "/etc/default/srp";
    let content = format!(
        "# /etc/default/srp — 由 srp setup 生成\n\
         # 引号可加可不加，systemd 的 $SRP_ARGS 会正确拆分参数。\n\
         SRP_ARGS=\"{target}\"\n"
    );

    match std::fs::write(path, &content) {
        Ok(()) => {
            println!();
            println!("✓ 已写入 {path}");
            println!();
            println!("接下来执行：");
            println!("  sudo systemctl daemon-reload");
            println!("  sudo systemctl restart srp");
            println!("  systemctl status srp");
            Ok(())
        }
        // 没有 root 权限是最常见的情况：不要只说"权限不足"，
        // 直接给出可以整段复制执行的命令。
        Err(e) if matches!(e.kind(), ErrorKind::PermissionDenied) => {
            println!();
            println!("⚠ 没有写入 {path} 的权限（需要 root）。");
            println!();
            println!("请复制执行下面三行：");
            println!();
            println!("  echo 'SRP_ARGS=\"{target}\"' | sudo tee {path}");
            println!("  sudo systemctl daemon-reload");
            println!("  sudo systemctl restart srp");
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("写入 {path} 失败：{e}")),
    }
}

/// 非交互环境下打印手动配置指引。
///
/// stdin 不是终端时（管道、CI、被服务调用）交互提示没有意义，
/// 直接给出完整命令，并以成功退出——这不是错误场景。
fn print_manual_setup_guide(candidates: &[String]) {
    let example = candidates
        .first()
        .cloned()
        .unwrap_or_else(|| "alice@gateway.example.com".to_string());

    println!("检测到非交互环境（stdin 不是终端），跳过交互式提问。");
    println!();
    if !candidates.is_empty() {
        println!("从 ~/.ssh/config 中发现这些候选目标：");
        for c in candidates {
            println!("  {c}");
        }
        println!();
    }
    println!("请把下面三行里的目标换成你自己的，然后复制执行：");
    println!();
    println!("  echo 'SRP_ARGS=\"{example}\"' | sudo tee /etc/default/srp");
    println!("  sudo systemctl daemon-reload");
    println!("  sudo systemctl restart srp");
    println!();
    println!("验证配置是否正确（不会真的连接）：");
    println!("  srp {example} check");
}

/// 读取一行输入并去掉首尾空白。
fn read_line_trimmed() -> Result<String> {
    use std::io::BufRead;

    let mut buf = String::new();
    std::io::stdin().lock().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

/// 交互式配置：检测 SSH 配置，让用户选择目标，写入 /etc/default/srp。
fn run_setup() -> Result<()> {
    use std::io::Write;

    println!("🔧 srp 交互式配置");
    println!();

    let hosts = discover_ssh_hosts();

    // 非终端环境不做交互，直接给可复制的命令。
    if !std::io::stdin().is_terminal() {
        print_manual_setup_guide(&hosts);
        return Ok(());
    }

    if hosts.is_empty() {
        println!("未在 ~/.ssh/config 中发现可用作跳板的主机。");
    } else {
        println!("检测到 ~/.ssh/config 中的主机：");
        for (i, h) in hosts.iter().enumerate() {
            println!("  [{}] {}", i + 1, h);
        }
        println!("  [0] 手动输入");
    }
    println!();

    // 最多给 3 次机会，避免一次误按回车就得从头再来。
    const MAX_TRIES: usize = 3;
    let mut target = String::new();

    for attempt in 1..=MAX_TRIES {
        let remaining = MAX_TRIES - attempt;

        if hosts.is_empty() {
            print!("SSH 目标（user@host[:port]）：");
        } else {
            print!("请选择编号 0-{}，或直接输入目标：", hosts.len());
        }
        std::io::stdout().flush()?;

        let input = read_line_trimmed()?;

        // 空输入：重试而不是直接退出。
        if input.is_empty() {
            if remaining == 0 {
                anyhow::bail!("连续 {MAX_TRIES} 次未输入内容，已取消配置。");
            }
            println!("输入不能为空，请重新输入（还剩 {remaining} 次机会）。");
            continue;
        }

        // 纯数字优先当作编号处理。
        if let Ok(idx) = input.parse::<usize>() {
            if idx == 0 {
                // 0 表示手动输入，继续下一轮但强制走手动分支。
                print!("SSH 目标（user@host[:port]）：");
                std::io::stdout().flush()?;
                let manual = read_line_trimmed()?;
                if manual.is_empty() {
                    if remaining == 0 {
                        anyhow::bail!("未输入目标，已取消配置。");
                    }
                    println!("输入不能为空，请重新输入（还剩 {remaining} 次机会）。");
                    continue;
                }
                target = manual;
            } else if idx <= hosts.len() {
                target = hosts[idx - 1].clone();
            } else {
                if remaining == 0 {
                    anyhow::bail!("编号 {idx} 超出范围，已取消配置。");
                }
                println!(
                    "编号 {idx} 超出范围，有效范围是 1-{}（或 0 手动输入），还剩 {remaining} 次机会。",
                    hosts.len()
                );
                continue;
            }
        } else {
            target = input;
        }

        // 校验格式，格式错误也给重试机会。
        match parse_target(&target) {
            Ok(_) => break,
            Err(e) => {
                if remaining == 0 {
                    return Err(e).context("目标格式无效，已取消配置");
                }
                println!("{e}");
                println!("请重新输入（还剩 {remaining} 次机会）。");
                target.clear();
            }
        }
    }

    if target.is_empty() {
        anyhow::bail!("未得到有效的 SSH 目标，已取消配置。");
    }

    println!();
    println!("将使用目标：{target}");

    write_setup_config(&target)
}

/// 校验单个监听地址字符串能否解析为 `SocketAddr`。
///
/// 返回 Ok(SocketAddr) 表示解析成功，Err 包含中文错误描述。
fn validate_listen_addr(addr_str: &str, param_name: &str) -> Result<std::net::SocketAddr> {
    // 尝试直接解析为 SocketAddr（如 "127.0.0.1:1080"）
    if let Ok(addr) = addr_str.parse::<std::net::SocketAddr>() {
        return Ok(addr);
    }

    // 检查是否缺少端口号（纯 IP/主机名，没有冒号）
    let has_colon = addr_str.contains(':');
    let has_bracket = addr_str.contains('[');

    if has_bracket {
        // IPv6 字面量格式但解析失败
        anyhow::bail!(
            "{param_name} 的地址 `{addr_str}` 格式不正确。\
             IPv6 地址应写为 [::1]:端口号，例如 [::1]:1080"
        );
    }

    if !has_colon {
        // 只有 IP/主机名，缺少端口号
        anyhow::bail!(
            "{param_name} 的地址 `{addr_str}` 缺少端口号。\
             格式应为 IP:端口号，例如 127.0.0.1:1080"
        );
    }

    // 有冒号但解析失败——可能是无效 IP
    anyhow::bail!(
        "{param_name} 的地址 `{addr_str}` 无法解析。\
         格式应为 IP:端口号，例如 127.0.0.1:1080"
    );
}

fn build_config(cli: &Cli) -> Result<Config> {
    if let Some(path) = &cli.config {
        return Config::load(path).context("加载配置文件失败");
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

    // 缺陷 8：SSH 端口 0 警告
    if port == 0 {
        let msg = "SSH 端口为 0，这通常不是预期值。标准 SSH 端口是 22，\
             请确认是否需要指定端口。";
        eprintln!("⚠ warning: {msg}");
        CLI_WARNINGS.with(|w| w.borrow_mut().push(msg.to_string()));
    }

    let auth = if a.agent {
        AuthMethod::Agent
    } else if let Some(p) = &a.password {
        AuthMethod::Password {
            password: p.clone(),
        }
    } else if let Some(k) = &a.identity {
        // 缺陷 2：校验 --identity 私钥路径
        let key_path = expand_tilde(k)?;
        if !key_path.exists() {
            anyhow::bail!(
                "私钥路径 `{}` 不存在。请检查路径是否正确，\
                 或改用 --agent 走 ssh-agent 认证。",
                key_path.display()
            );
        } else if !key_path.is_file() {
            anyhow::bail!(
                "私钥路径 `{}` 不是一个文件（可能是目录或符号链接）。\
                 请指定一个有效的私钥文件路径。",
                key_path.display()
            );
        } else {
            // 检查可读性：尝试打开文件
            use std::fs::File;
            match File::open(&key_path) {
                Ok(_) => {}
                Err(e) => {
                    anyhow::bail!(
                        "无法读取私钥文件 `{}`：{}。\
                         请检查文件权限（chmod 600 {}）或改用 --agent 走 ssh-agent 认证。",
                        key_path.display(),
                        e,
                        key_path.display()
                    );
                }
            }
        }
        AuthMethod::PublicKey {
            path: key_path,
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

    // 缺陷 5：keepalive 0 警告
    let keepalive = if a.keepalive == 0 {
        let msg = "--keepalive 0 不是有效值，已按最小值 1 秒生效。\
             如果想大幅降低保活频率（减少流量），请设置一个较大的值，例如 --keepalive 300（5 分钟）。";
        eprintln!("⚠ warning: {msg}");
        CLI_WARNINGS.with(|w| w.borrow_mut().push(msg.to_string()));
        std::time::Duration::from_secs(1)
    } else {
        std::time::Duration::from_secs(a.keepalive)
    };

    // 缺陷 4：校验所有监听地址（在构建 Config 之前）
    let socks5_addr = if a.no_socks5 {
        None
    } else {
        validate_listen_addr(&a.socks5, "--socks5")?;
        Some(a.socks5.clone())
    };

    let http_addr = if let Some(ref http) = a.http {
        validate_listen_addr(http, "--http")?;
        Some(http.clone())
    } else {
        None
    };

    // 缺陷 6：端口冲突检测——两个前端不能绑定同一地址
    if let (Some(ref s), Some(ref h)) = (&socks5_addr, &http_addr) {
        if s == h {
            anyhow::bail!(
                "--socks5 和 --http 使用了相同的监听地址 `{s}`，\
                 两个前端不能绑定同一端口。请为它们指定不同的地址。"
            );
        }
    }

    let cfg = Config {
        ssh: SshConfig {
            host,
            port,
            user,
            auth,
            host_key,
            known_hosts: a.known_hosts.clone(),
            keepalive_interval: keepalive,
            keepalive_max: 3,
            connect_timeout: std::time::Duration::from_secs(20),
        },
        mode: if a.helper {
            TunnelMode::Helper
        } else {
            TunnelMode::DirectTcpip
        },
        listen: ListenConfig {
            socks5: socks5_addr,
            http: http_addr,
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

    // 缺陷 3：--allow 在非 helper 模式下静默失效——发出警告
    if !a.allow.is_empty() && cfg.mode != TunnelMode::Helper {
        let msg = "--allow 目标白名单在当前模式（DirectTcpip）下不生效。\
             白名单只在 --helper 模式下生效。如需限制可访问目标，请加上 --helper。";
        eprintln!("⚠ warning: {msg}");
        CLI_WARNINGS.with(|w| w.borrow_mut().push(msg.to_string()));
    }

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
    // 缺陷 7：检查格式完整性并给出中文提示
    let (user, rest) = match s.split_once('@') {
        Some((u, r)) => (u, r),
        None => {
            anyhow::bail!(
                "SSH 目标格式错误，应为 user@host[:port]，例如 root@10.0.0.1 或 alice@gw:2222"
            );
        }
    };
    if user.is_empty() {
        anyhow::bail!("SSH 目标缺少用户名部分，格式应为 user@host[:port]，例如 root@10.0.0.1");
    }

    let (host, port) = if let Some(stripped) = rest.strip_prefix('[') {
        // IPv6 字面量
        let (addr, tail) = stripped
            .split_once(']')
            .context("SSH 目标中 IPv6 字面量未闭合，格式应为 user@[::1]:port 或 user@[::1]")?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p
                .parse()
                .context("SSH 目标中端口号格式错误，应为纯数字，例如 user@[::1]:2222")?,
            None if tail.is_empty() => 22,
            None => anyhow::bail!("SSH 目标 IPv6 字面量后面有多余文本，格式应为 user@[::1]:port"),
        };
        (addr.to_string(), port)
    } else {
        match rest.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse()
                    .context("SSH 目标中端口号格式错误，应为纯数字，例如 user@host:2222")?,
            ),
            None => (rest.to_string(), 22),
        }
    };

    if host.is_empty() {
        anyhow::bail!("SSH 目标缺少主机名部分，格式应为 user@host[:port]，例如 root@10.0.0.1");
    }

    // 缺陷 1：主机名中不允许包含空白字符
    if host.contains(char::is_whitespace) {
        // 检测是否包含以 '-' 开头的词——说明用户把命令行参数包进引号了
        let has_flag = host.split_whitespace().any(|part| part.starts_with('-'));
        if has_flag {
            anyhow::bail!(
                "SSH 目标里出现了空格：`{}`\n\
                 看起来命令行参数被引号包进了主机名。去掉引号即可：\n\
                 例如：srp {}",
                s,
                s.replace(char::is_whitespace, " ")
            );
        } else {
            anyhow::bail!(
                "SSH 目标主机名中包含空格：`{}`\n\
                 主机名不能包含空格，请检查输入是否正确",
                host
            );
        }
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
    fn git_hosts_are_filtered_from_setup_candidates() {
        // 用户名为 git 的一律排除，无论主机名是什么。
        assert!(is_git_host("git", "example.com"));
        // 平台域名本身与其子域名都要排除。
        assert!(is_git_host("anyone", "github.com"));
        assert!(is_git_host("anyone", "ssh.github.com"));
        assert!(is_git_host("anyone", "gitlab.com"));
        assert!(is_git_host("anyone", "altssh.gitlab.com"));
        assert!(is_git_host("anyone", "bitbucket.org"));
        assert!(is_git_host("anyone", "gitee.com"));
    }

    #[test]
    fn normal_jump_hosts_survive_the_filter() {
        // 真正能做跳板的主机不能被误杀。
        assert!(!is_git_host("root", "10.0.0.1"));
        assert!(!is_git_host("alice", "gateway.example.com"));
        assert!(!is_git_host("deploy", "prod-bastion.internal"));
        // 仅仅包含 github 子串但不是该域名，不应被排除。
        assert!(!is_git_host("alice", "mygithub.example.com"));
        assert!(!is_git_host("alice", "github.com.evil.net"));
    }

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

    // ==================== 缺陷 1 测试：引号包裹的目标 ====================

    #[test]
    fn rejects_quoted_target_with_flag_in_host() {
        // 缺陷 1：主机名中包含以 '-' 开头的参数（用户把命令行参数包进引号）
        let err =
            parse_target("root@1.2.3.4 --helper").expect_err("should reject whitespace in host");
        let msg = err.to_string();
        assert!(msg.contains("空格"), "应指出空格问题: {msg}");
        assert!(msg.contains("--helper"), "应提到被吞入的参数: {msg}");
        assert!(msg.contains("引号"), "应提示去掉引号: {msg}");
    }

    #[test]
    fn rejects_quoted_target_with_space_but_no_flag() {
        // 缺陷 1：主机名含空格但不含以 '-' 开头的词
        let err = parse_target("root@my host").expect_err("should reject whitespace in host");
        let msg = err.to_string();
        assert!(msg.contains("空格"), "应指出空格问题: {msg}");
        assert!(!msg.contains("引号"), "不应提示引号: {msg}");
    }

    // ==================== 缺陷 2 测试：私钥路径校验 ====================

    #[test]
    fn identity_path_not_found() {
        let cli = Cli::parse_from(["srp", "root@host", "--identity", "/does/not/exist"]);
        let err = build_config(&cli).expect_err("should reject missing identity");
        let msg = err.to_string();
        assert!(msg.contains("不存在"), "应指出路径不存在: {msg}");
        assert!(msg.contains("--agent"), "建议改用 --agent: {msg}");
    }

    #[test]
    fn identity_path_is_directory() {
        let cli = Cli::parse_from(["srp", "root@host", "--identity", "/tmp"]);
        let err = build_config(&cli).expect_err("should reject directory");
        let msg = err.to_string();
        assert!(msg.contains("不是一个文件"), "应指出不是文件: {msg}");
    }

    #[test]
    fn identity_path_not_readable() {
        // 创建一个不可读的文件
        let dir = std::env::temp_dir().join("srp_test_identity_unreadable");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("unreachable.key");
        std::fs::write(&file_path, "fake-key").unwrap();
        // 设置权限为 000（不可读）
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o000)).unwrap();
        }

        let cli = Cli::parse_from([
            "srp",
            "root@host",
            "--identity",
            file_path.to_str().unwrap(),
        ]);
        let err = build_config(&cli).expect_err("should reject unreadable key");
        let msg = err.to_string();
        assert!(
            msg.contains("无法读取") || msg.contains("权限"),
            "应指出权限问题: {msg}"
        );

        // 清理
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ==================== 缺陷 3 测试：--allow 不加 --helper ====================

    #[test]
    fn allow_without_helper_warns() {
        let cli = Cli::parse_from(["srp", "root@host", "--allow", "*.internal"]);
        let cfg = build_config(&cli).unwrap();
        assert_eq!(cfg.mode, TunnelMode::DirectTcpip);
        // 检查是否生成了警告
        let warnings = CLI_WARNINGS.with(|w| w.borrow().clone());
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("--allow") && w.contains("--helper")),
            "应提示 --allow 在 DirectTcpip 模式下不生效: {warnings:?}"
        );
    }

    // ==================== 缺陷 4 测试：监听地址校验 ====================

    #[test]
    fn socks5_missing_port() {
        let cli = Cli::parse_from(["srp", "root@host", "--socks5", "127.0.0.1"]);
        let err = build_config(&cli).expect_err("should reject missing port");
        let msg = err.to_string();
        assert!(msg.contains("--socks5"), "应指出是哪个参数: {msg}");
        assert!(msg.contains("缺少端口号"), "应说明缺少端口号: {msg}");
    }

    #[test]
    fn socks5_invalid_ip() {
        let cli = Cli::parse_from(["srp", "root@host", "--socks5", "abc:1080"]);
        let err = build_config(&cli).expect_err("should reject invalid addr");
        let msg = err.to_string();
        assert!(msg.contains("--socks5"), "应指出是哪个参数: {msg}");
        assert!(msg.contains("无法解析"), "应说明无法解析: {msg}");
    }

    #[test]
    fn socks5_garbage_ip() {
        let cli = Cli::parse_from(["srp", "root@host", "--socks5", "999.999.999.999:1080"]);
        let err = build_config(&cli).expect_err("should reject garbage IP");
        let msg = err.to_string();
        assert!(msg.contains("--socks5"), "应指出是哪个参数: {msg}");
        assert!(msg.contains("无法解析"), "应说明无法解析: {msg}");
    }

    // ==================== 缺陷 5 测试：keepalive 0 ====================

    #[test]
    fn keepalive_zero_warns_and_clamps() {
        let cli = Cli::parse_from(["srp", "root@host", "--keepalive", "0"]);
        let cfg = build_config(&cli).unwrap();
        assert_eq!(
            cfg.ssh.keepalive_interval,
            std::time::Duration::from_secs(1),
            "keepalive 0 应被钳位为 1 秒"
        );
        let warnings = CLI_WARNINGS.with(|w| w.borrow().clone());
        assert!(
            warnings.iter().any(|w| w.contains("--keepalive")),
            "应提示 keepalive 0 不是有效值: {warnings:?}"
        );
    }

    // ==================== 缺陷 6 测试：端口冲突 ====================

    #[test]
    fn port_conflict_between_socks5_and_http() {
        let cli = Cli::parse_from([
            "srp",
            "root@host",
            "--socks5",
            "127.0.0.1:1080",
            "--http",
            "127.0.0.1:1080",
        ]);
        let err = build_config(&cli).expect_err("should reject port conflict");
        let msg = err.to_string();
        assert!(msg.contains("相同"), "应指出地址相同: {msg}");
        assert!(
            msg.contains("--socks5") && msg.contains("--http"),
            "应同时提到两个参数: {msg}"
        );
    }

    // ==================== 缺陷 7 测试：parse_target 中文化 ====================

    #[test]
    fn parse_target_errors_are_chinese() {
        // 缺少 @
        let err = parse_target("abc").unwrap_err();
        assert!(
            err.to_string().contains("user@host"),
            "缺少 @ 应有中文格式说明: {err}"
        );
        // 端口号非数字
        let err = parse_target("user@host:abc").unwrap_err();
        assert!(
            err.to_string().contains("端口号"),
            "非法端口应提示端口号: {err}"
        );
        // 缺用户名
        let err = parse_target("@host").unwrap_err();
        assert!(
            err.to_string().contains("用户名"),
            "缺少用户应提示用户名: {err}"
        );
        // 缺主机名
        let err = parse_target("user@").unwrap_err();
        assert!(
            err.to_string().contains("主机名"),
            "缺少主机应提示主机名: {err}"
        );
    }

    // ==================== 缺陷 8 测试：SSH 端口 0 ====================

    #[test]
    fn ssh_port_zero_warns() {
        let cli = Cli::parse_from(["srp", "user@host:0"]);
        let cfg = build_config(&cli).unwrap();
        assert_eq!(cfg.ssh.port, 0, "端口值应保留为 0");
        let warnings = CLI_WARNINGS.with(|w| w.borrow().clone());
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("端口") && w.contains("0") && w.contains("22")),
            "应提示端口 0 通常不是预期值且标准端口是 22: {warnings:?}"
        );
    }
}
