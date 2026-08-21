# srp — 基于 SSH 的弹性 TCP 代理

用一条 SSH 连接转发本地 SOCKS5 / HTTP CONNECT 流量。**默认模式无需对 SSH 服务端做任何改动**，任何未经修改的 OpenSSH 服务器都能作为出口。

## 四项目标与各自的真实边界

| 目标 | 实现手段 | 边界 |
|---|---|---|
| 无需改 SSH 服务端 | 只用标准 `direct-tcpip` 通道 | 默认模式完全满足；helper 模式需要远端账号能执行一个上传的二进制，但 **sshd 配置仍然不动** |
| 保持连接 | SSH 层主动保活（默认 15s），死链在数十秒内暴露 | 依赖服务端响应保活；服务端完全静默时靠 `keepalive_max` 判定 |
| 断网自愈 | 带抖动的截断指数退避重连；断网期间新请求排队等待而非报错 | 重连速度取决于退避配置与网络恢复时间 |
| 掉包恢复 | 分两层，见下 | **这是唯一需要认真读的一项** |

### 掉包恢复的两个层级

这一点必须说清楚，因为它是本项目里唯一有硬性协议边界的目标。

**`direct-tcpip` 模式（默认，零远端依赖）**

远端出口 TCP 由 sshd 持有。SSH 一断，sshd 必然关闭它——**任何**纯客户端实现都无法让这条出口连接续命，这是 SSH 协议的结构性事实，不是本项目偷懒。该模式实际提供的是：

- 秒级重连；
- 重连期间新到达的请求排队等待（`dial_wait` 内），不会失败；
- 通道打开阶段的失败在新会话上**自动重放**（此时尚无应用数据流动，重放是幂等的，对调用方透明）。

已经开始传输的长流（大文件下载、嵌套 SSH）在断网后会被重置。

**`helper` 模式（字节级续传）**

出口 TCP 交给远端一个独立进程 `srp-helper` 持有，SSH 通道退化成纯字节管道。管道断了可以重建，两端的重传缓冲负责补齐缺口：

- 每条逻辑流的发送方在收到 `Ack(n)` 前不丢弃 offset ≥ n 的字节；
- 接收方严格按 offset 交付，重传造成的重叠部分裁剪后丢弃；
- 重连后双方交换各自的"已接收字节数"，发送方据此回退重发。

结果：**只要缺口不超过重传窗口（默认 4 MiB/流），重连期间零字节丢失**，逻辑流的生命周期长于任何一条 SSH 会话。缺口超出窗口时流被明确重置并上报，而不是静默丢数据。

## 快速开始

### 通过 deb 包安装（推荐）

```bash
# 安装后，srp 命令已可用
srp --help

# 交互式配置（自动检测 ~/.ssh/config，写入 systemd 环境文件）
# 需要 root 权限写入 /etc/default/srp
sudo srp setup

# 最简用法：走 ssh-agent，SOCKS5 监听 127.0.0.1:1080
srp alice@gateway.example.com

# 指定私钥 + 同时开 HTTP CONNECT 入口
srp alice@gw.example.com:2222 \
    -i ~/.ssh/id_ed25519 \
    --http 127.0.0.1:8080

# helper 模式（需先把 srp-helper 放到远端 PATH 里）
srp alice@gw.example.com --helper --allow '*.internal'

# 校验配置而不连接
srp --config srp.toml check

# 生成示例配置
srp example > srp.toml
```

### 从源码构建

```bash
# 构建
cargo build --release

# 最简用法：走 ssh-agent，SOCKS5 监听 127.0.0.1:1080
./target/release/srp alice@gateway.example.com

# 指定私钥 + 同时开 HTTP CONNECT 入口
./target/release/srp alice@gw.example.com:2222 \
    -i ~/.ssh/id_ed25519 \
    --http 127.0.0.1:8080

# helper 模式（需先把 srp-helper 放到远端 PATH 里）
./target/release/srp alice@gw.example.com --helper --allow '*.internal'

# 校验配置而不连接
./target/release/srp --config srp.toml check

# 生成示例配置
./target/release/srp example > srp.toml
```

### 验证代理可用

```bash
curl -x socks5h://127.0.0.1:1080 https://example.com
curl -x http://127.0.0.1:8080     https://example.com
```

注意 `socks5h` 而非 `socks5`：前者把域名交给代理解析，DNS 在远端出口发生，避免本地 DNS 污染。

### srp setup 子命令

`srp setup` 是交互式配置命令，用于：
1. 自动检测 `~/.ssh/config` 中的 SSH 主机配置
2. 让用户选择一个主机作为代理跳板
3. 将选择写入 `/etc/default/srp`（systemd 服务配置文件）
4. 提供 systemctl 命令重启服务

**使用场景**：通过 deb 包安装后首次配置，或需要重新配置代理目标时。

**权限要求**：需要 root 权限写入 `/etc/default/srp`，建议使用 `sudo srp setup`。

**非交互环境**：当 stdin 不是终端时（如管道、CI 环境），会打印手动配置指引并正常退出。

## 部署 helper 模式

helper 只是一个静态二进制，**不需要 root，也不需要碰 sshd 配置**：

```bash
cargo build --release -p srp-helper
scp target/release/srp-helper alice@gw:~/bin/
./target/release/srp alice@gw --helper --helper-path '~/bin/srp-helper'
```

远端账号必须能执行命令（不能是 `command=` 受限或 `nologin` 的 key）。若远端只允许端口转发，请使用默认的 `direct-tcpip` 模式。

## 安全说明

**主机密钥校验默认严格。** 代理承载全部流量，接受未知主机密钥等于把中间人攻击的门敞开。

- `strict`（默认）：必须已在 `known_hosts` 中且匹配；
- `accept-new`：首次见到的主机自动记录（会打警告）。**已记录的主机换了密钥时仍然拒绝**——那正是中间人攻击的特征；
- 直接传 SHA256 指纹即为固定模式，不读 `known_hosts`，适合容器 / CI：

```bash
srp alice@gw --host-key 'SHA256:abc123...'
```

**入口认证。** 监听非回环地址且未设置 `--proxy-user/--proxy-password` 时，任何能访问该地址的主机都可以用你的代理转发流量。程序启动时会明确告警，但不会阻止你——请自行判断。

**helper 允许列表。** `--allow` 为空时远端 helper 允许连接任意目标。生产环境建议限定：

```bash
srp alice@gw --helper --allow '*.internal' --allow '10.0.0.0/8:443'
```

**注意：** `--allow` 参数**仅在 helper 模式下生效**（即使用 `--helper` 时）。在默认的 `direct-tcpip` 模式下，`--allow` 参数会被静默忽略，不会产生任何效果。

**环境变量传递密码。** 命令行参数会出现在 `ps` 输出和 shell 历史中，不建议直接传递密码。srp 支持通过环境变量传递敏感信息：

- `SRP_KEY_PASSPHRASE`：私钥口令（对应 `--passphrase` 参数）
- `SRP_SSH_PASSWORD`：SSH 密码认证（对应 `--password` 参数）
- `SRP_PROXY_PASSWORD`：代理入口认证密码（对应 `--proxy-password` 参数）

```bash
# 推荐方式：通过环境变量传递密码
export SRP_SSH_PASSWORD="my_secret_password"
srp alice@gw.example.com

# 或者在 systemd 服务中配置
# /etc/default/srp
SRP_ARGS=alice@gw.example.com
SRP_SSH_PASSWORD=my_secret_password
```

使用环境变量比命令行参数更安全，因为：
1. 进程列表（`ps aux`）不会显示环境变量值
2. shell 历史记录不会保存环境变量赋值
3. 可以在 systemd 服务文件中安全配置

## 配置文件

```toml
mode = "direct_tcpip"   # 或 "helper"

[ssh]
host = "gateway.example.com"
port = 22
user = "alice"
auth = { type = "public_key", path = "/home/alice/.ssh/id_ed25519" }
# auth = { type = "agent" }
# auth = { type = "password", password = "..." }
host_key = "strict"
keepalive_interval = "15s"
keepalive_max = 3
connect_timeout = "20s"  # SSH 连接超时时间，默认 20 秒

[listen]
socks5 = "127.0.0.1:1080"
# http = "127.0.0.1:8080"
# 监听非回环地址时必须设置凭据，否则等于开放代理。
# username = "proxyuser"
# password = "proxypass"

[reconnect]
enabled = true           # 是否启用自动重连，设为 false 可完全关闭自动重连
initial_delay = "250ms"  # 首次重连延迟
max_delay = "30s"        # 最大重连延迟
multiplier = 2.0         # 指数退避乘数，默认 2.0
jitter = 0.2             # 抖动系数，避免重连风暴
dial_wait = "30s"        # 断网期间新请求最多等这么久

[helper]
remote_path = "srp-helper"
stream_window = 4194304  # 每条流的重传缓冲，决定可恢复的数据量
allow = []               # 远端允许连接的目标白名单，留空表示不限制
```

## 架构

```
crates/
  srp-proto/   帧协议 + 续传状态机（纯逻辑，无 I/O，可完整单测）
  srp/         客户端：入口协议 + SSH 隧道管理
    frontend/  SOCKS5 / HTTP CONNECT，通过 Dialer 抽象与隧道解耦
    tunnel/    会话生命周期、自愈监督、两种模式的 Dialer
  srp-helper/  远端二进制（仅 helper 模式需要）
  srp-testkit/ 测试用 SSH 服务器与 TCP 故障注入代理
```

分层的关键是 `Dialer` 这一个 trait：frontend 只知道"给我一条到 addr 的连接"，完全不知道底下重连过几次；tunnel 也不关心上层是 SOCKS5 还是 HTTP。两种模式对 frontend 完全等价。

`srp-proto` 刻意不含任何 I/O 与 SSH 依赖——续传是否正确这件事需要被证明，而纯状态机才可能被测试穷尽。

## 测试

```bash
cargo test --workspace              # 全部
cargo test -p srp-proto             # 协议与续传状态机
cargo clippy --workspace --all-targets -- -D warnings
```

覆盖重点（不是凑数量，每一条都对应一个能出错的地方）：

**续传正确性**（`srp-proto`）
- 多轮断线后字节流仍与原文逐字节一致；
- 重传造成的重叠部分被裁剪，不重复交付；
- 缺口超出重传窗口时明确重置，而不是静默丢数据；
- 窗口满时产生背压，不接受会被丢弃的字节。

**解码器健壮性**（`srp-proto/tests/decoder_robustness.rs`）
- 约 15000 次伪随机输入（合法帧、翻转位、纯垃圾）不 panic；
- 超大长度声明被立即拒绝，不预先分配内存；
- 数据不足时不消耗任何字节（流式读取正确性的基础）；
- 任意分片边界下不丢帧、不错序。

**自愈行为**（`srp/tunnel`）
- 连不上时持续退避重连而非放弃；
- 隧道不可用时 `wait_for_session` 按超时返回错误，不永久挂起；
- 关停后监督循环自行退出；
- 断网期间上层写入的字节进入重传缓冲且发送游标不推进（零丢失的关键不变式）。

**安全边界**（`srp/tunnel/handler.rs`、`config.rs`）
- strict 策略拒绝未知主机；known_hosts 不可读时也绝不视作可信；
- 已记录主机的密钥被替换时，`accept_new` 同样拒绝（中间人特征）；
- 固定指纹模式不依赖 known_hosts；
- 远端命令的 shell 转义交给真实 `sh` 做往返验证，覆盖引号闭合注入、命令替换等载荷。

**端到端**（`srp/tests/proxy_end_to_end.rs`）
- 1 MiB 载荷经代理往返零损坏；
- 20 条并发连接（一半成功一半失败）互不影响；
- 半关闭正确传播：客户端 shutdown 写端后目标仍能回复；
- `DialError` 到 SOCKS5 REP 码的映射在真实 socket 上正确。

**客户端 ↔ helper 线协议互操作**（`srp/tests/helper_wire_interop.rs`）

这是最有价值的一组：它启动**真实的 `srp-helper` 子进程**，把它的 stdin/stdout
当作 SSH 通道，验证两个独立实现对同一份协议的理解一致。单侧单测都过、
接起来不通，正是这类项目最常见的失败模式。

- 握手版本协商与 `resumed` 语义；同 session_id 认作续连、不同则强制重置；
- 192 KiB 分帧载荷按 offset 重组后与原文一致；
- **Resume 对齐：helper 按客户端声明的接收偏移精确重发缺口，重建的字节流与原文逐字节相同**——"掉包恢复"在两个实现之间真正互通；
- 允许列表拒绝 → `Forbidden`；出口不可达 → `ConnectFailed`；
- 未知流的数据被 `Reset` 而非静默忽略；Ping/Pong 互通；
- FIN 是半关闭：客户端停发后目标仍能把剩余数据发回。

集成测试起真实 socket，因此 CI 里额外用 `--test-threads 1` 串行跑一遍，确认没有端口或时序耦合。

## 已知限制

- **UDP 不支持。** SOCKS5 `UDP ASSOCIATE` 返回 `0x07`。SSH 只提供可靠字节流，转发 UDP 需要在 helper 侧封装，当前未实现。
- **SOCKS5 `BIND` 不支持**，返回 `0x07`。
- `direct-tcpip` 模式下已建立的长流无法在断网后续传（见上文，协议边界）。
- **helper 模式的续传边界。** 协议、状态机与两端实现都已完成并通过互操作测试
  （见上文 `helper_wire_interop.rs`：Resume 能精确重发缺口且零字节丢失）。
  但当前客户端在每次 SSH 通道重建时都会 `exec` 一个**新的** helper 进程，
  新进程没有旧状态，必然回复 `resumed=false`，客户端据此重置所有旧流并
  如实通知上层——而不是静默丢数据。

  因此**跨越一次真实断网的字节级续传尚未打通**，缺的不是续传机制，
  而是让 helper 在断网后活下来（detach + Unix socket 重附着）。
  已经生效的部分：同一 helper 进程内的通道重建可续传；断网期间新到达的
  请求排队等待而非失败。
- 重传缓冲占用内存 = 活跃流数 × `stream_window`。默认 4 MiB/流，大量并发流时需要下调。
