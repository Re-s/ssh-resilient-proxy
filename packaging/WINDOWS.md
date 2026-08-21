# srp for Windows 使用说明

## 这个压缩包里有什么

| 文件 | 用途 |
|---|---|
| `srp.exe` | 主程序，在本机跑，你只需要这一个就能用 |
| `srp-helper.exe` | 可选。只有启用 `--helper` 模式时才需要，而且是推到**远端服务器**上运行的 |
| `README.md` | 完整文档 |

Windows 用户绝大多数情况只用 `srp.exe`。

## 最快上手

解压后打开 PowerShell，切到解压目录：

```powershell
.\srp.exe your-user@your-server.com
```

看到这两行就是通了：

```
INFO srp::app: frontend listening frontend="socks5" local=127.0.0.1:1080
INFO srp::tunnel::manager: ssh tunnel established epoch=1
```

然后把浏览器或系统代理指向 `socks5://127.0.0.1:1080`。

按 `Ctrl+C` 退出。

## 认证方式

私钥会自动从 `%USERPROFILE%\.ssh\` 里发现（依次尝试 `id_ed25519`、`id_ecdsa`、`id_rsa`、`id_dsa`）。

指定私钥：

```powershell
.\srp.exe user@host -i $env:USERPROFILE\.ssh\my_key
```

用密码（会出现在命令历史里，建议改用环境变量）：

```powershell
$env:SRP_SSH_PASSWORD = "your-password"
.\srp.exe user@host --password $env:SRP_SSH_PASSWORD
```

### 关于 ssh-agent

Linux 上 `--agent` 走 `SSH_AUTH_SOCK`；Windows 上走的是 **Pageant**（PuTTY 的代理）协议。
如果你用的是 Windows 自带的 OpenSSH agent 服务，`--agent` 可能连不上——这种情况直接用 `-i` 指定私钥文件。

## 常用参数

```powershell
# 换监听端口
.\srp.exe user@host --socks5 127.0.0.1:7890

# 同时开 HTTP CONNECT 入口（给不支持 SOCKS5 的程序用）
.\srp.exe user@host --http 127.0.0.1:8080

# 非标准 SSH 端口
.\srp.exe user@host:2222

# 检查配置但不连接
.\srp.exe user@host check
```

## 开机自启

Windows 没有 systemd。用「任务计划程序」：

1. 打开任务计划程序 → 创建基本任务
2. 触发器选「计算机启动时」
3. 操作选「启动程序」，程序填 `srp.exe` 的完整路径，参数填 `your-user@your-server.com`
4. 在任务属性里勾选「不管用户是否登录都要运行」和「隐藏」

或者用 PowerShell 一条命令注册（把路径和目标换成你自己的）：

```powershell
$action  = New-ScheduledTaskAction -Execute "C:\srp\srp.exe" -Argument "user@host"
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName "srp" -Action $action -Trigger $trigger -RunLevel Highest
```

## 防火墙

默认只监听 `127.0.0.1`，不需要放行任何防火墙规则。

如果你把监听地址改成 `0.0.0.0`（让局域网其他机器也能用），Windows 会弹防火墙提示，而且**任何能访问这个端口的机器都能通过你的服务器转发流量**。这种情况务必加上代理认证：

```powershell
$env:SRP_PROXY_PASSWORD = "secret"
.\srp.exe user@host --socks5 0.0.0.0:1080 --proxy-user alice --proxy-password $env:SRP_PROXY_PASSWORD
```

## 选哪个架构

- `srp_0.2.0_windows_amd64.zip` — 绝大多数 Windows PC（Intel / AMD 处理器）
- `srp_0.2.0_windows_arm64.zip` — ARM 设备（Surface Pro X、骁龙笔记本等）

不确定就看「设置 → 系统 → 系统信息 → 系统类型」。

## 遇到问题

看详细日志：

```powershell
.\srp.exe user@host --log-level debug
```

完整参数列表：

```powershell
.\srp.exe --help
```
