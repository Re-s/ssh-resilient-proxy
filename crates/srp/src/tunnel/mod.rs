//! SSH 隧道层：连接保持、断网自愈、以及两种转发模式的 Dialer 实现。
//!
//! 模块划分沿着"变化的理由"切开：
//!
//! * [`config`]：配置解析与安全校验，无 I/O，可纯单测；
//! * [`backoff`]：重连节奏，纯计算；
//! * [`handler`]：russh 回调，承担主机密钥校验这一安全边界；
//! * [`manager`]：会话生命周期与自愈监督循环；
//! * [`direct`]：`direct-tcpip` 模式的 Dialer（零远端依赖）；
//! * [`helper`]：helper 模式的 Dialer（字节级续传）。

#![allow(dead_code)]

pub mod backoff;
pub mod config;
pub mod direct;
pub mod handler;
pub mod helper;
pub mod manager;

pub use config::{Config, HostKeyPolicy, TunnelMode};
pub use direct::DirectTcpipDialer;
pub use helper::HelperDialer;
pub use manager::{TunnelManager, TunnelState};
