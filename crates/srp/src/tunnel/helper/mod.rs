//! helper 模式：把出口 TCP 托管给远端独立进程，实现字节级续传。
//!
//! [`mux`] 是纯状态机（无 I/O），承载全部续传语义，因此可被完整单测；
//! [`session`] 负责把它接到真实的 SSH 通道与本地 socket 上。

pub mod mux;
pub mod session;

pub use session::HelperDialer;
