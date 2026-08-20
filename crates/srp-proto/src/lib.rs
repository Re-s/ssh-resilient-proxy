//! `srp-proto`：srp 客户端与远端 helper 共享的线协议与续传状态机。
//!
//! 这个 crate 刻意不含任何 I/O 与 SSH 依赖，只做纯数据结构与状态转换，
//! 因此可以被单元测试完整覆盖，也能被客户端和 helper 同时复用。

pub mod addr;
pub mod frame;
pub mod resume;

pub use addr::TargetAddr;
pub use frame::{
    Frame, ResetCode, SessionId, StreamId, DATA_CHUNK, DEFAULT_STREAM_WINDOW, HEADER_LEN,
    MAX_FRAME_PAYLOAD, PROTO_VERSION,
};
pub use resume::{RecvTracker, ResumeError, SendBuffer};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtoError {
    #[error("buffer truncated")]
    Truncated,
    #[error("unknown address kind {0}")]
    BadAddrKind(u8),
    #[error("invalid domain name")]
    BadDomain,
    #[error("unknown frame type 0x{0:02x}")]
    BadFrameType(u8),
    #[error("frame payload too large: {0} bytes")]
    FrameTooLarge(usize),
    #[error("protocol version mismatch: local {local}, peer {peer}")]
    VersionMismatch { local: u8, peer: u8 },
}
