//! `srp` 多路复用帧协议（仅在 helper 模式下使用）。
//!
//! 该协议运行在一条 SSH `session` 通道的 stdin/stdout 之上。SSH 已经提供
//! 机密性、完整性与顺序保证，所以这一层只解决 SSH **无法**解决的问题：
//! 当底层 TCP 连接断掉、SSH 会话整体重建之后，如何让上层的每一条 TCP 流
//! **字节级续传**而不是被迫重置。
//!
//! 做法是经典的"带确认序号的重传缓冲"：
//!
//! * 每条逻辑流的发送方为自己发出的字节维护一个单调递增的 `offset`；
//! * 未被对端 `Ack` 的字节留在重传缓冲里；
//! * 重连后双方交换各自的"已接收字节数"（`Resume` / `ResumeOk`），
//!   发送方据此回退并重发缺口部分。
//!
//! 因此"掉包恢复"在这里是确定性的：只要重传缓冲没有溢出，
//! 重连期间的字节丢失量为零。
//!
//! ## 线格式
//!
//! ```text
//! +--------+-----------+--------+===============+
//! | type   | stream_id | len    | payload       |
//! | 1 byte | 4 bytes   | 4 bytes| `len` bytes   |
//! +--------+-----------+--------+===============+
//! ```
//!
//! 所有整数为网络字节序（大端）。与流无关的帧（`Hello`/`Ping`）把
//! `stream_id` 置 0。

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{ProtoError, TargetAddr};

/// 协议版本。双方不一致时立即断开，不做隐式降级。
pub const PROTO_VERSION: u8 = 1;

/// 帧头长度：type(1) + stream_id(4) + len(4)。
pub const HEADER_LEN: usize = 9;

/// 单帧载荷上限。超过即视为对端异常或协议不同步，直接报错而不是尝试恢复。
pub const MAX_FRAME_PAYLOAD: usize = 256 * 1024;

/// 单次 `Data` 帧携带的目标字节数。
///
/// 32 KiB 在吞吐与重连粒度之间折中：太大则重传浪费，太小则帧头开销占比升高。
pub const DATA_CHUNK: usize = 32 * 1024;

/// 每条流默认允许的"已发送但未确认"字节数上限，同时也是重传缓冲的容量。
///
/// 这个值直接决定断线可恢复的数据量：重连时若对端缺口超过它，
/// 该流无法续传、只能重置。
pub const DEFAULT_STREAM_WINDOW: u64 = 4 * 1024 * 1024;

/// 会话标识，用于让远端 helper 认出"这是同一个逻辑会话在重连"。
pub type SessionId = [u8; 16];

/// 逻辑流标识。由客户端分配，奇偶性无特殊含义（仅客户端发起流）。
pub type StreamId = u32;

/// 流终止/拒绝原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResetCode {
    /// 正常关闭。
    Normal = 0,
    /// 出口 TCP 连接失败（DNS 失败、拒绝连接、超时）。
    ConnectFailed = 1,
    /// 对端不认识这个流（多半是重连后 helper 已重启）。
    UnknownStream = 2,
    /// 重传缓冲已无法覆盖对端缺口，续传不可能。
    ResumeImpossible = 3,
    /// helper 侧内部错误。
    Internal = 4,
    /// 策略拒绝（目标不在允许列表内）。
    Forbidden = 5,
}

impl ResetCode {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Normal,
            1 => Self::ConnectFailed,
            2 => Self::UnknownStream,
            3 => Self::ResumeImpossible,
            5 => Self::Forbidden,
            _ => Self::Internal,
        }
    }
}

mod ty {
    pub const HELLO: u8 = 0x01;
    pub const HELLO_ACK: u8 = 0x02;
    pub const OPEN: u8 = 0x10;
    pub const OPEN_OK: u8 = 0x11;
    pub const OPEN_ERR: u8 = 0x12;
    pub const DATA: u8 = 0x20;
    pub const ACK: u8 = 0x21;
    pub const FIN: u8 = 0x22;
    pub const RESET: u8 = 0x23;
    pub const RESUME: u8 = 0x30;
    pub const RESUME_OK: u8 = 0x31;
    pub const RESUME_ERR: u8 = 0x32;
    pub const PING: u8 = 0x40;
    pub const PONG: u8 = 0x41;
}

/// 一个协议帧。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// 客户端 → helper：握手。`resume = true` 表示这是既有会话的重连。
    Hello {
        version: u8,
        session_id: SessionId,
        resume: bool,
    },
    /// helper → 客户端：握手应答。`resumed = true` 表示 helper 认出了会话
    /// 并保留了流状态；为 false 时客户端必须把所有旧流当作已失效。
    HelloAck {
        version: u8,
        session_id: SessionId,
        resumed: bool,
    },
    /// 请求 helper 建立一条到 `addr` 的出口 TCP 连接。
    Open {
        stream_id: StreamId,
        addr: TargetAddr,
    },
    /// 出口连接已建立。
    OpenOk {
        stream_id: StreamId,
    },
    /// 出口连接失败。
    OpenErr {
        stream_id: StreamId,
        code: ResetCode,
        msg: String,
    },
    /// 流数据。`offset` 是本帧首字节在该流发送序列中的绝对位置。
    Data {
        stream_id: StreamId,
        offset: u64,
        data: Bytes,
    },
    /// 累积确认：已成功接收并交付 `offset` 个字节。
    Ack {
        stream_id: StreamId,
        offset: u64,
    },
    /// 发送方半关闭（对应 TCP FIN）。
    Fin {
        stream_id: StreamId,
    },
    /// 流终止，双向立即失效。
    Reset {
        stream_id: StreamId,
        code: ResetCode,
    },
    /// 重连后声明：我这一侧已收到该流 `recv_offset` 字节，请从此处续发。
    Resume {
        stream_id: StreamId,
        recv_offset: u64,
    },
    /// 重连应答：流仍存活，且我这一侧已收到 `recv_offset` 字节。
    ResumeOk {
        stream_id: StreamId,
        recv_offset: u64,
    },
    /// 重连应答：该流无法续传。
    ResumeErr {
        stream_id: StreamId,
        code: ResetCode,
    },
    /// 保活探测。
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
}

impl Frame {
    /// 与该帧关联的流；无关联时为 `None`。
    pub fn stream_id(&self) -> Option<StreamId> {
        match self {
            Self::Hello { .. } | Self::HelloAck { .. } | Self::Ping { .. } | Self::Pong { .. } => {
                None
            }
            Self::Open { stream_id, .. }
            | Self::OpenOk { stream_id }
            | Self::OpenErr { stream_id, .. }
            | Self::Data { stream_id, .. }
            | Self::Ack { stream_id, .. }
            | Self::Fin { stream_id }
            | Self::Reset { stream_id, .. }
            | Self::Resume { stream_id, .. }
            | Self::ResumeOk { stream_id, .. }
            | Self::ResumeErr { stream_id, .. } => Some(*stream_id),
        }
    }

    /// 把帧追加编码到 `dst`。
    pub fn encode(&self, dst: &mut BytesMut) {
        // 先写入头部占位，载荷写完后回填长度，避免预先计算长度时算错。
        let write = |dst: &mut BytesMut, ty: u8, sid: StreamId, body: &dyn Fn(&mut BytesMut)| {
            dst.put_u8(ty);
            dst.put_u32(sid);
            let len_pos = dst.len();
            dst.put_u32(0);
            let body_start = dst.len();
            body(dst);
            let body_len = (dst.len() - body_start) as u32;
            dst[len_pos..len_pos + 4].copy_from_slice(&body_len.to_be_bytes());
        };

        match self {
            Self::Hello {
                version,
                session_id,
                resume,
            } => write(dst, ty::HELLO, 0, &|d| {
                d.put_u8(*version);
                d.put_slice(session_id);
                d.put_u8(u8::from(*resume));
            }),
            Self::HelloAck {
                version,
                session_id,
                resumed,
            } => write(dst, ty::HELLO_ACK, 0, &|d| {
                d.put_u8(*version);
                d.put_slice(session_id);
                d.put_u8(u8::from(*resumed));
            }),
            Self::Open { stream_id, addr } => write(dst, ty::OPEN, *stream_id, &|d| addr.encode(d)),
            Self::OpenOk { stream_id } => write(dst, ty::OPEN_OK, *stream_id, &|_| {}),
            Self::OpenErr {
                stream_id,
                code,
                msg,
            } => write(dst, ty::OPEN_ERR, *stream_id, &|d| {
                d.put_u8(*code as u8);
                let bytes = msg.as_bytes();
                let n = bytes.len().min(u16::MAX as usize);
                d.put_u16(n as u16);
                d.put_slice(&bytes[..n]);
            }),
            Self::Data {
                stream_id,
                offset,
                data,
            } => write(dst, ty::DATA, *stream_id, &|d| {
                d.put_u64(*offset);
                d.put_slice(data);
            }),
            Self::Ack { stream_id, offset } => write(dst, ty::ACK, *stream_id, &|d| {
                d.put_u64(*offset);
            }),
            Self::Fin { stream_id } => write(dst, ty::FIN, *stream_id, &|_| {}),
            Self::Reset { stream_id, code } => write(dst, ty::RESET, *stream_id, &|d| {
                d.put_u8(*code as u8);
            }),
            Self::Resume {
                stream_id,
                recv_offset,
            } => write(dst, ty::RESUME, *stream_id, &|d| {
                d.put_u64(*recv_offset);
            }),
            Self::ResumeOk {
                stream_id,
                recv_offset,
            } => write(dst, ty::RESUME_OK, *stream_id, &|d| {
                d.put_u64(*recv_offset);
            }),
            Self::ResumeErr { stream_id, code } => write(dst, ty::RESUME_ERR, *stream_id, &|d| {
                d.put_u8(*code as u8);
            }),
            Self::Ping { nonce } => write(dst, ty::PING, 0, &|d| d.put_u64(*nonce)),
            Self::Pong { nonce } => write(dst, ty::PONG, 0, &|d| d.put_u64(*nonce)),
        }
    }

    /// 尝试从 `src` 头部解析一帧。
    ///
    /// * `Ok(Some(frame))`：解析成功，已消耗对应字节。
    /// * `Ok(None)`：数据不足，`src` 未被修改，等待更多字节。
    /// * `Err(..)`：协议违规，调用方应终止该 SSH 通道。
    pub fn decode(src: &mut BytesMut) -> Result<Option<Self>, ProtoError> {
        if src.len() < HEADER_LEN {
            return Ok(None);
        }
        let ty = src[0];
        let stream_id = u32::from_be_bytes([src[1], src[2], src[3], src[4]]);
        let len = u32::from_be_bytes([src[5], src[6], src[7], src[8]]) as usize;
        if len > MAX_FRAME_PAYLOAD {
            return Err(ProtoError::FrameTooLarge(len));
        }
        if src.len() < HEADER_LEN + len {
            return Ok(None);
        }
        src.advance(HEADER_LEN);
        let mut body = src.split_to(len);

        let need = |b: &BytesMut, n: usize| -> Result<(), ProtoError> {
            if b.remaining() < n {
                Err(ProtoError::Truncated)
            } else {
                Ok(())
            }
        };

        let frame = match ty {
            ty::HELLO | ty::HELLO_ACK => {
                need(&body, 18)?;
                let version = body.get_u8();
                let mut session_id = [0u8; 16];
                body.copy_to_slice(&mut session_id);
                let flag = body.get_u8() != 0;
                if ty == ty::HELLO {
                    Self::Hello {
                        version,
                        session_id,
                        resume: flag,
                    }
                } else {
                    Self::HelloAck {
                        version,
                        session_id,
                        resumed: flag,
                    }
                }
            }
            ty::OPEN => Self::Open {
                stream_id,
                addr: TargetAddr::decode(&mut body)?,
            },
            ty::OPEN_OK => Self::OpenOk { stream_id },
            ty::OPEN_ERR => {
                need(&body, 3)?;
                let code = ResetCode::from_u8(body.get_u8());
                let n = body.get_u16() as usize;
                need(&body, n)?;
                let mut buf = vec![0u8; n];
                body.copy_to_slice(&mut buf);
                Self::OpenErr {
                    stream_id,
                    code,
                    msg: String::from_utf8_lossy(&buf).into_owned(),
                }
            }
            ty::DATA => {
                need(&body, 8)?;
                let offset = body.get_u64();
                Self::Data {
                    stream_id,
                    offset,
                    data: body.split().freeze(),
                }
            }
            ty::ACK => {
                need(&body, 8)?;
                Self::Ack {
                    stream_id,
                    offset: body.get_u64(),
                }
            }
            ty::FIN => Self::Fin { stream_id },
            ty::RESET => {
                need(&body, 1)?;
                Self::Reset {
                    stream_id,
                    code: ResetCode::from_u8(body.get_u8()),
                }
            }
            ty::RESUME => {
                need(&body, 8)?;
                Self::Resume {
                    stream_id,
                    recv_offset: body.get_u64(),
                }
            }
            ty::RESUME_OK => {
                need(&body, 8)?;
                Self::ResumeOk {
                    stream_id,
                    recv_offset: body.get_u64(),
                }
            }
            ty::RESUME_ERR => {
                need(&body, 1)?;
                Self::ResumeErr {
                    stream_id,
                    code: ResetCode::from_u8(body.get_u8()),
                }
            }
            ty::PING | ty::PONG => {
                need(&body, 8)?;
                let nonce = body.get_u64();
                if ty == ty::PING {
                    Self::Ping { nonce }
                } else {
                    Self::Pong { nonce }
                }
            }
            other => return Err(ProtoError::BadFrameType(other)),
        };
        Ok(Some(frame))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_frames() -> Vec<Frame> {
        vec![
            Frame::Hello {
                version: PROTO_VERSION,
                session_id: [7u8; 16],
                resume: true,
            },
            Frame::HelloAck {
                version: PROTO_VERSION,
                session_id: [7u8; 16],
                resumed: false,
            },
            Frame::Open {
                stream_id: 3,
                addr: TargetAddr::Domain("example.com".into(), 443),
            },
            Frame::OpenOk { stream_id: 3 },
            Frame::OpenErr {
                stream_id: 3,
                code: ResetCode::ConnectFailed,
                msg: "connection refused".into(),
            },
            Frame::Data {
                stream_id: 3,
                offset: 4096,
                data: Bytes::from_static(b"hello world"),
            },
            Frame::Ack {
                stream_id: 3,
                offset: 4107,
            },
            Frame::Fin { stream_id: 3 },
            Frame::Reset {
                stream_id: 3,
                code: ResetCode::Normal,
            },
            Frame::Resume {
                stream_id: 3,
                recv_offset: 99,
            },
            Frame::ResumeOk {
                stream_id: 3,
                recv_offset: 100,
            },
            Frame::ResumeErr {
                stream_id: 3,
                code: ResetCode::ResumeImpossible,
            },
            Frame::Ping { nonce: 1234 },
            Frame::Pong { nonce: 1234 },
        ]
    }

    #[test]
    fn roundtrips_every_frame_type() {
        for f in all_frames() {
            let mut buf = BytesMut::new();
            f.encode(&mut buf);
            let decoded = Frame::decode(&mut buf)
                .expect("decode ok")
                .expect("complete");
            assert_eq!(decoded, f, "roundtrip mismatch");
            assert!(buf.is_empty(), "leftover bytes after {f:?}");
        }
    }

    #[test]
    fn decodes_a_pipelined_stream_in_order() {
        let frames = all_frames();
        let mut buf = BytesMut::new();
        for f in &frames {
            f.encode(&mut buf);
        }
        let mut out = Vec::new();
        while let Some(f) = Frame::decode(&mut buf).expect("decode ok") {
            out.push(f);
        }
        assert_eq!(out, frames);
        assert!(buf.is_empty());
    }

    /// 逐字节喂入：验证解码器对任意 TCP 分片边界都不会误判或丢帧。
    #[test]
    fn tolerates_arbitrary_fragmentation() {
        let frames = all_frames();
        let mut wire = BytesMut::new();
        for f in &frames {
            f.encode(&mut wire);
        }
        let wire = wire.freeze();

        let mut buf = BytesMut::new();
        let mut out = Vec::new();
        for byte in wire.iter() {
            buf.put_u8(*byte);
            while let Some(f) = Frame::decode(&mut buf).expect("decode ok") {
                out.push(f);
            }
        }
        assert_eq!(out, frames);
    }

    #[test]
    fn returns_none_on_partial_header() {
        let mut buf = BytesMut::from(&[ty::DATA, 0, 0][..]);
        assert_eq!(Frame::decode(&mut buf).unwrap(), None);
        assert_eq!(buf.len(), 3, "src must be untouched when incomplete");
    }

    #[test]
    fn rejects_oversized_and_unknown_frames() {
        let mut buf = BytesMut::new();
        buf.put_u8(ty::DATA);
        buf.put_u32(1);
        buf.put_u32(MAX_FRAME_PAYLOAD as u32 + 1);
        assert!(matches!(
            Frame::decode(&mut buf),
            Err(ProtoError::FrameTooLarge(_))
        ));

        let mut buf = BytesMut::new();
        buf.put_u8(0xEE);
        buf.put_u32(0);
        buf.put_u32(0);
        assert!(matches!(
            Frame::decode(&mut buf),
            Err(ProtoError::BadFrameType(0xEE))
        ));
    }

    #[test]
    fn rejects_truncated_payload_body() {
        // 声明 2 字节载荷，但 ACK 需要 8 字节。
        let mut buf = BytesMut::new();
        buf.put_u8(ty::ACK);
        buf.put_u32(1);
        buf.put_u32(2);
        buf.put_slice(&[0, 0]);
        assert!(matches!(
            Frame::decode(&mut buf),
            Err(ProtoError::Truncated)
        ));
    }

    #[test]
    fn empty_data_frame_is_valid() {
        let f = Frame::Data {
            stream_id: 1,
            offset: 0,
            data: Bytes::new(),
        };
        let mut buf = BytesMut::new();
        f.encode(&mut buf);
        assert_eq!(buf.len(), HEADER_LEN + 8);
        assert_eq!(Frame::decode(&mut buf).unwrap().unwrap(), f);
    }

    #[test]
    fn stream_id_association_is_reported() {
        assert_eq!(Frame::Ping { nonce: 0 }.stream_id(), None);
        assert_eq!(Frame::Fin { stream_id: 42 }.stream_id(), Some(42));
    }
}
