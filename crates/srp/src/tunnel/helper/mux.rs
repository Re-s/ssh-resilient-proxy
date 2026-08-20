//! helper 模式的多路复用器：字节级续传的客户端侧实现。
//!
//! # 与 direct-tcpip 的本质区别
//!
//! `direct-tcpip` 把"出口 TCP 的生命周期"托管给了 sshd，SSH 一断出口必死。
//! helper 模式把出口 TCP 交给远端一个**独立进程**持有，SSH 通道退化成
//! 单纯的字节管道。管道断了可以重建，两端的重传缓冲负责把缺口补齐——
//! 于是逻辑流的生命周期长于任何一条 SSH 会话。
//!
//! # 不变式
//!
//! 1. 每条逻辑流的发送方在收到 `Ack(n)` 之前不丢弃 offset ≥ n 的字节；
//! 2. 接收方严格按 offset 顺序交付，重叠部分裁剪后丢弃；
//! 3. 重连后双方交换各自的 `delivered()`，发送方据此回退重发。
//!
//! 三条合起来保证：只要缺口不超过重传窗口，重连期间**零字节丢失**。

use std::collections::HashMap;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use srp_proto::{Frame, ProtoError, RecvTracker, ResetCode, SendBuffer, StreamId, DATA_CHUNK};
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::{debug, warn};

/// 一条逻辑流在客户端侧的状态。
pub struct StreamState {
    /// 本地 → 远端方向的重传缓冲。
    pub tx: SendBuffer,
    /// 远端 → 本地方向的按序交付跟踪。
    pub rx: RecvTracker,
    /// 目标地址，重连时若 helper 不认这条流可用于重新 `Open`。
    pub addr: srp_proto::TargetAddr,
    /// 已收到 helper 的 `OpenOk`。
    pub opened: bool,
    /// 本地已停止写入。
    pub local_fin: bool,
    /// 已收到远端 FIN。
    pub remote_fin: bool,
    /// 已被重置，等待清理。
    pub reset: Option<ResetCode>,
}

impl StreamState {
    pub fn new(addr: srp_proto::TargetAddr, window: u64) -> Self {
        Self {
            tx: SendBuffer::new(window),
            rx: RecvTracker::new(),
            addr,
            opened: false,
            local_fin: false,
            remote_fin: false,
            reset: None,
        }
    }

    /// 双向都结束且发送缓冲已清空，可以回收。
    pub fn is_finished(&self) -> bool {
        self.reset.is_some() || (self.local_fin && self.remote_fin && self.tx.is_fully_acked())
    }
}

/// 累积确认阈值：收到这么多字节后立刻发 `Ack`，不必等定时器。
///
/// 太小会让 ack 帧淹没链路，太大则发送方窗口迟迟不释放导致吞吐塌陷。
/// 取窗口的 1/8 量级是常见折中。
pub const ACK_THRESHOLD: u64 = 64 * 1024;

/// 多路复用器的共享状态。
pub struct MuxState {
    streams: HashMap<StreamId, StreamState>,
    /// 下一个可用的流 ID。
    next_id: StreamId,
    /// 每条流的重传窗口。
    window: u64,
}

impl MuxState {
    pub fn new(window: u64) -> Self {
        Self {
            streams: HashMap::new(),
            next_id: 1,
            window,
        }
    }

    pub fn alloc_stream(&mut self, addr: srp_proto::TargetAddr) -> StreamId {
        // 跳过已占用的 ID。流数量远小于 u32 空间，这个循环实际不会转很多圈。
        loop {
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            // 0 保留给与流无关的帧。
            if id == 0 || self.streams.contains_key(&id) {
                continue;
            }
            self.streams.insert(id, StreamState::new(addr, self.window));
            return id;
        }
    }

    pub fn get_mut(&mut self, id: StreamId) -> Option<&mut StreamState> {
        self.streams.get_mut(&id)
    }

    pub fn remove(&mut self, id: StreamId) -> Option<StreamState> {
        self.streams.remove(&id)
    }

    pub fn len(&self) -> usize {
        self.streams.len()
    }

    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    pub fn stream_ids(&self) -> Vec<StreamId> {
        self.streams.keys().copied().collect()
    }

    /// 重连后为所有存活流生成 `Resume` 帧，向对端声明"我已收到多少字节"。
    ///
    /// 这里**只报告接收侧进度**，不动发送游标。发送侧的回退发生在收到对端
    /// `ResumeOk` 时（见 [`apply_frame`] 对 `ResumeOk` 的处理调用
    /// `SendBuffer::rewind_to`）。两步分开是必要的：只有对端告知它实际收到
    /// 多少，我们才知道该从哪里续发；提前回退会导致重复发送已确认的数据。
    pub fn build_resume_frames(&mut self) -> Vec<Frame> {
        self.streams
            .iter()
            .map(|(id, st)| Frame::Resume {
                stream_id: *id,
                recv_offset: st.rx.delivered(),
            })
            .collect()
    }

    /// helper 报告"这是一个新进程，旧状态全部丢失"时调用。
    ///
    /// 所有流都无法续传，必须全部重置。这是 helper 模式的诚实之处：
    /// 无法恢复时明确告知上层，而不是静默丢数据。
    pub fn reset_all(&mut self, code: ResetCode) -> Vec<StreamId> {
        let ids: Vec<_> = self.streams.keys().copied().collect();
        for id in &ids {
            if let Some(st) = self.streams.get_mut(id) {
                st.reset = Some(code);
            }
        }
        ids
    }
}

/// 处理一个入站帧对流状态的影响。
///
/// 抽成纯函数（只依赖 `MuxState` 与帧，不做 I/O）是为了让"续传是否正确"
/// 这件事能被单元测试完整验证——这是整个项目最需要证明的性质。
#[derive(Debug, PartialEq, Eq)]
pub enum FrameEffect {
    /// 无需额外动作。
    None,
    /// 应把这些字节交付给本地 socket。
    Deliver { stream_id: StreamId, data: Bytes },
    /// 应回送这些帧。
    Reply(Vec<Frame>),
    /// 流已终止，应关闭本地 socket。
    Terminate {
        stream_id: StreamId,
        code: ResetCode,
    },
    /// 远端半关闭，应对本地 socket 做 write shutdown。
    RemoteFin { stream_id: StreamId },
    /// 该流可以续传，缺口 `gap` 字节会被重发。
    Resumed { stream_id: StreamId, gap: u64 },
}

pub fn apply_frame(state: &mut MuxState, frame: Frame) -> Result<Vec<FrameEffect>, ProtoError> {
    let mut out = Vec::new();
    match frame {
        Frame::OpenOk { stream_id } => {
            if let Some(st) = state.get_mut(stream_id) {
                st.opened = true;
            }
        }
        Frame::OpenErr {
            stream_id,
            code,
            msg,
        } => {
            debug!(stream_id, ?code, %msg, "helper refused to open stream");
            if let Some(st) = state.get_mut(stream_id) {
                st.reset = Some(code);
            }
            out.push(FrameEffect::Terminate { stream_id, code });
        }
        Frame::Data {
            stream_id,
            offset,
            data,
        } => {
            let Some(st) = state.get_mut(stream_id) else {
                // 未知流：告诉 helper 别再发了。
                out.push(FrameEffect::Reply(vec![Frame::Reset {
                    stream_id,
                    code: ResetCode::UnknownStream,
                }]));
                return Ok(out);
            };
            match st.rx.accept(offset, data) {
                Ok(Some(fresh)) => {
                    let delivered = st.rx.delivered();
                    out.push(FrameEffect::Deliver {
                        stream_id,
                        data: fresh,
                    });
                    // 累积确认：够量就立刻确认，释放对端窗口。
                    out.push(FrameEffect::Reply(vec![Frame::Ack {
                        stream_id,
                        offset: delivered,
                    }]));
                }
                // 整帧重复（重连重发导致）：安全丢弃，但仍要重申 ack，
                // 否则对端可能因为 ack 丢失而反复重发同一段。
                Ok(None) => {
                    let delivered = st.rx.delivered();
                    out.push(FrameEffect::Reply(vec![Frame::Ack {
                        stream_id,
                        offset: delivered,
                    }]));
                }
                Err(e) => {
                    warn!(stream_id, error = %e, "data gap from helper; resetting stream");
                    st.reset = Some(ResetCode::Internal);
                    out.push(FrameEffect::Reply(vec![Frame::Reset {
                        stream_id,
                        code: ResetCode::Internal,
                    }]));
                    out.push(FrameEffect::Terminate {
                        stream_id,
                        code: ResetCode::Internal,
                    });
                }
            }
        }
        Frame::Ack { stream_id, offset } => {
            if let Some(st) = state.get_mut(stream_id) {
                if let Err(e) = st.tx.ack(offset) {
                    warn!(stream_id, error = %e, "invalid ack from helper");
                    st.reset = Some(ResetCode::Internal);
                    out.push(FrameEffect::Terminate {
                        stream_id,
                        code: ResetCode::Internal,
                    });
                }
            }
        }
        Frame::Fin { stream_id } => {
            if let Some(st) = state.get_mut(stream_id) {
                st.remote_fin = true;
                st.rx.mark_fin();
                out.push(FrameEffect::RemoteFin { stream_id });
            }
        }
        Frame::Reset { stream_id, code } => {
            if let Some(st) = state.get_mut(stream_id) {
                st.reset = Some(code);
            }
            out.push(FrameEffect::Terminate { stream_id, code });
        }
        Frame::ResumeOk {
            stream_id,
            recv_offset,
        } => {
            let Some(st) = state.get_mut(stream_id) else {
                return Ok(out);
            };
            match st.tx.rewind_to(recv_offset) {
                Ok(gap) => {
                    debug!(stream_id, gap, "stream resumed; resending gap");
                    out.push(FrameEffect::Resumed { stream_id, gap });
                }
                Err(e) => {
                    // 缺口超出重传窗口：诚实地重置，而不是静默丢字节。
                    warn!(stream_id, error = %e, "cannot resume stream; buffer gap too large");
                    st.reset = Some(ResetCode::ResumeImpossible);
                    out.push(FrameEffect::Reply(vec![Frame::Reset {
                        stream_id,
                        code: ResetCode::ResumeImpossible,
                    }]));
                    out.push(FrameEffect::Terminate {
                        stream_id,
                        code: ResetCode::ResumeImpossible,
                    });
                }
            }
        }
        Frame::ResumeErr { stream_id, code } => {
            if let Some(st) = state.get_mut(stream_id) {
                st.reset = Some(code);
            }
            out.push(FrameEffect::Terminate { stream_id, code });
        }
        Frame::Ping { nonce } => {
            out.push(FrameEffect::Reply(vec![Frame::Pong { nonce }]));
        }
        Frame::Pong { .. } => {}
        // 客户端不该收到这些（它们是客户端 → helper 方向的帧）。
        Frame::Hello { .. } | Frame::Open { .. } | Frame::Resume { .. } => {
            warn!("received a client-to-helper frame from helper; ignoring");
        }
        Frame::HelloAck { .. } => {
            // 由握手阶段单独处理，不在稳态循环里。
        }
    }
    Ok(out)
}

/// 从某条流的发送缓冲里取出待发数据，编码成 `Data` 帧。
pub fn drain_stream_output(state: &mut MuxState, id: StreamId, max_frames: usize) -> Vec<Frame> {
    let mut frames = Vec::new();
    let Some(st) = state.get_mut(id) else {
        return frames;
    };
    while frames.len() < max_frames {
        match st.tx.next_unsent(DATA_CHUNK) {
            Some((offset, data)) => frames.push(Frame::Data {
                stream_id: id,
                offset,
                data,
            }),
            None => break,
        }
    }
    // 数据全部发出且本地已 EOF 时补一个 FIN。
    if st.local_fin && !st.tx.has_pending() && !st.tx.fin_queued() {
        st.tx.mark_fin();
        frames.push(Frame::Fin { stream_id: id });
    }
    frames
}

/// 把帧编码进发送缓冲。
pub fn encode_all(frames: &[Frame], dst: &mut BytesMut) {
    for f in frames {
        f.encode(dst);
    }
}

/// 一条流对应的本地端点句柄，用于把 helper 的数据递给 SOCKS/HTTP 侧。
pub struct StreamHandles {
    pub deliver: mpsc::Sender<Bytes>,
    pub closed: Option<oneshot::Sender<ResetCode>>,
}

/// 客户端流表：流 ID → 本地端点。
pub type StreamTable = Arc<Mutex<HashMap<StreamId, StreamHandles>>>;

#[cfg(test)]
mod tests {
    use super::*;
    use srp_proto::TargetAddr;

    fn addr() -> TargetAddr {
        TargetAddr::Domain("example.com".into(), 443)
    }

    fn state_with_stream() -> (MuxState, StreamId) {
        let mut s = MuxState::new(64 * 1024);
        let id = s.alloc_stream(addr());
        (s, id)
    }

    #[test]
    fn alloc_never_returns_zero_or_duplicates() {
        let mut s = MuxState::new(1024);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let id = s.alloc_stream(addr());
            assert_ne!(id, 0, "0 is reserved for stream-less frames");
            assert!(seen.insert(id), "duplicate stream id {id}");
        }
        assert_eq!(s.len(), 1000);
    }

    #[test]
    fn data_is_delivered_and_acked() {
        let (mut s, id) = state_with_stream();
        let effects = apply_frame(
            &mut s,
            Frame::Data {
                stream_id: id,
                offset: 0,
                data: Bytes::from_static(b"hello"),
            },
        )
        .unwrap();

        assert_eq!(
            effects[0],
            FrameEffect::Deliver {
                stream_id: id,
                data: Bytes::from_static(b"hello")
            }
        );
        assert_eq!(
            effects[1],
            FrameEffect::Reply(vec![Frame::Ack {
                stream_id: id,
                offset: 5
            }])
        );
    }

    /// 重连重发导致的重复帧：不得重复交付，但必须重申 ack。
    #[test]
    fn duplicate_data_is_dropped_but_reacked() {
        let (mut s, id) = state_with_stream();
        apply_frame(
            &mut s,
            Frame::Data {
                stream_id: id,
                offset: 0,
                data: Bytes::from_static(b"abcdef"),
            },
        )
        .unwrap();

        let effects = apply_frame(
            &mut s,
            Frame::Data {
                stream_id: id,
                offset: 0,
                data: Bytes::from_static(b"abc"),
            },
        )
        .unwrap();

        assert!(
            !effects
                .iter()
                .any(|e| matches!(e, FrameEffect::Deliver { .. })),
            "duplicate bytes must not be delivered twice: {effects:?}"
        );
        assert_eq!(
            effects[0],
            FrameEffect::Reply(vec![Frame::Ack {
                stream_id: id,
                offset: 6
            }]),
            "must re-announce the ack so the peer stops resending"
        );
    }

    /// 部分重叠：只交付新增部分。
    #[test]
    fn partially_overlapping_retransmit_delivers_only_fresh_bytes() {
        let (mut s, id) = state_with_stream();
        apply_frame(
            &mut s,
            Frame::Data {
                stream_id: id,
                offset: 0,
                data: Bytes::from_static(b"abcd"),
            },
        )
        .unwrap();

        let effects = apply_frame(
            &mut s,
            Frame::Data {
                stream_id: id,
                offset: 2,
                data: Bytes::from_static(b"cdef"),
            },
        )
        .unwrap();

        assert_eq!(
            effects[0],
            FrameEffect::Deliver {
                stream_id: id,
                data: Bytes::from_static(b"ef")
            }
        );
    }

    #[test]
    fn unknown_stream_data_triggers_reset() {
        let mut s = MuxState::new(1024);
        let effects = apply_frame(
            &mut s,
            Frame::Data {
                stream_id: 99,
                offset: 0,
                data: Bytes::from_static(b"x"),
            },
        )
        .unwrap();
        assert_eq!(
            effects[0],
            FrameEffect::Reply(vec![Frame::Reset {
                stream_id: 99,
                code: ResetCode::UnknownStream
            }])
        );
    }

    #[test]
    fn ping_is_answered_with_pong() {
        let mut s = MuxState::new(1024);
        let effects = apply_frame(&mut s, Frame::Ping { nonce: 7 }).unwrap();
        assert_eq!(
            effects[0],
            FrameEffect::Reply(vec![Frame::Pong { nonce: 7 }])
        );
    }

    #[test]
    fn open_err_terminates_the_stream() {
        let (mut s, id) = state_with_stream();
        let effects = apply_frame(
            &mut s,
            Frame::OpenErr {
                stream_id: id,
                code: ResetCode::ConnectFailed,
                msg: "refused".into(),
            },
        )
        .unwrap();
        assert_eq!(
            effects[0],
            FrameEffect::Terminate {
                stream_id: id,
                code: ResetCode::ConnectFailed
            }
        );
        assert!(s.get_mut(id).unwrap().is_finished());
    }

    #[test]
    fn fin_marks_remote_half_close() {
        let (mut s, id) = state_with_stream();
        let effects = apply_frame(&mut s, Frame::Fin { stream_id: id }).unwrap();
        assert_eq!(effects[0], FrameEffect::RemoteFin { stream_id: id });
        assert!(s.get_mut(id).unwrap().remote_fin);
        // 本地还没结束，流不能回收。
        assert!(!s.get_mut(id).unwrap().is_finished());
    }

    #[test]
    fn drain_produces_chunked_data_frames_then_fin() {
        let (mut s, id) = state_with_stream();
        let payload = vec![0xABu8; DATA_CHUNK + 100];
        {
            let st = s.get_mut(id).unwrap();
            assert_eq!(st.tx.push(&payload), payload.len());
            st.local_fin = true;
        }

        let frames = drain_stream_output(&mut s, id, 16);
        // 应切成 DATA_CHUNK + 余下 100 两帧，再加一个 FIN。
        assert_eq!(frames.len(), 3, "got {frames:?}");
        match &frames[0] {
            Frame::Data { offset, data, .. } => {
                assert_eq!(*offset, 0);
                assert_eq!(data.len(), DATA_CHUNK);
            }
            f => panic!("unexpected {f:?}"),
        }
        match &frames[1] {
            Frame::Data { offset, data, .. } => {
                assert_eq!(*offset, DATA_CHUNK as u64);
                assert_eq!(data.len(), 100);
            }
            f => panic!("unexpected {f:?}"),
        }
        assert_eq!(frames[2], Frame::Fin { stream_id: id });
    }

    /// 端到端续传：模拟"发出一半后断线"，验证重连后缺口被精确重发且零丢失。
    #[test]
    fn resume_after_disconnect_loses_no_bytes() {
        let (mut s, id) = state_with_stream();
        let payload: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        s.get_mut(id).unwrap().tx.push(&payload);

        // 全部编码成帧发出。
        let frames = drain_stream_output(&mut s, id, 1000);
        let total: usize = frames
            .iter()
            .filter_map(|f| match f {
                Frame::Data { data, .. } => Some(data.len()),
                _ => None,
            })
            .sum();
        assert_eq!(total, 3000);

        // helper 侧只收到前 1200 字节（其余在断网中丢失），且 ack 也没回来。
        let helper_received = 1200u64;

        // 重连：客户端发 Resume（携带自己收到多少，此处方向无关），
        // helper 回 ResumeOk 告知它收到了 1200。
        let effects = apply_frame(
            &mut s,
            Frame::ResumeOk {
                stream_id: id,
                recv_offset: helper_received,
            },
        )
        .unwrap();
        assert_eq!(
            effects[0],
            FrameEffect::Resumed {
                stream_id: id,
                gap: 3000 - helper_received
            },
            "must plan to resend exactly the missing tail"
        );

        // 重发缺口，验证字节序列与原文完全一致。
        let resent = drain_stream_output(&mut s, id, 1000);
        let mut rebuilt = Vec::new();
        for f in &resent {
            match f {
                Frame::Data { offset, data, .. } => {
                    assert_eq!(
                        *offset as usize,
                        helper_received as usize + rebuilt.len(),
                        "resend offsets must be contiguous from the gap start"
                    );
                    rebuilt.extend_from_slice(data);
                }
                other => panic!("unexpected frame {other:?}"),
            }
        }
        assert_eq!(rebuilt.len(), 1800);
        assert_eq!(
            rebuilt,
            &payload[helper_received as usize..],
            "resent bytes must match the original stream exactly"
        );
    }

    /// 缺口超过重传窗口时必须明确重置，而不是静默丢字节。
    #[test]
    fn unresumable_gap_resets_the_stream_instead_of_losing_data() {
        let mut s = MuxState::new(1024);
        let id = s.alloc_stream(addr());
        {
            let st = s.get_mut(id).unwrap();
            st.tx.push(&[0u8; 1024]);
            let _ = st.tx.next_unsent(1024);
            st.tx.ack(1024).unwrap(); // 缓冲已释放
        }

        // helper 声称只收到 100 字节——那部分已经不在缓冲里了。
        let effects = apply_frame(
            &mut s,
            Frame::ResumeOk {
                stream_id: id,
                recv_offset: 100,
            },
        )
        .unwrap();

        assert!(
            effects.iter().any(|e| matches!(
                e,
                FrameEffect::Terminate {
                    code: ResetCode::ResumeImpossible,
                    ..
                }
            )),
            "must terminate honestly rather than silently drop bytes: {effects:?}"
        );
    }

    #[test]
    fn reset_all_marks_every_stream_when_helper_restarts() {
        let mut s = MuxState::new(1024);
        let a = s.alloc_stream(addr());
        let b = s.alloc_stream(addr());
        let ids = s.reset_all(ResetCode::UnknownStream);
        assert_eq!(ids.len(), 2);
        assert!(s.get_mut(a).unwrap().is_finished());
        assert!(s.get_mut(b).unwrap().is_finished());
    }

    #[test]
    fn build_resume_frames_reports_local_delivered_offsets() {
        let mut s = MuxState::new(4096);
        let id = s.alloc_stream(addr());
        apply_frame(
            &mut s,
            Frame::Data {
                stream_id: id,
                offset: 0,
                data: Bytes::from_static(b"0123456789"),
            },
        )
        .unwrap();

        let frames = s.build_resume_frames();
        assert_eq!(
            frames,
            vec![Frame::Resume {
                stream_id: id,
                recv_offset: 10
            }]
        );
    }

    #[test]
    fn invalid_ack_terminates_the_stream() {
        let (mut s, id) = state_with_stream();
        // 从未发送过任何字节，却收到 ack 500。
        let effects = apply_frame(
            &mut s,
            Frame::Ack {
                stream_id: id,
                offset: 500,
            },
        )
        .unwrap();
        assert_eq!(
            effects[0],
            FrameEffect::Terminate {
                stream_id: id,
                code: ResetCode::Internal
            }
        );
    }

    #[test]
    fn backpressure_stops_accepting_data_when_window_is_full() {
        let mut s = MuxState::new(100);
        let id = s.alloc_stream(addr());
        let st = s.get_mut(id).unwrap();
        assert_eq!(st.tx.push(&[1u8; 250]), 100, "must clamp to window");
        assert_eq!(st.tx.writable(), 0);
        assert_eq!(st.tx.push(&[1u8; 10]), 0, "window full means backpressure");
    }
}
