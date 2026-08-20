//! 续传核心：发送侧重传缓冲与接收侧去重。
//!
//! 这是"掉包恢复"的实现所在。整个设计只依赖一个不变式：
//!
//! > **发送方在收到 `Ack(offset)` 之前，绝不丢弃 offset 之后的任何字节。**
//!
//! 于是断线重连后，接收方只需告知"我已收到 N 字节"，发送方即可从 N
//! 精确续发。SSH 会话本身可以整体重建，逻辑流的字节序列不受影响。

use std::collections::VecDeque;

use bytes::{Buf, Bytes};

/// 发送侧重传缓冲。
///
/// 语义上是一个字节窗口 `[acked, acked + len)`：`acked` 之前的字节已被对端
/// 确认并释放，`acked + len` 是下一个待写入字节的绝对偏移。
/// `cursor` 记录"已发往网络"的位置，重连时把它回退到 `acked` 即可触发重发。
#[derive(Debug)]
pub struct SendBuffer {
    /// 对端已累积确认的字节数（该偏移之前的数据可安全丢弃）。
    acked: u64,
    /// 已交给网络层的绝对偏移。始终满足 `acked <= cursor <= acked + buffered`。
    cursor: u64,
    /// 缓冲区容量上限（字节）。
    capacity: u64,
    /// 未确认数据。分块保存以避免频繁的大块内存搬移。
    chunks: VecDeque<Bytes>,
    /// `chunks` 内的总字节数。
    buffered: u64,
    /// 本地已停止写入（应用层 EOF）。
    fin_queued: bool,
}

impl SendBuffer {
    pub fn new(capacity: u64) -> Self {
        assert!(capacity > 0, "capacity must be positive");
        Self {
            acked: 0,
            cursor: 0,
            capacity,
            chunks: VecDeque::new(),
            buffered: 0,
            fin_queued: false,
        }
    }

    /// 已确认偏移。
    pub fn acked(&self) -> u64 {
        self.acked
    }

    /// 下一个待写入字节的绝对偏移（即应用层已提交的总字节数）。
    pub fn write_offset(&self) -> u64 {
        self.acked + self.buffered
    }

    /// 已发往网络的绝对偏移。
    pub fn send_cursor(&self) -> u64 {
        self.cursor
    }

    /// 当前可再接收多少应用层字节而不超出窗口。
    pub fn writable(&self) -> u64 {
        self.capacity.saturating_sub(self.buffered)
    }

    /// 是否还有已缓冲但未发出的字节。
    pub fn has_pending(&self) -> bool {
        self.cursor < self.write_offset()
    }

    /// 所有数据均已确认。
    pub fn is_fully_acked(&self) -> bool {
        self.buffered == 0
    }

    pub fn mark_fin(&mut self) {
        self.fin_queued = true;
    }

    pub fn fin_queued(&self) -> bool {
        self.fin_queued
    }

    /// 写入应用层数据。
    ///
    /// 返回实际接纳的字节数；为 0 表示窗口已满，调用方必须停止从
    /// 本地 socket 读取（背压），否则会破坏"未确认数据不可丢弃"的不变式。
    pub fn push(&mut self, data: &[u8]) -> usize {
        let n = (self.writable() as usize).min(data.len());
        if n > 0 {
            self.chunks.push_back(Bytes::copy_from_slice(&data[..n]));
            self.buffered += n as u64;
        }
        n
    }

    /// 取出下一段待发送数据，最多 `max` 字节。
    ///
    /// 返回 `(绝对偏移, 数据)`。数据仍留在重传缓冲中，直到被 `ack` 释放。
    pub fn next_unsent(&mut self, max: usize) -> Option<(u64, Bytes)> {
        if !self.has_pending() || max == 0 {
            return None;
        }
        let offset = self.cursor;
        // cursor 在缓冲区内的相对位置。
        let mut skip = (self.cursor - self.acked) as usize;
        let mut taken = 0usize;
        let mut collected: Vec<Bytes> = Vec::new();

        for chunk in &self.chunks {
            if skip >= chunk.len() {
                skip -= chunk.len();
                continue;
            }
            let avail = &chunk[skip..];
            skip = 0;
            let want = max - taken;
            let n = avail.len().min(want);
            collected
                .push(chunk.slice((chunk.len() - avail.len())..(chunk.len() - avail.len() + n)));
            taken += n;
            if taken >= max {
                break;
            }
        }

        if taken == 0 {
            return None;
        }
        // 单块时零拷贝直接复用；多块时才合并。
        let out = if collected.len() == 1 {
            collected.pop().expect("len==1")
        } else {
            let mut merged = bytes::BytesMut::with_capacity(taken);
            for c in collected {
                merged.extend_from_slice(&c);
            }
            merged.freeze()
        };
        self.cursor += taken as u64;
        Some((offset, out))
    }

    /// 处理对端累积确认，释放已确认字节。
    ///
    /// 拒绝倒退或超前的确认——那意味着对端实现有误或数据被篡改，
    /// 静默接受会破坏偏移一致性。
    pub fn ack(&mut self, offset: u64) -> Result<(), ResumeError> {
        if offset < self.acked {
            // 重复/乱序确认，幂等忽略。
            return Ok(());
        }
        if offset > self.write_offset() {
            return Err(ResumeError::AckBeyondSent {
                ack: offset,
                sent: self.write_offset(),
            });
        }
        let mut release = offset - self.acked;
        while release > 0 {
            let front_len = match self.chunks.front() {
                Some(c) => c.len() as u64,
                None => break,
            };
            if front_len <= release {
                self.chunks.pop_front();
                self.buffered -= front_len;
                release -= front_len;
            } else {
                let mut front = self.chunks.pop_front().expect("front exists");
                front.advance(release as usize);
                self.buffered -= release;
                self.chunks.push_front(front);
                release = 0;
            }
        }
        self.acked = offset;
        // 对端确认的数据一定已经发出；若 cursor 落后（不应发生）则修正。
        if self.cursor < self.acked {
            self.cursor = self.acked;
        }
        Ok(())
    }

    /// 重连后按对端报告的接收偏移回退发送游标。
    ///
    /// `peer_recv` 是对端声明"我已收到这么多字节"。
    /// * 小于 `acked`：对端收到的比它自己确认过的还少，说明缓冲已被释放，
    ///   缺口无法重建 → 该流只能重置。
    /// * 处于 `[acked, write_offset]`：把游标回退到该处，缺口数据会被重发。
    /// * 大于 `write_offset`：对端声称收到了我们从未发送的字节 → 协议违规。
    pub fn rewind_to(&mut self, peer_recv: u64) -> Result<u64, ResumeError> {
        if peer_recv < self.acked {
            return Err(ResumeError::GapUnrecoverable {
                peer_recv,
                acked: self.acked,
            });
        }
        if peer_recv > self.write_offset() {
            return Err(ResumeError::AckBeyondSent {
                ack: peer_recv,
                sent: self.write_offset(),
            });
        }
        // 对端已收到的部分等价于已确认，可安全释放。
        self.ack(peer_recv)?;
        self.cursor = peer_recv;
        Ok(self.write_offset() - self.cursor)
    }
}

/// 接收侧偏移跟踪：保证字节严格按序交付，并丢弃重连造成的重复数据。
///
/// 重连后发送方从对端上次确认处重发，中间可能包含接收方**已经**交付过的
/// 字节（因为 `Ack` 可能在断线时丢失）。这里按绝对偏移裁剪重叠部分，
/// 从而做到"至少一次传输 + 恰好一次交付"。
#[derive(Debug, Default)]
pub struct RecvTracker {
    delivered: u64,
    fin_at: Option<u64>,
}

impl RecvTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// 已按序交付给应用层的字节数，也是要放进 `Ack` 的值。
    pub fn delivered(&self) -> u64 {
        self.delivered
    }

    /// 处理一个 `Data` 帧，返回应当交付给应用层的切片。
    ///
    /// * `Ok(Some(bytes))`：这些字节是新数据，需按序写入本地 socket。
    /// * `Ok(None)`：整帧都是重复数据，安全丢弃。
    /// * `Err(Gap)`：帧起始偏移超过了已交付位置，中间存在空洞。
    ///   本协议下这不可能由正常重传产生，属于协议违规。
    pub fn accept(&mut self, offset: u64, data: Bytes) -> Result<Option<Bytes>, ResumeError> {
        let end = offset + data.len() as u64;
        if end <= self.delivered {
            return Ok(None); // 完全重复
        }
        if offset > self.delivered {
            return Err(ResumeError::Gap {
                expected: self.delivered,
                got: offset,
            });
        }
        // 裁掉已交付的前缀。
        let skip = (self.delivered - offset) as usize;
        let fresh = data.slice(skip..);
        self.delivered = end;
        Ok(Some(fresh))
    }

    /// 记录对端 FIN 出现在当前交付位置。
    pub fn mark_fin(&mut self) {
        self.fin_at = Some(self.delivered);
    }

    pub fn fin_received(&self) -> bool {
        self.fin_at.is_some()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResumeError {
    #[error("peer acked {ack} but only {sent} bytes were ever sent")]
    AckBeyondSent { ack: u64, sent: u64 },
    #[error("peer received only {peer_recv} but buffer was already released up to {acked}; resume impossible")]
    GapUnrecoverable { peer_recv: u64, acked: u64 },
    #[error("data gap: expected offset {expected}, got {got}")]
    Gap { expected: u64, got: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_send_ack_cycle() {
        let mut b = SendBuffer::new(1024);
        assert_eq!(b.push(b"hello"), 5);
        assert_eq!(b.write_offset(), 5);
        assert!(b.has_pending());

        let (off, data) = b.next_unsent(1024).expect("pending");
        assert_eq!(off, 0);
        assert_eq!(&data[..], b"hello");
        assert!(!b.has_pending());
        assert!(!b.is_fully_acked(), "still awaiting ack");

        b.ack(5).unwrap();
        assert!(b.is_fully_acked());
        assert_eq!(b.acked(), 5);
        assert_eq!(b.writable(), 1024);
    }

    #[test]
    fn respects_window_and_applies_backpressure() {
        let mut b = SendBuffer::new(8);
        assert_eq!(b.push(b"0123456789"), 8, "must clamp to capacity");
        assert_eq!(b.writable(), 0);
        assert_eq!(b.push(b"more"), 0, "window full -> backpressure");

        b.next_unsent(8).unwrap();
        b.ack(4).unwrap();
        assert_eq!(b.writable(), 4);
        assert_eq!(b.push(b"abcd"), 4);
    }

    #[test]
    fn next_unsent_splits_by_max_and_merges_chunks() {
        let mut b = SendBuffer::new(1024);
        b.push(b"abc");
        b.push(b"def");
        b.push(b"ghi");

        let (o1, d1) = b.next_unsent(4).unwrap();
        assert_eq!((o1, &d1[..]), (0, &b"abcd"[..]), "merged across chunks");
        let (o2, d2) = b.next_unsent(4).unwrap();
        assert_eq!((o2, &d2[..]), (4, &b"efgh"[..]));
        let (o3, d3) = b.next_unsent(4).unwrap();
        assert_eq!((o3, &d3[..]), (8, &b"i"[..]));
        assert!(b.next_unsent(4).is_none());
    }

    #[test]
    fn partial_ack_trims_chunk_prefix() {
        let mut b = SendBuffer::new(1024);
        b.push(b"abcdef");
        b.next_unsent(6).unwrap();
        b.ack(2).unwrap();
        assert_eq!(b.acked(), 2);
        // 回退到 2 应重发 "cdef"
        let regap = b.rewind_to(2).unwrap();
        assert_eq!(regap, 4);
        let (off, data) = b.next_unsent(64).unwrap();
        assert_eq!(off, 2);
        assert_eq!(&data[..], b"cdef");
    }

    #[test]
    fn duplicate_ack_is_idempotent_and_overshoot_rejected() {
        let mut b = SendBuffer::new(64);
        b.push(b"abcd");
        b.next_unsent(64).unwrap();
        b.ack(4).unwrap();
        b.ack(2).unwrap(); // 旧的重复 ack
        assert_eq!(b.acked(), 4);
        assert_eq!(
            b.ack(99),
            Err(ResumeError::AckBeyondSent { ack: 99, sent: 4 })
        );
    }

    /// 断线重连的核心场景：ack 在断线中丢失，重连后必须精确重发缺口。
    #[test]
    fn reconnect_resends_exact_gap_without_loss() {
        let mut tx = SendBuffer::new(4096);
        let payload: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        tx.push(&payload);

        // 发出全部 1000 字节，但对端只成功接收了前 400 字节，且 ack 丢失。
        let mut wire = Vec::new();
        while let Some((off, d)) = tx.next_unsent(256) {
            wire.push((off, d));
        }
        assert_eq!(tx.send_cursor(), 1000);

        let mut rx = RecvTracker::new();
        let mut received = Vec::new();
        for (off, d) in &wire {
            if *off >= 400 {
                break; // 模拟断网：后续帧全部丢失
            }
            let take = ((400 - *off) as usize).min(d.len());
            if let Some(fresh) = rx.accept(*off, d.slice(..take)).unwrap() {
                received.extend_from_slice(&fresh);
            }
        }
        assert_eq!(rx.delivered(), 400);
        assert_eq!(received.len(), 400);

        // 重连：接收方声明 400，发送方回退。
        let gap = tx.rewind_to(rx.delivered()).unwrap();
        assert_eq!(gap, 600, "must resend exactly the missing tail");

        while let Some((off, d)) = tx.next_unsent(256) {
            if let Some(fresh) = rx.accept(off, d).unwrap() {
                received.extend_from_slice(&fresh);
            }
        }

        assert_eq!(received.len(), 1000);
        assert_eq!(
            received, payload,
            "byte stream must be identical: zero loss"
        );
        assert_eq!(rx.delivered(), 1000);
    }

    /// 重传导致的重叠必须被接收方裁剪，不能重复交付。
    #[test]
    fn overlapping_retransmit_is_deduplicated() {
        let mut rx = RecvTracker::new();
        let fresh = rx
            .accept(0, Bytes::from_static(b"abcdef"))
            .unwrap()
            .unwrap();
        assert_eq!(&fresh[..], b"abcdef");

        // 完全重复
        assert_eq!(rx.accept(0, Bytes::from_static(b"abc")).unwrap(), None);
        // 部分重叠：只应交付 "gh"
        let fresh = rx.accept(4, Bytes::from_static(b"efgh")).unwrap().unwrap();
        assert_eq!(&fresh[..], b"gh");
        assert_eq!(rx.delivered(), 8);
    }

    #[test]
    fn recv_rejects_gap() {
        let mut rx = RecvTracker::new();
        rx.accept(0, Bytes::from_static(b"ab")).unwrap();
        assert_eq!(
            rx.accept(5, Bytes::from_static(b"z")),
            Err(ResumeError::Gap {
                expected: 2,
                got: 5
            })
        );
    }

    #[test]
    fn rewind_below_acked_is_unrecoverable() {
        let mut tx = SendBuffer::new(64);
        tx.push(b"abcdefgh");
        tx.next_unsent(64).unwrap();
        tx.ack(8).unwrap(); // 缓冲已释放
        assert_eq!(
            tx.rewind_to(3),
            Err(ResumeError::GapUnrecoverable {
                peer_recv: 3,
                acked: 8
            })
        );
    }

    #[test]
    fn rewind_beyond_sent_is_rejected() {
        let mut tx = SendBuffer::new(64);
        tx.push(b"abc");
        assert_eq!(
            tx.rewind_to(10),
            Err(ResumeError::AckBeyondSent { ack: 10, sent: 3 })
        );
    }

    /// 多轮断线：连续三次重连仍要保持字节流完整。
    #[test]
    fn survives_repeated_disconnects() {
        let mut tx = SendBuffer::new(1 << 16);
        let mut rx = RecvTracker::new();
        let payload: Vec<u8> = (0..5000u32).map(|i| (i % 97) as u8).collect();
        let mut out = Vec::new();
        let mut fed = 0usize;

        for round in 0..4 {
            // 逐步喂入应用数据
            let end = ((round + 1) * 1250).min(payload.len());
            fed += tx.push(&payload[fed..end]);

            // 本轮只有一半帧成功送达
            let mut frames = Vec::new();
            while let Some(f) = tx.next_unsent(300) {
                frames.push(f);
            }
            let deliver = frames.len() / 2 + 1;
            for (off, d) in frames.into_iter().take(deliver) {
                if let Some(fresh) = rx.accept(off, d).unwrap() {
                    out.extend_from_slice(&fresh);
                }
            }
            // 断线重连：ack 全部丢失，靠 Resume 对齐
            tx.rewind_to(rx.delivered()).unwrap();
        }

        // 最后一轮把剩余数据全部送达
        while let Some((off, d)) = tx.next_unsent(300) {
            if let Some(fresh) = rx.accept(off, d).unwrap() {
                out.extend_from_slice(&fresh);
            }
        }

        assert_eq!(out.len(), payload.len());
        assert_eq!(out, payload, "stream corrupted across reconnects");
    }

    #[test]
    fn fin_flags_track_state() {
        let mut tx = SendBuffer::new(16);
        assert!(!tx.fin_queued());
        tx.mark_fin();
        assert!(tx.fin_queued());

        let mut rx = RecvTracker::new();
        assert!(!rx.fin_received());
        rx.mark_fin();
        assert!(rx.fin_received());
    }
}
