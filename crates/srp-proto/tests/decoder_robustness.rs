//! 解码器健壮性测试。
//!
//! 帧解码器直接面对来自网络的字节，是本项目最主要的攻击面。这里用伪随机
//! 输入做大量往返与畸形输入测试，验证三条性质：
//!
//! 1. **不 panic**：任何字节序列都只能得到 `Ok`/`Err`，绝不 panic 或越界；
//! 2. **不无限增长**：拒绝超大长度声明，不因一个恶意帧头分配数百 MB；
//! 3. **往返一致**：合法帧编码后解码必须完全等价。
//!
//! 这不是真正的 fuzz（没有覆盖率引导），但确定性种子让失败可复现，
//! 且能覆盖手写用例容易漏掉的边界组合。

use bytes::{BufMut, Bytes, BytesMut};
use srp_proto::{Frame, ProtoError, ResetCode, TargetAddr, HEADER_LEN, MAX_FRAME_PAYLOAD};

/// 确定性 PRNG（xorshift64*）。用固定种子让任何失败都能被精确重放。
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // 0 是 xorshift 的不动点，必须避开。
        Self(if seed == 0 { 0x9E3779B97F4A7C15 } else { seed })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| (self.next_u64() & 0xFF) as u8).collect()
    }
}

/// 反复解码直到不再产出，模拟真实的流式读取循环。
///
/// 这些测试只关心"任何输入都不会 panic"，所以刻意忽略解码结果本身：
/// `Ok(None)`（数据不足）与 `Err`（协议违规）都是可接受的收场。
fn drain_quietly(buf: &mut BytesMut) {
    while let Ok(Some(_)) = Frame::decode(buf) {}
}

fn random_addr(rng: &mut Rng) -> TargetAddr {
    let port = (rng.below(65536)) as u16;
    match rng.below(3) {
        0 => {
            let b = rng.bytes(4);
            TargetAddr::V4([b[0], b[1], b[2], b[3]], port)
        }
        1 => {
            let b = rng.bytes(16);
            let mut o = [0u8; 16];
            o.copy_from_slice(&b);
            TargetAddr::V6(o, port)
        }
        _ => {
            // 域名长度受 1 字节前缀限制，取 1..=255。
            let len = 1 + rng.below(255) as usize;
            let name: String = (0..len)
                .map(|_| {
                    // 只用安全字符，保证是合法 UTF-8 且可比较。
                    let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789-.";
                    alphabet[rng.below(alphabet.len() as u64) as usize] as char
                })
                .collect();
            TargetAddr::Domain(name, port)
        }
    }
}

fn random_frame(rng: &mut Rng) -> Frame {
    let sid = rng.next_u64() as u32;
    let codes = [
        ResetCode::Normal,
        ResetCode::ConnectFailed,
        ResetCode::UnknownStream,
        ResetCode::ResumeImpossible,
        ResetCode::Internal,
        ResetCode::Forbidden,
    ];
    let code = codes[rng.below(codes.len() as u64) as usize];

    match rng.below(14) {
        0 => {
            let mut id = [0u8; 16];
            id.copy_from_slice(&rng.bytes(16));
            Frame::Hello {
                version: (rng.below(256)) as u8,
                session_id: id,
                resume: rng.below(2) == 1,
            }
        }
        1 => {
            let mut id = [0u8; 16];
            id.copy_from_slice(&rng.bytes(16));
            Frame::HelloAck {
                version: (rng.below(256)) as u8,
                session_id: id,
                resumed: rng.below(2) == 1,
            }
        }
        2 => Frame::Open {
            stream_id: sid,
            addr: random_addr(rng),
        },
        3 => Frame::OpenOk { stream_id: sid },
        4 => Frame::OpenErr {
            stream_id: sid,
            code,
            // 含多字节 UTF-8，验证错误消息不被截断成非法序列。
            msg: format!("失败 {}", rng.below(1000)),
        },
        5 => {
            // 覆盖 0 长度到跨越单帧上限附近的载荷。
            let len = rng.below(70_000) as usize;
            Frame::Data {
                stream_id: sid,
                offset: rng.next_u64(),
                data: Bytes::from(rng.bytes(len)),
            }
        }
        6 => Frame::Ack {
            stream_id: sid,
            offset: rng.next_u64(),
        },
        7 => Frame::Fin { stream_id: sid },
        8 => Frame::Reset {
            stream_id: sid,
            code,
        },
        9 => Frame::Resume {
            stream_id: sid,
            recv_offset: rng.next_u64(),
        },
        10 => Frame::ResumeOk {
            stream_id: sid,
            recv_offset: rng.next_u64(),
        },
        11 => Frame::ResumeErr {
            stream_id: sid,
            code,
        },
        12 => Frame::Ping {
            nonce: rng.next_u64(),
        },
        _ => Frame::Pong {
            nonce: rng.next_u64(),
        },
    }
}

/// 大量随机合法帧的编解码往返必须完全一致。
#[test]
fn random_frames_roundtrip_exactly() {
    let mut rng = Rng::new(0xC0FFEE);
    for i in 0..4000 {
        let frame = random_frame(&mut rng);
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        let decoded = Frame::decode(&mut buf)
            .unwrap_or_else(|e| panic!("iteration {i}: decode failed for {frame:?}: {e}"))
            .unwrap_or_else(|| panic!("iteration {i}: incomplete frame for {frame:?}"));

        assert_eq!(decoded, frame, "iteration {i}: roundtrip mismatch");
        assert!(buf.is_empty(), "iteration {i}: leftover bytes");
    }
}

/// 随机帧流水线：连续多帧编码后必须按序解出，且无残留。
#[test]
fn pipelined_random_frames_decode_in_order() {
    let mut rng = Rng::new(0xBADC0DE);
    for round in 0..200 {
        let n = 1 + rng.below(20) as usize;
        let frames: Vec<Frame> = (0..n).map(|_| random_frame(&mut rng)).collect();

        let mut wire = BytesMut::new();
        for f in &frames {
            f.encode(&mut wire);
        }

        let mut out = Vec::new();
        while let Some(f) = Frame::decode(&mut wire).expect("decode") {
            out.push(f);
        }
        assert_eq!(out, frames, "round {round}: pipeline mismatch");
        assert!(wire.is_empty(), "round {round}: leftover bytes");
    }
}

/// 任意分片边界：逐字节喂入不得丢帧、错序或误判。
#[test]
fn arbitrary_fragmentation_preserves_frames() {
    let mut rng = Rng::new(0x5EED);
    for round in 0..60 {
        let n = 1 + rng.below(8) as usize;
        let frames: Vec<Frame> = (0..n).map(|_| random_frame(&mut rng)).collect();

        let mut wire = BytesMut::new();
        for f in &frames {
            f.encode(&mut wire);
        }
        let wire = wire.freeze();

        // 随机切成不等长的块喂进去。
        let mut buf = BytesMut::new();
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos < wire.len() {
            let chunk = 1 + rng.below(1000) as usize;
            let end = (pos + chunk).min(wire.len());
            buf.extend_from_slice(&wire[pos..end]);
            pos = end;
            while let Some(f) = Frame::decode(&mut buf).expect("decode") {
                out.push(f);
            }
        }
        assert_eq!(out, frames, "round {round}: fragmentation lost frames");
        assert!(buf.is_empty(), "round {round}: leftover bytes");
    }
}

/// 完全随机的垃圾字节：只允许返回 Ok 或 Err，绝不 panic。
#[test]
fn random_garbage_never_panics() {
    let mut rng = Rng::new(0xDEADBEEF);
    for _ in 0..6000 {
        let len = rng.below(600) as usize;
        let mut buf = BytesMut::from(&rng.bytes(len)[..]);
        drain_quietly(&mut buf);
    }
}

/// 合法帧头 + 被破坏的载荷：同样不得 panic。
#[test]
fn corrupted_payloads_are_rejected_cleanly() {
    let mut rng = Rng::new(0x1337);
    for _ in 0..3000 {
        let frame = random_frame(&mut rng);
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        if buf.is_empty() {
            continue;
        }

        // 随机翻转若干字节。
        let flips = 1 + rng.below(5) as usize;
        for _ in 0..flips {
            let idx = rng.below(buf.len() as u64) as usize;
            buf[idx] ^= 1u8 << rng.below(8);
        }

        drain_quietly(&mut buf);
    }
}

/// 声明超大长度的帧头必须被立即拒绝，而不是尝试分配。
///
/// 这是最实际的拒绝服务向量：一个 9 字节的帧头若被信任，
/// 就能让接收方申请 4 GiB 内存。
#[test]
fn oversized_length_declarations_are_refused_without_allocating() {
    for declared in [
        MAX_FRAME_PAYLOAD as u32 + 1,
        1 << 20,
        1 << 24,
        u32::MAX / 2,
        u32::MAX,
    ] {
        let mut buf = BytesMut::new();
        buf.put_u8(0x20); // DATA
        buf.put_u32(1);
        buf.put_u32(declared);

        match Frame::decode(&mut buf) {
            Err(ProtoError::FrameTooLarge(n)) => {
                assert_eq!(n as u32, declared);
                // 关键：源缓冲区必须保持原样（未被消耗），且没有增长。
                assert_eq!(buf.len(), HEADER_LEN);
            }
            other => panic!("declared {declared} should be refused, got {other:?}"),
        }
    }
}

/// 长度刚好等于上限的帧是合法的，不能被误杀。
#[test]
fn payload_exactly_at_the_limit_is_accepted() {
    let data = vec![0x5Au8; MAX_FRAME_PAYLOAD - 8]; // 减去 offset 占用的 8 字节
    let frame = Frame::Data {
        stream_id: 42,
        offset: 12345,
        data: Bytes::from(data.clone()),
    };
    let mut buf = BytesMut::new();
    frame.encode(&mut buf);
    assert_eq!(buf.len(), HEADER_LEN + MAX_FRAME_PAYLOAD);

    let decoded = Frame::decode(&mut buf)
        .expect("must accept")
        .expect("complete");
    assert_eq!(decoded, frame);
}

/// 不完整输入必须返回 `Ok(None)` 且**不消耗**任何字节。
///
/// 这条性质是流式读取正确性的基础：若解码器在数据不足时消耗了字节，
/// 后续到达的数据就会被错位解析。
#[test]
fn incomplete_input_never_consumes_bytes() {
    let mut rng = Rng::new(0xFEED);
    for _ in 0..2000 {
        let frame = random_frame(&mut rng);
        let mut full = BytesMut::new();
        frame.encode(&mut full);
        if full.len() <= 1 {
            continue;
        }

        // 截断到任意长度（不含完整帧）。
        let cut = rng.below(full.len() as u64) as usize;
        let mut partial = BytesMut::from(&full[..cut]);
        let before = partial.len();

        // 只有"数据不足"这一分支有约束：缓冲区必须原封不动。
        // 截断后的字节恰好构成一个更短的合法帧、或直接违规，都是允许的。
        if let Ok(None) = Frame::decode(&mut partial) {
            assert_eq!(
                partial.len(),
                before,
                "incomplete decode must leave the buffer untouched"
            );
        }
    }
}
