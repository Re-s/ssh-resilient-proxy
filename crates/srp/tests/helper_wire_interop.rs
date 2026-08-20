//! 客户端 ↔ 真实 `srp-helper` 进程的线协议互操作测试。
//!
//! 这里不经过 SSH：直接把 helper 子进程的 stdin/stdout 当作 SSH 通道的
//! 两个方向。这样做刻意隔离了变量——SSH 层的正确性由 `tunnel` 模块自己的
//! 测试覆盖，本文件只回答一个问题：
//!
//! > **客户端与 helper 对同一份线协议的理解是否一致？**
//!
//! 这是最容易出现"两边各自单测都过、接起来却不通"的地方：帧编码、握手
//! 语义、Ack 时机、Resume 对齐、FIN 半关闭，任何一处理解偏差都会在这里暴露。

use std::process::Stdio;
use std::time::Duration;

use bytes::BytesMut;
use srp_proto::{Frame, ResetCode, TargetAddr, PROTO_VERSION};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

/// 定位 helper 二进制。
///
/// cargo 把集成测试的可执行文件放在 `target/<profile>/deps/`，
/// 所以从当前测试二进制往上两级即是 profile 目录。
fn helper_path() -> std::path::PathBuf {
    let mut p = std::env::current_exe().expect("current_exe");
    p.pop(); // deps/
    p.pop(); // <profile>/
    p.push("srp-helper");
    assert!(
        p.exists(),
        "srp-helper binary not found at {p:?}; run `cargo build -p srp-helper` first"
    );
    p
}

/// 一个受测的 helper 子进程，外加帧级读写辅助。
struct Peer {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    inbox: BytesMut,
}

impl Peer {
    async fn spawn(extra_args: &[&str]) -> Self {
        let mut cmd = Command::new(helper_path());
        cmd.args(extra_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // stderr 直通测试输出，helper 的日志在排障时能看到。
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = cmd.spawn().expect("spawn srp-helper");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        Self {
            child,
            stdin,
            stdout,
            inbox: BytesMut::new(),
        }
    }

    async fn send(&mut self, frame: Frame) {
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        self.stdin.write_all(&buf).await.expect("write frame");
        self.stdin.flush().await.expect("flush");
    }

    /// 读一帧，带超时以免测试挂死。
    async fn recv(&mut self) -> Frame {
        loop {
            if let Some(f) = Frame::decode(&mut self.inbox).expect("decode") {
                return f;
            }
            let mut chunk = [0u8; 8192];
            let n = tokio::time::timeout(Duration::from_secs(10), self.stdout.read(&mut chunk))
                .await
                .expect("helper did not answer in time")
                .expect("read stdout");
            assert_ne!(n, 0, "helper closed stdout unexpectedly");
            self.inbox.extend_from_slice(&chunk[..n]);
        }
    }

    /// 完成握手，返回 helper 是否声称恢复了会话状态。
    async fn handshake(&mut self, session_id: u8, resume: bool) -> bool {
        self.send(Frame::Hello {
            version: PROTO_VERSION,
            session_id: [session_id; 16],
            resume,
        })
        .await;
        match self.recv().await {
            Frame::HelloAck {
                version, resumed, ..
            } => {
                assert_eq!(version, PROTO_VERSION, "version must match");
                resumed
            }
            other => panic!("expected HelloAck, got {other:?}"),
        }
    }

    async fn shutdown(mut self) {
        drop(self.stdin);
        let _ = tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await;
    }
}

/// 起一个 echo 服务器，返回端口。保持连接直到对端关闭。
async fn spawn_echo() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 32 * 1024];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });
    port
}

fn local(port: u16) -> TargetAddr {
    TargetAddr::V4([127, 0, 0, 1], port)
}

/// 握手：客户端与 helper 对 Hello/HelloAck 的理解必须一致。
#[tokio::test]
async fn handshake_agrees_on_version_and_reports_no_resume_initially() {
    let mut peer = Peer::spawn(&[]).await;
    let resumed = peer.handshake(1, false).await;
    assert!(!resumed, "a fresh helper must not claim to have resumed");
    peer.shutdown().await;
}

/// 同一进程内、同一 session_id 的第二次 Hello 应当被认作续连。
///
/// 这条性质决定了 helper 模式的续传能力边界：只有 helper 认出会话，
/// 客户端才敢保留旧流的重传缓冲。
#[tokio::test]
async fn same_session_id_with_resume_flag_is_recognised() {
    let port = spawn_echo().await;
    let mut peer = Peer::spawn(&[]).await;
    assert!(!peer.handshake(7, false).await);

    // 建一条活跃流，让 helper 有状态可保留。
    peer.send(Frame::Open {
        stream_id: 1,
        addr: local(port),
    })
    .await;
    assert_eq!(peer.recv().await, Frame::OpenOk { stream_id: 1 });

    // 同 session_id + resume=true。
    let resumed = peer.handshake(7, true).await;
    assert!(
        resumed,
        "helper should recognise the same session id while streams are alive"
    );
    peer.shutdown().await;
}

/// 不同 session_id 必须导致状态重置，客户端据此放弃旧流。
#[tokio::test]
async fn different_session_id_forces_a_reset() {
    let port = spawn_echo().await;
    let mut peer = Peer::spawn(&[]).await;
    peer.handshake(1, false).await;
    peer.send(Frame::Open {
        stream_id: 1,
        addr: local(port),
    })
    .await;
    assert_eq!(peer.recv().await, Frame::OpenOk { stream_id: 1 });

    let resumed = peer.handshake(2, true).await;
    assert!(
        !resumed,
        "a different session id must not be reported as resumed"
    );
    peer.shutdown().await;
}

/// 数据往返 + 累积确认：这是最基本的互操作。
#[tokio::test]
async fn data_round_trips_and_is_acknowledged() {
    let port = spawn_echo().await;
    let mut peer = Peer::spawn(&[]).await;
    peer.handshake(1, false).await;

    peer.send(Frame::Open {
        stream_id: 5,
        addr: local(port),
    })
    .await;
    assert_eq!(peer.recv().await, Frame::OpenOk { stream_id: 5 });

    peer.send(Frame::Data {
        stream_id: 5,
        offset: 0,
        data: bytes::Bytes::from_static(b"interop"),
    })
    .await;

    // Ack 与回显数据的顺序由调度决定，两者都必须出现。
    let mut acked = false;
    let mut echoed = false;
    while !(acked && echoed) {
        match peer.recv().await {
            Frame::Ack {
                stream_id: 5,
                offset,
            } => {
                assert_eq!(offset, 7, "ack must cover exactly the delivered bytes");
                acked = true;
            }
            Frame::Data {
                stream_id: 5,
                offset,
                data,
            } => {
                assert_eq!(offset, 0);
                assert_eq!(&data[..], b"interop");
                echoed = true;
            }
            Frame::Fin { stream_id: 5 } => {}
            other => panic!("unexpected frame {other:?}"),
        }
    }
    peer.shutdown().await;
}

/// 大载荷分帧：验证双方对 offset 语义与分块边界的理解一致。
#[tokio::test]
async fn large_payload_reassembles_in_order() {
    let port = spawn_echo().await;
    let mut peer = Peer::spawn(&[]).await;
    peer.handshake(1, false).await;
    peer.send(Frame::Open {
        stream_id: 9,
        addr: local(port),
    })
    .await;
    assert_eq!(peer.recv().await, Frame::OpenOk { stream_id: 9 });

    // 分多帧发送 192 KiB，offset 必须连续。
    let total = 192 * 1024usize;
    let payload: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
    let chunk = 24 * 1024;
    let mut sent = 0usize;
    while sent < total {
        let end = (sent + chunk).min(total);
        peer.send(Frame::Data {
            stream_id: 9,
            offset: sent as u64,
            data: bytes::Bytes::copy_from_slice(&payload[sent..end]),
        })
        .await;
        sent = end;
    }

    // 收齐回显，按 offset 校验完整性。
    let mut received = vec![0u8; total];
    let mut filled = 0usize;
    while filled < total {
        match peer.recv().await {
            Frame::Data {
                stream_id: 9,
                offset,
                data,
            } => {
                let off = offset as usize;
                assert!(off + data.len() <= total, "echo exceeded the payload size");
                received[off..off + data.len()].copy_from_slice(&data);
                filled += data.len();
            }
            // Ack 与 Fin 都是合法的穿插帧。
            Frame::Ack { stream_id: 9, .. } | Frame::Fin { stream_id: 9 } => {}
            other => panic!("unexpected frame {other:?}"),
        }
    }
    assert_eq!(received, payload, "payload corrupted across the wire");
    peer.shutdown().await;
}

/// Resume 对齐：helper 必须按客户端声明的接收偏移回退并重发缺口。
///
/// 这直接验证"掉包恢复"在两个实现之间是**互通**的，而不是各自单测里
/// 自说自话。
#[tokio::test]
async fn resume_makes_the_helper_resend_the_exact_gap() {
    // 一个只发数据、不读的服务器：让 helper 的发送缓冲里积累已发未确认字节。
    //
    // 注意它发完**不能**关闭连接：出口 EOF 会让 helper 认为该流双向结束并
    // 回收状态，随后到达的 Resume 就只能得到 ResumeErr{UnknownStream}。
    // 真实场景里被续传的流当然还活着，所以这里保持连接开启。
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let body: Vec<u8> = (0..4096u32).map(|i| (i % 97) as u8).collect();
    let body_for_server = body.clone();
    let (hold_tx, hold_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        s.write_all(&body_for_server).await.unwrap();
        // 挂住连接，直到测试主体做完 Resume 校验。
        let _ = hold_rx.await;
        let _ = s.shutdown().await;
    });

    let mut peer = Peer::spawn(&[]).await;
    peer.handshake(1, false).await;
    peer.send(Frame::Open {
        stream_id: 11,
        addr: local(port),
    })
    .await;
    assert_eq!(peer.recv().await, Frame::OpenOk { stream_id: 11 });

    // 收一部分数据但**故意不 Ack**，模拟断网导致确认丢失。
    let mut first_pass = Vec::new();
    while first_pass.len() < 1024 {
        match peer.recv().await {
            Frame::Data {
                stream_id: 11,
                offset,
                data,
            } => {
                assert_eq!(
                    offset as usize,
                    first_pass.len(),
                    "helper must send contiguous offsets"
                );
                first_pass.extend_from_slice(&data);
            }
            Frame::Fin { stream_id: 11 } => break,
            other => panic!("unexpected frame {other:?}"),
        }
    }
    let acknowledged = 512u64;
    assert!(first_pass.len() as u64 >= acknowledged);

    // 重连语义：声明"我只收到了 512 字节"，helper 应从此处续发。
    peer.send(Frame::Resume {
        stream_id: 11,
        recv_offset: acknowledged,
    })
    .await;

    let mut resumed_ok = false;
    // 已确认的前缀保留，缺口部分等 helper 重发。
    let mut rebuilt = first_pass[..acknowledged as usize].to_vec();

    // 收帧直到两个条件**都**满足：见到 ResumeOk，且字节收齐。
    //
    // 这两件事的先后顺序由 helper 内部的任务调度决定：重发数据可能先于
    // ResumeOk 抵达。早期版本把 `resumed_ok` 的断言放在"字节收齐"循环之后，
    // 于是在高负载下偶发失败——数据先填满缓冲、循环提前退出，ResumeOk
    // 还躺在管道里没被读。这里显式等两个条件都达成，消除该竞态。
    let mut saw_fin = false;
    while !resumed_ok || (rebuilt.len() < body.len() && !saw_fin) {
        match peer.recv().await {
            Frame::ResumeOk { stream_id: 11, .. } => resumed_ok = true,
            Frame::Data {
                stream_id: 11,
                offset,
                data,
            } => {
                let off = offset as usize;
                // 重传允许重叠，但绝不允许出现空洞。
                assert!(
                    off <= rebuilt.len(),
                    "gap in resumed stream: expected offset <= {}, got {off}",
                    rebuilt.len()
                );
                if off + data.len() > rebuilt.len() {
                    rebuilt.resize(off + data.len(), 0);
                }
                rebuilt[off..off + data.len()].copy_from_slice(&data);
            }
            Frame::Fin { stream_id: 11 } => saw_fin = true,
            Frame::ResumeErr { code, .. } => panic!("helper refused to resume: {code:?}"),
            other => panic!("unexpected frame {other:?}"),
        }
    }

    assert!(resumed_ok, "helper must confirm the resume with ResumeOk");
    assert_eq!(rebuilt.len(), body.len(), "resumed stream is incomplete");
    assert_eq!(
        rebuilt, body,
        "resumed byte stream diverged from the original: resume lost or duplicated data"
    );

    let _ = hold_tx.send(());
    peer.shutdown().await;
}

/// 允许列表：不匹配的目标必须被 helper 拒绝，且错误码是 Forbidden。
#[tokio::test]
async fn allow_list_is_enforced_by_the_helper() {
    let port = spawn_echo().await;
    // 只允许一个不相干的域名。
    let mut peer = Peer::spawn(&["--allow", "example.invalid"]).await;
    peer.handshake(1, false).await;
    peer.send(Frame::Open {
        stream_id: 21,
        addr: local(port),
    })
    .await;

    match peer.recv().await {
        Frame::OpenErr { code, .. } => assert_eq!(
            code,
            ResetCode::Forbidden,
            "a target outside the allow list must be Forbidden"
        ),
        other => panic!("expected OpenErr, got {other:?}"),
    }
    peer.shutdown().await;
}

/// 出口连接失败必须映射成 ConnectFailed（而不是被当成协议错误）。
#[tokio::test]
async fn unreachable_target_reports_connect_failed() {
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };
    let mut peer = Peer::spawn(&[]).await;
    peer.handshake(1, false).await;
    peer.send(Frame::Open {
        stream_id: 31,
        addr: local(dead),
    })
    .await;

    match peer.recv().await {
        Frame::OpenErr { code, msg, .. } => {
            assert_eq!(code, ResetCode::ConnectFailed);
            assert!(!msg.is_empty(), "error message should describe the failure");
        }
        other => panic!("expected OpenErr, got {other:?}"),
    }
    peer.shutdown().await;
}

/// Ping/Pong：保活探测在两个实现之间必须互通。
#[tokio::test]
async fn ping_is_answered_with_matching_pong() {
    let mut peer = Peer::spawn(&[]).await;
    peer.handshake(1, false).await;
    peer.send(Frame::Ping { nonce: 0xDEADBEEF }).await;
    assert_eq!(peer.recv().await, Frame::Pong { nonce: 0xDEADBEEF });
    peer.shutdown().await;
}

/// 未知流的数据必须被 Reset，而不是静默忽略。
#[tokio::test]
async fn data_for_an_unknown_stream_is_reset() {
    let mut peer = Peer::spawn(&[]).await;
    peer.handshake(1, false).await;
    peer.send(Frame::Data {
        stream_id: 999,
        offset: 0,
        data: bytes::Bytes::from_static(b"x"),
    })
    .await;
    match peer.recv().await {
        Frame::Reset { stream_id, code } => {
            assert_eq!(stream_id, 999);
            assert_eq!(code, ResetCode::UnknownStream);
        }
        other => panic!("expected Reset, got {other:?}"),
    }
    peer.shutdown().await;
}

/// FIN 半关闭：客户端停止发送后，目标仍应能把剩余数据发回来。
#[tokio::test]
async fn fin_is_half_close_not_full_close() {
    // 读到 EOF 才回复的服务器。
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut got = Vec::new();
        s.read_to_end(&mut got).await.unwrap();
        s.write_all(format!("got:{}", got.len()).as_bytes())
            .await
            .unwrap();
        s.shutdown().await.unwrap();
    });

    let mut peer = Peer::spawn(&[]).await;
    peer.handshake(1, false).await;
    peer.send(Frame::Open {
        stream_id: 41,
        addr: local(port),
    })
    .await;
    assert_eq!(peer.recv().await, Frame::OpenOk { stream_id: 41 });

    peer.send(Frame::Data {
        stream_id: 41,
        offset: 0,
        data: bytes::Bytes::from_static(b"abcde"),
    })
    .await;
    peer.send(Frame::Fin { stream_id: 41 }).await;

    let mut reply = Vec::new();
    loop {
        match peer.recv().await {
            Frame::Data {
                stream_id: 41,
                data,
                ..
            } => {
                reply.extend_from_slice(&data);
                if reply.starts_with(b"got:") {
                    break;
                }
            }
            Frame::Ack { stream_id: 41, .. } => {}
            Frame::Fin { stream_id: 41 } => break,
            other => panic!("unexpected frame {other:?}"),
        }
    }
    assert_eq!(
        String::from_utf8_lossy(&reply),
        "got:5",
        "the target must observe EOF and still be able to reply"
    );
    peer.shutdown().await;
}
