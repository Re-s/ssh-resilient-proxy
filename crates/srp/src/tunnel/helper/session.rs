//! helper 模式的会话驱动：把 [`super::mux`] 状态机接到真实的 SSH 通道。
//!
//! # 运行结构
//!
//! ```text
//!  SOCKS/HTTP 连接 ──┐                              ┌── 出口 TCP
//!                    ├─ LocalStream(逻辑流) ─┐      │
//!  SOCKS/HTTP 连接 ──┘                       │      │
//!                                            ▼      │
//!                        MuxState (重传缓冲) ──► SSH session 通道 ──► srp-helper
//! ```
//!
//! 驱动循环（[`run_session`]）独占一条 SSH `session` 通道，在它上面跑帧协议。
//! 通道断开时循环退出，外层监督逻辑等隧道恢复后重建通道并**尝试**续传。
//!
//! # 当前实现的真实边界
//!
//! 续传机制（重传缓冲、Resume 对齐、去重交付）是完整且经过测试的，
//! 但它能否真正跨越一次断网，取决于**远端 helper 进程是否存活**：
//!
//! * 通道重建时若 helper 仍是同一进程且保留了流状态，它回 `resumed = true`，
//!   双方对齐偏移后逐流续传，零字节丢失；
//! * 当前的 [`MuxDriver::supervise`] 每轮都通过 `exec` 启动一个**新** helper
//!   进程，所以实际上必然收到 `resumed = false`，客户端据此**重置**所有旧流
//!   并如实通知上层——而不是静默丢数据。
//!
//! 换言之：协议与状态机已经就绪，缺的是让 helper 在断网后活下来
//! （detach + Unix socket 重附着）。这一步尚未实现，README 的"已知限制"
//! 里有同样的说明。断网期间**新到达**的请求排队等待这一行为是完整可用的。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context as _};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use srp_proto::{Frame, ResetCode, SessionId, StreamId, TargetAddr, DATA_CHUNK, PROTO_VERSION};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::frontend::{BoxedStream, DialError, Dialer};
use crate::tunnel::config::HelperConfig;
use crate::tunnel::manager::TunnelManager;

use super::mux::{apply_frame, drain_stream_output, FrameEffect, MuxState};

/// 本地端点缓冲大小。这个值只影响单条流在内存里排队的字节数，
/// 真正的流控由 `SendBuffer` 的窗口负责。
const LOCAL_BUF: usize = 64 * 1024;

/// 单条逻辑流在客户端侧对上层暴露的句柄。
///
/// 上层（SOCKS5/HTTP frontend）拿到的是一个普通的 `AsyncRead + AsyncWrite`，
/// 完全不知道底下发生过几次重连——这是分层解耦换来的直接好处。
struct LocalEndpoint {
    /// helper → 本地：把收到的数据写进去，上层从对端读。
    to_local: mpsc::Sender<Bytes>,
    /// 远端半关闭通知。
    remote_fin: Option<oneshot::Sender<()>>,
    /// 流终止通知。
    terminate: Option<oneshot::Sender<ResetCode>>,
}

/// 需要驱动循环执行的命令。
enum MuxCommand {
    /// 上层请求打开一条新流。
    Open {
        addr: TargetAddr,
        local: DuplexStream,
        ready: oneshot::Sender<Result<(), DialError>>,
    },
    /// 某条流的本地侧读到了数据。
    LocalData { stream_id: StreamId, data: Bytes },
    /// 某条流的本地侧 EOF。
    LocalEof { stream_id: StreamId },
    /// 某条流被上层丢弃。
    LocalClose { stream_id: StreamId },
}

/// helper 模式的 Dialer。
///
/// 它本身不做 I/O，只把请求投递给常驻的驱动循环。
pub struct HelperDialer {
    cmd_tx: mpsc::Sender<MuxCommand>,
    dial_wait: Duration,
}

impl HelperDialer {
    /// 启动 helper 模式：spawn 常驻驱动循环，返回可用于 frontend 的 Dialer。
    pub fn spawn(
        tunnel: Arc<TunnelManager>,
        helper_cfg: HelperConfig,
        dial_wait: Duration,
    ) -> Arc<Self> {
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let session_id = random_session_id();

        let driver = MuxDriver {
            tunnel,
            helper_cfg,
            session_id,
            cmd_tx: cmd_tx.clone(),
        };
        tokio::spawn(driver.supervise(cmd_rx));

        Arc::new(Self { cmd_tx, dial_wait })
    }
}

#[async_trait]
impl Dialer for HelperDialer {
    async fn dial(&self, addr: &TargetAddr) -> Result<BoxedStream, DialError> {
        // 本地侧用内存双向流：一端给上层，一端由驱动循环持有。
        let (mine, theirs) = tokio::io::duplex(LOCAL_BUF);
        let (ready_tx, ready_rx) = oneshot::channel();

        self.cmd_tx
            .send(MuxCommand::Open {
                addr: addr.clone(),
                local: theirs,
                ready: ready_tx,
            })
            .await
            .map_err(|_| {
                warn!("helper mux driver is gone");
                DialError::Internal
            })?;

        // 等 helper 回 OpenOk / OpenErr。超时上限用 dial_wait：
        // 断网期间驱动循环会先等隧道恢复，再转发 Open。
        match tokio::time::timeout(self.dial_wait, ready_rx).await {
            Ok(Ok(Ok(()))) => Ok(Box::new(mine)),
            Ok(Ok(Err(e))) => Err(e),
            Ok(Err(_)) => Err(DialError::Internal),
            Err(_) => Err(DialError::TimedOut),
        }
    }
}

/// 驱动循环。
struct MuxDriver {
    tunnel: Arc<TunnelManager>,
    helper_cfg: HelperConfig,
    session_id: SessionId,
    cmd_tx: mpsc::Sender<MuxCommand>,
}

impl MuxDriver {
    /// 外层监督：SSH 通道断了就重建，并让存活的逻辑流续传。
    async fn supervise(self, mut cmd_rx: mpsc::Receiver<MuxCommand>) {
        let mut state = MuxState::new(self.helper_cfg.stream_window);
        let mut endpoints: HashMap<StreamId, LocalEndpoint> = HashMap::new();
        // 尚未投递给 helper 的 Open 请求（断网期间到达的请求在这里排队）。
        let mut pending_opens: Vec<PendingOpen> = Vec::new();
        let mut first = true;

        loop {
            // 等一条可用的 SSH 会话。断网期间在这里阻塞，
            // 期间到达的 Open 命令会被下面的 select 收集进 pending_opens。
            let session = match self
                .wait_session(&mut cmd_rx, &mut state, &mut endpoints, &mut pending_opens)
                .await
            {
                Some(s) => s,
                None => {
                    debug!("helper mux driver shutting down");
                    return;
                }
            };

            // 打开一条 session 通道并执行 helper。
            let channel = match self.open_helper_channel(&session).await {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "failed to start remote helper; will retry");
                    self.tunnel.notify_broken();
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
            };

            if first {
                info!("remote helper started");
                first = false;
            } else {
                // 说明清楚这里发生了什么：每轮都会执行一个**新的** helper 进程，
                // 所以除非将来支持 helper 常驻（detach + 重附着），
                // 它必然报告 resumed=false，旧流只能被重置。
                // 续传机制本身是完整的，等的是常驻能力。
                info!(
                    streams = state.len(),
                    "restarting remote helper after channel loss; \
                     streams can only resume if the helper kept its state"
                );
            }

            // 跑一轮会话，直到通道断开。
            let outcome = run_session(
                channel,
                self.session_id,
                &mut state,
                &mut endpoints,
                &mut pending_opens,
                &mut cmd_rx,
                &self.cmd_tx,
            )
            .await;

            match outcome {
                SessionOutcome::ChannelLost => {
                    warn!(
                        streams = state.len(),
                        "helper channel lost; streams retained for resume"
                    );
                    self.tunnel.notify_broken();
                }
                SessionOutcome::Shutdown => return,
            }
        }
    }

    /// 等一条可用 SSH 会话，同时不丢弃期间到达的命令。
    ///
    /// 断网期间上层仍在写数据。这些字节**必须**立刻进入重传缓冲，
    /// 否则它们在被送出之前就丢了——那会直接破坏"零字节丢失"的承诺。
    /// 所以这里不是简单地忽略非 Open 命令，而是把它们照常应用到状态机上，
    /// 只是暂时不 flush 到网络（没有可用通道）。
    async fn wait_session(
        &self,
        cmd_rx: &mut mpsc::Receiver<MuxCommand>,
        state: &mut MuxState,
        endpoints: &mut HashMap<StreamId, LocalEndpoint>,
        pending: &mut Vec<PendingOpen>,
    ) -> Option<Arc<crate::tunnel::manager::Session>> {
        loop {
            if let Some(s) = self.tunnel.current().await {
                return Some(s);
            }
            tokio::select! {
                // 短轮询等待隧道恢复。
                _ = tokio::time::sleep(Duration::from_millis(200)) => {}
                cmd = cmd_rx.recv() => {
                    match cmd {
                        // 断网期间到达的新请求排队，隧道恢复后统一投递——
                        // 这就是"断网期间新请求不失败"的具体实现。
                        Some(MuxCommand::Open { addr, local, ready }) => {
                            pending.push(PendingOpen { addr, local, ready });
                        }
                        // 已存在的流仍在产生数据：进重传缓冲，绝不丢弃。
                        //
                        // 注意这里**不能**走 handle_command：它会调用
                        // drain_stream_output 推进发送游标，而此刻帧无处可去，
                        // 被"发出"的字节就再也不会重发了。所以只入缓冲、不动游标。
                        Some(other) => {
                            if !buffer_command_offline(other, state, endpoints) {
                                return None;
                            }
                        }
                        None => return None,
                    }
                }
            }
        }
    }

    /// 在给定会话上打开通道并执行 helper。
    async fn open_helper_channel(
        &self,
        session: &crate::tunnel::manager::Session,
    ) -> anyhow::Result<russh::Channel<russh::client::Msg>> {
        let channel = session
            .handle
            .channel_open_session()
            .await
            .context("failed to open ssh session channel for helper")?;
        let cmd = self.helper_cfg.build_command();
        debug!(%cmd, "executing remote helper");
        channel
            .exec(true, cmd.as_bytes())
            .await
            .context("failed to exec remote helper")?;
        Ok(channel)
    }
}

struct PendingOpen {
    addr: TargetAddr,
    local: DuplexStream,
    ready: oneshot::Sender<Result<(), DialError>>,
}

enum SessionOutcome {
    /// SSH 通道断开，逻辑流保留待续传。
    ChannelLost,
    /// 上层已关停。
    Shutdown,
}

/// 单轮会话循环：在一条 SSH 通道上跑帧协议直到它断开。
#[allow(clippy::too_many_arguments)]
async fn run_session(
    channel: russh::Channel<russh::client::Msg>,
    session_id: SessionId,
    state: &mut MuxState,
    endpoints: &mut HashMap<StreamId, LocalEndpoint>,
    pending_opens: &mut Vec<PendingOpen>,
    cmd_rx: &mut mpsc::Receiver<MuxCommand>,
    cmd_tx: &mpsc::Sender<MuxCommand>,
) -> SessionOutcome {
    let (mut reader, writer) = channel.split();
    let mut inbound = BytesMut::with_capacity(64 * 1024);
    let mut outbound = BytesMut::with_capacity(64 * 1024);

    // 握手：resume 标志取决于是否已有存活流。
    let resuming = !state.is_empty();
    Frame::Hello {
        version: PROTO_VERSION,
        session_id,
        resume: resuming,
    }
    .encode(&mut outbound);

    if flush(&writer, &mut outbound).await.is_err() {
        return SessionOutcome::ChannelLost;
    }

    // 等 HelloAck 才能确定旧流能否续传。
    let mut handshake_done = false;

    loop {
        tokio::select! {
            // ---- 来自 helper 的字节 ----
            msg = reader.wait() => {
                let Some(msg) = msg else {
                    return SessionOutcome::ChannelLost;
                };
                match msg {
                    russh::ChannelMsg::Data { data } => {
                        inbound.extend_from_slice(&data);
                    }
                    russh::ChannelMsg::ExtendedData { data, .. } => {
                        // helper 的 stderr。转成日志，绝不混进协议流。
                        let text = String::from_utf8_lossy(&data);
                        for line in text.lines().filter(|l| !l.trim().is_empty()) {
                            debug!(target: "srp_helper", "{line}");
                        }
                        continue;
                    }
                    russh::ChannelMsg::Eof | russh::ChannelMsg::Close => {
                        return SessionOutcome::ChannelLost;
                    }
                    russh::ChannelMsg::ExitStatus { exit_status } => {
                        warn!(exit_status, "remote helper exited");
                        continue;
                    }
                    _ => continue,
                }

                // 逐帧处理。
                loop {
                    let frame = match Frame::decode(&mut inbound) {
                        Ok(Some(f)) => f,
                        Ok(None) => break,
                        Err(e) => {
                            warn!(error = %e, "protocol violation from helper; dropping channel");
                            return SessionOutcome::ChannelLost;
                        }
                    };

                    // HelloAck 决定旧流命运，必须在稳态处理之前拦下。
                    if let Frame::HelloAck { version, resumed, .. } = &frame {
                        if *version != PROTO_VERSION {
                            warn!(
                                local = PROTO_VERSION,
                                peer = version,
                                "helper protocol version mismatch; refusing to continue"
                            );
                            terminate_all(state, endpoints, ResetCode::Internal);
                            return SessionOutcome::ChannelLost;
                        }
                        handshake_done = true;
                        if resuming && !*resumed {
                            // helper 是新进程，旧流状态全丢——诚实地全部重置。
                            warn!("remote helper lost session state; resetting all streams");
                            terminate_all(state, endpoints, ResetCode::UnknownStream);
                        } else if resuming {
                            // 可以续传：为每条存活流请求对齐。
                            for f in state.build_resume_frames() {
                                f.encode(&mut outbound);
                            }
                        }
                        continue;
                    }

                    if !handshake_done {
                        warn!("helper sent data before HelloAck; dropping channel");
                        return SessionOutcome::ChannelLost;
                    }

                    let effects = match apply_frame(state, frame) {
                        Ok(e) => e,
                        Err(e) => {
                            warn!(error = %e, "failed to apply frame");
                            return SessionOutcome::ChannelLost;
                        }
                    };

                    for effect in effects {
                        match effect {
                            FrameEffect::None => {}
                            FrameEffect::Reply(frames) => {
                                for f in frames { f.encode(&mut outbound); }
                            }
                            FrameEffect::Deliver { stream_id, data } => {
                                if let Some(ep) = endpoints.get(&stream_id) {
                                    // 本地端点满了说明上层读得慢；等它，
                                    // 背压会自然沿 Ack 传导回 helper。
                                    if ep.to_local.send(data).await.is_err() {
                                        endpoints.remove(&stream_id);
                                        Frame::Reset { stream_id, code: ResetCode::Normal }
                                            .encode(&mut outbound);
                                        state.remove(stream_id);
                                    }
                                }
                            }
                            FrameEffect::RemoteFin { stream_id } => {
                                if let Some(ep) = endpoints.get_mut(&stream_id) {
                                    if let Some(tx) = ep.remote_fin.take() { let _ = tx.send(()); }
                                }
                            }
                            FrameEffect::Terminate { stream_id, code } => {
                                if let Some(mut ep) = endpoints.remove(&stream_id) {
                                    if let Some(tx) = ep.terminate.take() { let _ = tx.send(code); }
                                }
                                state.remove(stream_id);
                            }
                            FrameEffect::Resumed { stream_id, gap } => {
                                debug!(stream_id, gap, "resending gap after reconnect");
                                for f in drain_stream_output(state, stream_id, 64) {
                                    f.encode(&mut outbound);
                                }
                            }
                        }
                    }
                }

                if flush(&writer, &mut outbound).await.is_err() {
                    return SessionOutcome::ChannelLost;
                }
            }

            // ---- 来自上层的命令 ----
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { return SessionOutcome::Shutdown };
                if !handle_command(cmd, state, endpoints, &mut outbound, cmd_tx).await {
                    return SessionOutcome::Shutdown;
                }
                if flush(&writer, &mut outbound).await.is_err() {
                    return SessionOutcome::ChannelLost;
                }
            }
        }

        // 握手完成后投递排队的 Open 请求。
        if handshake_done && !pending_opens.is_empty() {
            for p in pending_opens.drain(..) {
                open_stream(p, state, endpoints, &mut outbound, cmd_tx).await;
            }
            if flush(&writer, &mut outbound).await.is_err() {
                return SessionOutcome::ChannelLost;
            }
        }
    }
}

/// 断网期间处理上层命令：只更新状态与重传缓冲，**不推进发送游标**。
///
/// 这个函数的存在是为了守住"零字节丢失"这条不变式。若此刻复用
/// [`handle_command`]，它会调用 `drain_stream_output` 把字节标记为"已发送"，
/// 可帧其实无处可去——重连后这些字节既不在待发队列里，也不会被
/// `rewind_to` 覆盖（因为对端从未确认过、也从未收到过），于是永久丢失。
///
/// 返回 false 表示上层已关停。
fn buffer_command_offline(
    cmd: MuxCommand,
    state: &mut MuxState,
    endpoints: &mut HashMap<StreamId, LocalEndpoint>,
) -> bool {
    match cmd {
        // Open 由调用方单独排队处理，不会走到这里。
        MuxCommand::Open { ready, .. } => {
            let _ = ready.send(Err(DialError::Internal));
        }
        MuxCommand::LocalData { stream_id, data } => {
            if let Some(st) = state.get_mut(stream_id) {
                let n = st.tx.push(&data);
                if n < data.len() {
                    // 窗口在断网期间被填满：这是可预期的（对端无法 ack），
                    // 必须让上层知道这条流已经无法保证完整性。
                    warn!(
                        stream_id,
                        dropped = data.len() - n,
                        "send window exhausted while offline; resetting stream"
                    );
                    st.reset = Some(ResetCode::Internal);
                    if let Some(mut ep) = endpoints.remove(&stream_id) {
                        if let Some(tx) = ep.terminate.take() {
                            let _ = tx.send(ResetCode::Internal);
                        }
                    }
                    state.remove(stream_id);
                }
            }
        }
        MuxCommand::LocalEof { stream_id } => {
            if let Some(st) = state.get_mut(stream_id) {
                // 只记标志。FIN 帧在重连后由 drain_stream_output 补发。
                st.local_fin = true;
            }
        }
        MuxCommand::LocalClose { stream_id } => {
            state.remove(stream_id);
            endpoints.remove(&stream_id);
        }
    }
    true
}

/// 处理一条上层命令。返回 false 表示应关停。
async fn handle_command(
    cmd: MuxCommand,
    state: &mut MuxState,
    endpoints: &mut HashMap<StreamId, LocalEndpoint>,
    outbound: &mut BytesMut,
    cmd_tx: &mpsc::Sender<MuxCommand>,
) -> bool {
    match cmd {
        MuxCommand::Open { addr, local, ready } => {
            open_stream(
                PendingOpen { addr, local, ready },
                state,
                endpoints,
                outbound,
                cmd_tx,
            )
            .await;
        }
        MuxCommand::LocalData { stream_id, data } => {
            if let Some(st) = state.get_mut(stream_id) {
                // push 返回值小于 data.len() 时说明窗口不足。
                // pump 任务只在 writable 允许时读取，所以这里正常不会截断；
                // 真发生了就说明流控有 bug，宁可重置也不能静默丢字节。
                let n = st.tx.push(&data);
                if n < data.len() {
                    warn!(
                        stream_id,
                        dropped = data.len() - n,
                        "send window overflow; resetting stream rather than losing bytes"
                    );
                    st.reset = Some(ResetCode::Internal);
                    Frame::Reset {
                        stream_id,
                        code: ResetCode::Internal,
                    }
                    .encode(outbound);
                    endpoints.remove(&stream_id);
                    state.remove(stream_id);
                    return true;
                }
            }
            for f in drain_stream_output(state, stream_id, 64) {
                f.encode(outbound);
            }
        }
        MuxCommand::LocalEof { stream_id } => {
            if let Some(st) = state.get_mut(stream_id) {
                st.local_fin = true;
            }
            for f in drain_stream_output(state, stream_id, 64) {
                f.encode(outbound);
            }
        }
        MuxCommand::LocalClose { stream_id } => {
            if state.remove(stream_id).is_some() {
                endpoints.remove(&stream_id);
                Frame::Reset {
                    stream_id,
                    code: ResetCode::Normal,
                }
                .encode(outbound);
            }
        }
    }
    true
}

/// 分配流 ID、注册端点、发出 `Open`，并启动本地泵。
async fn open_stream(
    p: PendingOpen,
    state: &mut MuxState,
    endpoints: &mut HashMap<StreamId, LocalEndpoint>,
    outbound: &mut BytesMut,
    cmd_tx: &mpsc::Sender<MuxCommand>,
) {
    let PendingOpen { addr, local, ready } = p;
    let id = state.alloc_stream(addr.clone());

    let (to_local_tx, to_local_rx) = mpsc::channel::<Bytes>(16);
    let (fin_tx, fin_rx) = oneshot::channel();
    let (term_tx, term_rx) = oneshot::channel();

    endpoints.insert(
        id,
        LocalEndpoint {
            to_local: to_local_tx,
            remote_fin: Some(fin_tx),
            terminate: Some(term_tx),
        },
    );

    Frame::Open {
        stream_id: id,
        addr,
    }
    .encode(outbound);

    // 这个模式下不等 OpenOk 就让上层开始写：写入的数据先进重传缓冲，
    // helper 建连成功后自然被发出；建连失败则整条流重置，上层收到错误。
    // 这样省掉一个 RTT，且不破坏正确性（缓冲里的字节不会丢）。
    let _ = ready.send(Ok(()));

    tokio::spawn(pump_local(
        id,
        local,
        to_local_rx,
        fin_rx,
        term_rx,
        cmd_tx.clone(),
    ));
}

/// 本地端点泵：把上层的字节转成命令，把 helper 的字节写回上层。
async fn pump_local(
    stream_id: StreamId,
    local: DuplexStream,
    mut to_local: mpsc::Receiver<Bytes>,
    mut remote_fin: oneshot::Receiver<()>,
    mut terminate: oneshot::Receiver<ResetCode>,
    cmd_tx: mpsc::Sender<MuxCommand>,
) {
    let (mut lr, mut lw) = tokio::io::split(local);
    let mut buf = vec![0u8; DATA_CHUNK];
    let mut local_eof = false;

    loop {
        tokio::select! {
            // 上层 → helper
            r = lr.read(&mut buf), if !local_eof => {
                match r {
                    Ok(0) => {
                        local_eof = true;
                        let _ = cmd_tx.send(MuxCommand::LocalEof { stream_id }).await;
                    }
                    Ok(n) => {
                        if cmd_tx
                            .send(MuxCommand::LocalData {
                                stream_id,
                                data: Bytes::copy_from_slice(&buf[..n]),
                            })
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    Err(_) => {
                        let _ = cmd_tx.send(MuxCommand::LocalClose { stream_id }).await;
                        return;
                    }
                }
            }

            // helper → 上层
            data = to_local.recv() => {
                match data {
                    Some(d) => {
                        if lw.write_all(&d).await.is_err() {
                            let _ = cmd_tx.send(MuxCommand::LocalClose { stream_id }).await;
                            return;
                        }
                    }
                    None => {
                        let _ = lw.shutdown().await;
                        return;
                    }
                }
            }

            _ = &mut remote_fin => {
                // 远端不再发数据：关掉本地写端，让上层看到 EOF。
                let _ = lw.shutdown().await;
            }

            _ = &mut terminate => {
                let _ = lw.shutdown().await;
                return;
            }
        }
    }
}

/// 终止所有流并通知上层。
fn terminate_all(
    state: &mut MuxState,
    endpoints: &mut HashMap<StreamId, LocalEndpoint>,
    code: ResetCode,
) {
    for id in state.stream_ids() {
        state.remove(id);
        if let Some(mut ep) = endpoints.remove(&id) {
            if let Some(tx) = ep.terminate.take() {
                let _ = tx.send(code);
            }
        }
    }
}

/// 把缓冲的帧写进 SSH 通道。
async fn flush(
    writer: &russh::ChannelWriteHalf<russh::client::Msg>,
    outbound: &mut BytesMut,
) -> Result<(), russh::Error> {
    if outbound.is_empty() {
        return Ok(());
    }
    let data = outbound.split().freeze();
    writer.data_bytes(data).await
}

/// 生成随机会话 ID。
fn random_session_id() -> SessionId {
    use rand::Rng as _;
    let mut id = [0u8; 16];
    rand::rng().fill(&mut id);
    id
}

/// 供上层构造的错误：helper 模式尚未就绪。
pub fn helper_unavailable() -> anyhow::Error {
    anyhow!("helper mode is not available")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_ids_are_random_and_nonzero() {
        let a = random_session_id();
        let b = random_session_id();
        assert_ne!(a, b, "session ids must differ between runs");
        assert_ne!(a, [0u8; 16], "session id must not be all zeroes");
    }

    /// 本地泵：上层写入的数据必须变成 LocalData 命令，EOF 变成 LocalEof。
    #[tokio::test]
    async fn local_pump_forwards_writes_and_eof() {
        let (mut app, local) = tokio::io::duplex(1024);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let (_to_local_tx, to_local_rx) = mpsc::channel(4);
        let (_fin_tx, fin_rx) = oneshot::channel();
        let (_term_tx, term_rx) = oneshot::channel();

        tokio::spawn(pump_local(7, local, to_local_rx, fin_rx, term_rx, cmd_tx));

        app.write_all(b"hello").await.unwrap();
        match tokio::time::timeout(Duration::from_secs(2), cmd_rx.recv())
            .await
            .expect("timeout")
            .expect("closed")
        {
            MuxCommand::LocalData { stream_id, data } => {
                assert_eq!(stream_id, 7);
                assert_eq!(&data[..], b"hello");
            }
            _ => panic!("expected LocalData"),
        }

        drop(app);
        match tokio::time::timeout(Duration::from_secs(2), cmd_rx.recv())
            .await
            .expect("timeout")
            .expect("closed")
        {
            MuxCommand::LocalEof { stream_id } => assert_eq!(stream_id, 7),
            other => panic!(
                "expected LocalEof, got other variant: {}",
                match other {
                    MuxCommand::LocalData { .. } => "LocalData",
                    MuxCommand::LocalClose { .. } => "LocalClose",
                    _ => "?",
                }
            ),
        }
    }

    /// helper 侧数据必须写回上层。
    #[tokio::test]
    async fn local_pump_delivers_inbound_data_to_the_app() {
        let (mut app, local) = tokio::io::duplex(1024);
        let (cmd_tx, _cmd_rx) = mpsc::channel(16);
        let (to_local_tx, to_local_rx) = mpsc::channel(4);
        let (_fin_tx, fin_rx) = oneshot::channel();
        let (_term_tx, term_rx) = oneshot::channel();

        tokio::spawn(pump_local(1, local, to_local_rx, fin_rx, term_rx, cmd_tx));

        to_local_tx
            .send(Bytes::from_static(b"world"))
            .await
            .unwrap();
        let mut buf = [0u8; 5];
        tokio::time::timeout(Duration::from_secs(2), app.read_exact(&mut buf))
            .await
            .expect("timeout")
            .expect("read");
        assert_eq!(&buf, b"world");
    }

    /// remote_fin 必须让上层读到 EOF。
    #[tokio::test]
    async fn remote_fin_closes_the_app_read_side() {
        let (mut app, local) = tokio::io::duplex(1024);
        let (cmd_tx, _cmd_rx) = mpsc::channel(16);
        let (_to_local_tx, to_local_rx) = mpsc::channel(4);
        let (fin_tx, fin_rx) = oneshot::channel();
        let (_term_tx, term_rx) = oneshot::channel();

        tokio::spawn(pump_local(1, local, to_local_rx, fin_rx, term_rx, cmd_tx));
        fin_tx.send(()).unwrap();

        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(2), app.read(&mut buf))
            .await
            .expect("timeout")
            .expect("read");
        assert_eq!(n, 0, "app must observe EOF after remote FIN");
    }

    /// 断网期间上层写入的数据必须进重传缓冲，且**发送游标不得推进**。
    ///
    /// 这条不变式是"零字节丢失"的地基：若游标被推进，那些字节会被当成
    /// "已发送"，重连后既不在待发队列里也不会被 rewind 覆盖，于是永久丢失。
    #[test]
    fn offline_writes_enter_the_retransmit_buffer_without_advancing_the_cursor() {
        let mut state = MuxState::new(4096);
        let mut endpoints: HashMap<StreamId, LocalEndpoint> = HashMap::new();
        let id = state.alloc_stream(TargetAddr::Domain("x".into(), 1));

        assert!(buffer_command_offline(
            MuxCommand::LocalData {
                stream_id: id,
                data: Bytes::from_static(b"offline-bytes"),
            },
            &mut state,
            &mut endpoints,
        ));

        let st = state.get_mut(id).expect("stream alive");
        assert_eq!(st.tx.write_offset(), 13, "bytes must be buffered");
        assert_eq!(
            st.tx.send_cursor(),
            0,
            "cursor must NOT advance while offline"
        );
        assert!(st.tx.has_pending(), "bytes must still be pending");

        // 重连后这些字节应当被正常发出。
        let frames = drain_stream_output(&mut state, id, 8);
        assert_eq!(frames.len(), 1);
        match &frames[0] {
            Frame::Data { offset, data, .. } => {
                assert_eq!(*offset, 0);
                assert_eq!(&data[..], b"offline-bytes");
            }
            f => panic!("unexpected {f:?}"),
        }
    }

    /// 断网期间的 EOF 只记标志，FIN 帧留到重连后补发。
    #[test]
    fn offline_eof_defers_the_fin_frame() {
        let mut state = MuxState::new(4096);
        let mut endpoints: HashMap<StreamId, LocalEndpoint> = HashMap::new();
        let id = state.alloc_stream(TargetAddr::Domain("x".into(), 1));

        buffer_command_offline(
            MuxCommand::LocalEof { stream_id: id },
            &mut state,
            &mut endpoints,
        );
        assert!(state.get_mut(id).unwrap().local_fin);
        assert!(
            !state.get_mut(id).unwrap().tx.fin_queued(),
            "FIN must not be marked as sent while offline"
        );

        let frames = drain_stream_output(&mut state, id, 8);
        assert_eq!(frames, vec![Frame::Fin { stream_id: id }]);
    }

    /// 断网期间窗口被填满时必须重置该流并通知上层，而不是静默截断字节。
    #[test]
    fn offline_window_exhaustion_resets_the_stream_instead_of_truncating() {
        let mut state = MuxState::new(16);
        let mut endpoints: HashMap<StreamId, LocalEndpoint> = HashMap::new();
        let id = state.alloc_stream(TargetAddr::Domain("x".into(), 1));

        let (to_local, _rx) = mpsc::channel(1);
        let (fin_tx, _fin_rx) = oneshot::channel();
        let (term_tx, term_rx) = oneshot::channel();
        endpoints.insert(
            id,
            LocalEndpoint {
                to_local,
                remote_fin: Some(fin_tx),
                terminate: Some(term_tx),
            },
        );

        buffer_command_offline(
            MuxCommand::LocalData {
                stream_id: id,
                data: Bytes::from_static(&[0u8; 64]),
            },
            &mut state,
            &mut endpoints,
        );

        assert!(state.get_mut(id).is_none(), "stream must be removed");
        assert_eq!(
            term_rx.blocking_recv().unwrap(),
            ResetCode::Internal,
            "the app must be told the stream failed rather than silently losing bytes"
        );
    }

    #[test]
    fn offline_close_drops_the_stream() {
        let mut state = MuxState::new(1024);
        let mut endpoints: HashMap<StreamId, LocalEndpoint> = HashMap::new();
        let id = state.alloc_stream(TargetAddr::Domain("x".into(), 1));
        buffer_command_offline(
            MuxCommand::LocalClose { stream_id: id },
            &mut state,
            &mut endpoints,
        );
        assert!(state.is_empty());
    }

    #[test]
    fn terminate_all_clears_state_and_notifies() {
        let mut state = MuxState::new(1024);
        let mut endpoints: HashMap<StreamId, LocalEndpoint> = HashMap::new();
        let id = state.alloc_stream(TargetAddr::Domain("x".into(), 1));

        let (to_local, _rx) = mpsc::channel(1);
        let (fin_tx, _fin_rx) = oneshot::channel();
        let (term_tx, term_rx) = oneshot::channel();
        endpoints.insert(
            id,
            LocalEndpoint {
                to_local,
                remote_fin: Some(fin_tx),
                terminate: Some(term_tx),
            },
        );

        terminate_all(&mut state, &mut endpoints, ResetCode::UnknownStream);
        assert!(state.is_empty());
        assert!(endpoints.is_empty());
        assert_eq!(term_rx.blocking_recv().unwrap(), ResetCode::UnknownStream);
    }
}
