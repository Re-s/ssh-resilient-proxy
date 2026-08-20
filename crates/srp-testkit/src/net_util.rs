//! TCP 层的低级工具：用于制造"真的能被对端观察到"的连接中断。

use std::net::Shutdown;
use std::time::Duration;

use socket2::{SockRef, Socket};
use tokio::net::TcpStream;

/// 把一个 socket 置为"立即硬断"状态：
///
/// 1. `SO_LINGER = 0`：之后 `close(2)` 会发 RST 而不是走正常的 FIN/TIME_WAIT；
/// 2. `shutdown(BOTH)`：立刻让对端读到 EOF、让本端所有 pending I/O 出错。
///
/// 两步都是幂等的，错误一律忽略（socket 可能已经被对端关掉了）。
/// 单独 `shutdown` 只会发 FIN，所以这里配合 `SO_LINGER=0`：真正 `drop` 该
/// socket 时内核会补一个 RST，客户端无论处于读还是写都能立刻观察到断开。
pub(crate) fn hard_reset(socket: &SockRef<'_>) {
    let _ = socket.set_linger(Some(Duration::ZERO));
    let _ = socket.shutdown(Shutdown::Both);
}

/// 对 tokio 的 `TcpStream` 做 [`hard_reset`]。
pub(crate) fn hard_reset_stream(stream: &TcpStream) {
    hard_reset(&SockRef::from(stream));
}

/// 硬断并立即释放：`drop` 会执行 `close(2)`，此时 `SO_LINGER=0` 生效，发 RST。
pub(crate) fn hard_reset_and_drop(stream: TcpStream) {
    hard_reset_stream(&stream);
    drop(stream);
}

/// 复制（`dup(2)`）一个 `TcpStream` 的文件描述符，得到一个独立句柄。
///
/// russh 的 `run_stream` 会拿走 `TcpStream` 的所有权，所以想在之后还能强杀这条
/// 连接，就必须提前留一个 dup 出来的句柄：`shutdown`/`setsockopt` 作用在底层
/// socket 上，dup 出来的 fd 和原 fd 共享同一个 socket。
pub(crate) fn dup_socket(stream: &TcpStream) -> std::io::Result<Socket> {
    SockRef::from(stream).try_clone()
}

/// 对 dup 出来的句柄做硬断，然后关闭这个 fd（原 fd 仍由 russh 持有）。
pub(crate) fn hard_reset_dup(socket: &Socket) {
    let _ = socket.set_linger(Some(Duration::ZERO));
    let _ = socket.shutdown(Shutdown::Both);
}
