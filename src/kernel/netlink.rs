//! rtnetlink on the compio runtime.

use std::{
    io,
    os::fd::{AsFd, OwnedFd},
    task::{Context, Poll},
};

use compio::runtime::fd::PollFd;
use netlink_sys::{AsyncSocket, Socket, SocketAddr};
use rtnetlink::Handle;

/// Opens an rtnetlink connection whose I/O task runs on the current compio
/// runtime.
pub fn connect() -> io::Result<Handle> {
    let (connection, handle, _) = rtnetlink::new_connection_with_socket::<CompioSocket>()?;
    compio::runtime::spawn(connection).detach();
    Ok(handle)
}

pub struct CompioSocket {
    socket: Socket,
    /// A duplicate of the socket's descriptor that waits for readiness.
    /// `socket_mut` must hand out the socket mutably, which `PollFd` does not
    /// allow for the descriptor it owns.
    poll: PollFd<OwnedFd>,
}

impl AsyncSocket for CompioSocket {
    fn socket_ref(&self) -> &Socket {
        &self.socket
    }

    fn socket_mut(&mut self) -> &mut Socket {
        &mut self.socket
    }

    fn new(protocol: isize) -> io::Result<Self> {
        let socket = Socket::new(protocol)?;
        socket.set_non_blocking(true)?;
        let poll = PollFd::new(socket.as_fd().try_clone_to_owned()?)?;
        Ok(Self { socket, poll })
    }

    fn poll_send(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.poll.poll_write_with(cx, |_| self.socket.send(buf, 0))
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        addr: &SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.poll
            .poll_write_with(cx, |_| self.socket.send_to(buf, addr, 0))
    }

    fn poll_recv<B: bytes::BufMut>(
        &self,
        cx: &mut Context<'_>,
        buf: &mut B,
    ) -> Poll<io::Result<()>> {
        self.poll
            .poll_read_with(cx, |_| self.socket.recv(buf, 0).map(drop))
    }

    fn poll_recv_from<B: bytes::BufMut>(
        &self,
        cx: &mut Context<'_>,
        buf: &mut B,
    ) -> Poll<io::Result<SocketAddr>> {
        self.poll
            .poll_read_with(cx, |_| self.socket.recv_from(buf, 0).map(|(_, addr)| addr))
    }

    fn poll_recv_from_full(&self, cx: &mut Context<'_>) -> Poll<io::Result<(Vec<u8>, SocketAddr)>> {
        self.poll
            .poll_read_with(cx, |_| self.socket.recv_from_full())
    }
}
