//! Receive slab reservations selected before binding, also used by replacement sockets.
use dae_resident_core::{ResidentRuntimeProfile, ResidentRuntimeProfileSelection};
use std::{
    future::Future,
    io,
    io::IoSliceMut,
    net::UdpSocket,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

pub(super) fn selected_segments() -> usize {
    match ResidentRuntimeProfileSelection::selected().profile {
        ResidentRuntimeProfile::LowMemory => 1,
        ResidentRuntimeProfile::Balanced => 64,
        ResidentRuntimeProfile::HighPerformance => 64,
    }
}

pub(crate) fn tiered_runtime(inner: Arc<dyn quinn::Runtime>) -> Arc<dyn quinn::Runtime> {
    Arc::new(ReceiveTierRuntime {
        inner,
        segments: selected_segments(),
    })
}

#[derive(Debug)]
struct ReceiveTierRuntime {
    inner: Arc<dyn quinn::Runtime>,
    segments: usize,
}

impl quinn::Runtime for ReceiveTierRuntime {
    fn new_timer(&self, instant: std::time::Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        self.inner.new_timer(instant)
    }
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.inner.spawn(future);
    }
    fn now(&self) -> std::time::Instant {
        self.inner.now()
    }
    fn wrap_udp_socket(&self, socket: UdpSocket) -> io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        #[cfg(target_os = "linux")]
        let handle = socket.try_clone()?;
        let inner = self.inner.wrap_udp_socket(socket)?;
        let segments = inner.max_receive_segments().min(self.segments);
        if segments >= inner.max_receive_segments() {
            return Ok(inner);
        }
        // A smaller advertised slab MUST NOT receive a 64-segment kernel GRO
        // packet. Only the low-memory profile trades GRO for bounded slab capacity.
        // Keep the conservative tier reservation even with GRO disabled.
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let disabled: libc::c_int = 0;
            let result = unsafe {
                libc::setsockopt(
                    handle.as_raw_fd(),
                    libc::SOL_UDP,
                    libc::UDP_GRO,
                    (&disabled as *const libc::c_int).cast(),
                    std::mem::size_of_val(&disabled) as libc::socklen_t,
                )
            };
            if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ENOPROTOOPT) {
                return Err(io::Error::last_os_error());
            }
        }
        // Other platforms retain their native capability rather than claim a
        // reduced cap without a verified GRO control.
        #[cfg(not(target_os = "linux"))]
        return Ok(inner);
        #[cfg(target_os = "linux")]
        Ok(Arc::new(ReceiveTierSocket { inner, segments }))
    }
}

#[derive(Debug)]
struct ReceiveTierSocket {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    segments: usize,
}
impl quinn::AsyncUdpSocket for ReceiveTierSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }
    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        self.inner.try_send(transmit)
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }
    fn max_receive_segments(&self) -> usize {
        self.segments
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests;
