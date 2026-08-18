use std::io::{self, IoSliceMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use super::metrics::QuicEndpointObservation;

pub(super) struct ObservedQuicUdpSocket {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    observation: Arc<QuicEndpointObservation>,
}

impl std::fmt::Debug for ObservedQuicUdpSocket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ObservedQuicUdpSocket")
            .field("inner", &self.inner)
            .field("provenance", &self.observation.provenance())
            .finish()
    }
}

impl ObservedQuicUdpSocket {
    pub(super) fn new(
        inner: Arc<dyn quinn::AsyncUdpSocket>,
        observation: Arc<QuicEndpointObservation>,
    ) -> Self {
        observation.udp_fd_opened();
        Self { inner, observation }
    }
}

impl Drop for ObservedQuicUdpSocket {
    fn drop(&mut self) {
        self.observation.udp_fd_closed();
    }
}

impl quinn::AsyncUdpSocket for ObservedQuicUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        let inner = Arc::clone(&self.inner).create_io_poller();
        Box::pin(ObservedQuicUdpPoller {
            inner,
            socket_lifetime: self,
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        context: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(context, buffers, metadata)
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

struct ObservedQuicUdpPoller {
    inner: Pin<Box<dyn quinn::UdpPoller>>,
    socket_lifetime: Arc<ObservedQuicUdpSocket>,
}

impl std::fmt::Debug for ObservedQuicUdpPoller {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ObservedQuicUdpPoller")
            .field("inner", &self.inner)
            .field("socket", &self.socket_lifetime)
            .finish()
    }
}

impl quinn::UdpPoller for ObservedQuicUdpPoller {
    fn poll_writable(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.as_mut().poll_writable(context)
    }
}
