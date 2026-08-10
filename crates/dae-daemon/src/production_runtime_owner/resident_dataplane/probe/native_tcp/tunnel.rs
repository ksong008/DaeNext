use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::task::JoinHandle;
use tokio::time::{self, Sleep};

use super::super::super::{RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE, SharedResidentStopSignal};

pub(super) trait NativeTcpTunnel: AsyncRead + AsyncWrite + Unpin + Send {
    fn poll_cleanup(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

pub(super) fn boxed_native_tcp_tunnel<T>(stream: T) -> Box<dyn NativeTcpTunnel>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    Box::new(PlainNativeTcpTunnel { stream })
}

pub(super) async fn cleanup_native_tcp_tunnel(tunnel: &mut dyn NativeTcpTunnel) -> io::Result<()> {
    std::future::poll_fn(|cx| tunnel.poll_cleanup(cx)).await
}

struct PlainNativeTcpTunnel<T> {
    stream: T,
}

impl<T> NativeTcpTunnel for PlainNativeTcpTunnel<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn poll_cleanup(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl<T> AsyncRead for PlainNativeTcpTunnel<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for PlainNativeTcpTunnel<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

pub(super) struct PrefixedNativeTcpTunnel<T> {
    prefix: Vec<u8>,
    offset: usize,
    stream: T,
}

impl<T> PrefixedNativeTcpTunnel<T> {
    pub(super) fn new(prefix: Vec<u8>, stream: T) -> Self {
        Self {
            prefix,
            offset: 0,
            stream,
        }
    }
}

impl<T> AsyncRead for PrefixedNativeTcpTunnel<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.offset < self.prefix.len() && buf.remaining() > 0 {
            let available = &self.prefix[self.offset..];
            let len = available.len().min(buf.remaining());
            buf.put_slice(&available[..len]);
            self.offset += len;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for PrefixedNativeTcpTunnel<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

pub(super) struct SpawnedNativeTcpTunnel<T = DuplexStream> {
    stream: T,
    task: Option<JoinHandle<()>>,
    stop: SharedResidentStopSignal,
    cleanup_grace: Duration,
    cleanup_deadline: Option<Pin<Box<Sleep>>>,
    abort_requested: bool,
}

impl<T> SpawnedNativeTcpTunnel<T> {
    pub(super) fn new(stream: T, task: JoinHandle<()>, stop: SharedResidentStopSignal) -> Self {
        Self::with_cleanup_grace(stream, task, stop, RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
    }

    fn with_cleanup_grace(
        stream: T,
        task: JoinHandle<()>,
        stop: SharedResidentStopSignal,
        cleanup_grace: Duration,
    ) -> Self {
        Self {
            stream,
            task: Some(task),
            stop,
            cleanup_grace,
            cleanup_deadline: None,
            abort_requested: false,
        }
    }

    fn poll_task_join(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let Some(task) = self.task.as_mut() else {
            return Poll::Ready(());
        };
        match Pin::new(task).poll(cx) {
            Poll::Ready(_) => {
                self.task = None;
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T> NativeTcpTunnel for SpawnedNativeTcpTunnel<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn poll_cleanup(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stop.store(true, Ordering::Release);
        if self.cleanup_deadline.is_none() {
            self.cleanup_deadline = Some(Box::pin(time::sleep(self.cleanup_grace)));
        }
        let shutdown = Pin::new(&mut self.stream).poll_shutdown(cx);
        if self.poll_task_join(cx).is_ready() {
            return match shutdown {
                Poll::Ready(result) => Poll::Ready(result),
                Poll::Pending => Poll::Ready(Ok(())),
            };
        }

        let cleanup_expired = self
            .cleanup_deadline
            .as_mut()
            .is_some_and(|deadline| deadline.as_mut().poll(cx).is_ready());
        if cleanup_expired && !self.abort_requested {
            if let Some(task) = self.task.as_ref() {
                task.abort();
            }
            self.abort_requested = true;
        }
        if self.abort_requested && self.poll_task_join(cx).is_ready() {
            return Poll::Ready(match shutdown {
                Poll::Ready(result) => result,
                Poll::Pending => Ok(()),
            });
        }
        Poll::Pending
    }
}

impl<T> Drop for SpawnedNativeTcpTunnel<T> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
    }
}

impl<T> AsyncRead for SpawnedNativeTcpTunnel<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for SpawnedNativeTcpTunnel<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use crate::production_runtime_owner::resident_dataplane::ResidentStopSignal;
    use rcgen::generate_simple_self_signed;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls;
    use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn spawned_tunnel_forwards_rustls_application_read_wake() {
        let certified = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let certificate = certified.cert.der().clone();
        let private_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let server_config =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(vec![certificate.clone()], private_key)
                .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let (probe_side, server_side) = tokio::io::duplex(64 * 1024);
        let (first_poll_tx, first_poll_rx) = oneshot::channel();
        let relay_task = tokio::spawn(async move {
            let mut tls = acceptor.accept(server_side).await.unwrap();
            let mut request = [0_u8; 1];
            tls.read_exact(&mut request).await.unwrap();
            first_poll_rx.await.unwrap();
            tls.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
            tls.flush().await.unwrap();
        });
        let stop = ResidentStopSignal::shared();
        let mut tunnel = SpawnedNativeTcpTunnel::new(probe_side, relay_task, stop);
        let server_name = ServerName::try_from("localhost".to_owned()).unwrap();
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(client_config))
            .connect(server_name, &mut tunnel)
            .await
            .unwrap();
        tls.write_all(b"x").await.unwrap();
        tls.flush().await.unwrap();
        let mut first_poll_tx = Some(first_poll_tx);
        let mut buf = [0_u8; 32];
        let read = tokio::time::timeout(
            Duration::from_secs(1),
            std::future::poll_fn(|cx| {
                if let Some(tx) = first_poll_tx.take() {
                    let _ = tx.send(());
                }
                let mut read_buf = ReadBuf::new(&mut buf);
                match Pin::new(&mut tls).poll_read(cx, &mut read_buf) {
                    Poll::Ready(result) => Poll::Ready(result.map(|_| read_buf.filled().len())),
                    Poll::Pending => Poll::Pending,
                }
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(read > 0);
        drop(tls);
        cleanup_native_tcp_tunnel(&mut tunnel).await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cleanup_requests_stop_and_joins_the_relay() {
        let (probe, _relay) = tokio::io::duplex(64);
        let stop = ResidentStopSignal::shared();
        let mut listener = stop.listener();
        let task = tokio::spawn(async move { listener.cancelled().await });
        let mut tunnel = SpawnedNativeTcpTunnel::with_cleanup_grace(
            probe,
            task,
            Arc::clone(&stop),
            Duration::from_millis(10),
        );
        tokio::time::sleep(Duration::from_millis(20)).await;

        cleanup_native_tcp_tunnel(&mut tunnel).await.unwrap();

        assert!(stop.load(Ordering::Acquire));
        assert!(tunnel.task.is_none());
        assert!(!tunnel.abort_requested);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cleanup_escalates_to_abort_and_awaits_cancellation() {
        let (probe, _relay) = tokio::io::duplex(64);
        let stop = ResidentStopSignal::shared();
        let task = tokio::spawn(std::future::pending::<()>());
        let mut tunnel = SpawnedNativeTcpTunnel::with_cleanup_grace(
            probe,
            task,
            stop,
            Duration::from_millis(10),
        );

        tokio::time::timeout(
            Duration::from_secs(1),
            cleanup_native_tcp_tunnel(&mut tunnel),
        )
        .await
        .expect("cleanup timeout")
        .unwrap();

        assert!(tunnel.task.is_none());
        assert!(tunnel.abort_requested);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cleanup_awaits_cancellation_for_many_stalled_relays() {
        const STALLED_RELAY_COUNT: usize = 1_024;

        struct ActiveRelayGuard(Arc<AtomicUsize>);

        impl Drop for ActiveRelayGuard {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::AcqRel);
            }
        }

        let active_relays = Arc::new(AtomicUsize::new(0));
        let mut tunnels = Vec::with_capacity(STALLED_RELAY_COUNT);
        for _ in 0..STALLED_RELAY_COUNT {
            let (probe, _relay) = tokio::io::duplex(64);
            let stop = ResidentStopSignal::shared();
            let task_active_relays = Arc::clone(&active_relays);
            let task = tokio::spawn(async move {
                task_active_relays.fetch_add(1, Ordering::AcqRel);
                let _active = ActiveRelayGuard(task_active_relays);
                std::future::pending::<()>().await;
            });
            tunnels.push(SpawnedNativeTcpTunnel::with_cleanup_grace(
                probe,
                task,
                stop,
                Duration::ZERO,
            ));
        }

        time::timeout(Duration::from_secs(5), async {
            while active_relays.load(Ordering::Acquire) != STALLED_RELAY_COUNT {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("stalled relay startup timeout");

        let mut cleanups = tokio::task::JoinSet::new();
        for mut tunnel in tunnels {
            cleanups.spawn(async move {
                cleanup_native_tcp_tunnel(&mut tunnel).await.unwrap();
                assert!(tunnel.task.is_none());
                assert!(tunnel.abort_requested);
            });
        }
        time::timeout(Duration::from_secs(5), async {
            while let Some(result) = cleanups.join_next().await {
                result.unwrap();
            }
        })
        .await
        .expect("stalled relay cleanup timeout");

        assert_eq!(active_relays.load(Ordering::Acquire), 0);
    }
}
