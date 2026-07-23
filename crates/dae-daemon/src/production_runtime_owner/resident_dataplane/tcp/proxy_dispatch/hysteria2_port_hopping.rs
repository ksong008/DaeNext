use super::*;

use std::fmt;
use std::future::{Future, poll_fn};
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use quinn::udp;
use serde_json::{Value, json};

#[derive(Default)]
pub(crate) struct Hysteria2PortHoppingMetrics {
    active_sockets: AtomicUsize,
    high_water_sockets: AtomicUsize,
    active_transitions: AtomicUsize,
    high_water_transitions: AtomicUsize,
    cumulative_attempts: AtomicU64,
    cumulative_successes: AtomicU64,
    cumulative_failures: AtomicU64,
    cumulative_transition_nanos: AtomicU64,
    last_transition_nanos: AtomicU64,
}

impl Hysteria2PortHoppingMetrics {
    fn socket_opened(&self) {
        let active = self.active_sockets.fetch_add(1, Ordering::AcqRel) + 1;
        update_hysteria2_port_hopping_high_water(&self.high_water_sockets, active);
    }

    fn sockets_closed(&self, count: usize) {
        let _ = self
            .active_sockets
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |active| {
                Some(active.saturating_sub(count))
            });
    }

    fn transition_started(&self) {
        self.cumulative_attempts.fetch_add(1, Ordering::Relaxed);
        let active = self.active_transitions.fetch_add(1, Ordering::AcqRel) + 1;
        update_hysteria2_port_hopping_high_water(&self.high_water_transitions, active);
    }

    fn transition_finished(&self, started: Instant, succeeded: bool) {
        let nanos = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
        self.last_transition_nanos.store(nanos, Ordering::Relaxed);
        self.cumulative_transition_nanos
            .fetch_add(nanos, Ordering::Relaxed);
        if succeeded {
            self.cumulative_successes.fetch_add(1, Ordering::Relaxed);
        } else {
            self.cumulative_failures.fetch_add(1, Ordering::Relaxed);
        }
        let _ =
            self.active_transitions
                .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |active| {
                    Some(active.saturating_sub(1))
                });
    }

    pub(crate) fn snapshot(&self) -> Value {
        json!({
            "schemaVersion": 1,
            "activeSockets": self.active_sockets.load(Ordering::Relaxed),
            "highWaterSockets": self.high_water_sockets.load(Ordering::Relaxed),
            "activeTransitions": self.active_transitions.load(Ordering::Relaxed),
            "highWaterTransitions": self.high_water_transitions.load(Ordering::Relaxed),
            "cumulativeAttempts": self.cumulative_attempts.load(Ordering::Relaxed),
            "cumulativeSuccesses": self.cumulative_successes.load(Ordering::Relaxed),
            "cumulativeFailures": self.cumulative_failures.load(Ordering::Relaxed),
            "cumulativeTransitionNanos": self.cumulative_transition_nanos.load(Ordering::Relaxed),
            "lastTransitionNanos": self.last_transition_nanos.load(Ordering::Relaxed),
        })
    }
}

fn update_hysteria2_port_hopping_high_water(high_water: &AtomicUsize, value: usize) {
    let mut current = high_water.load(Ordering::Relaxed);
    while value > current {
        match high_water.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

#[derive(Clone)]
pub(crate) struct Hysteria2PortHoppingRuntimeConfig {
    pub(crate) addresses: Arc<Vec<IpAddr>>,
    pub(crate) ports: Arc<Vec<u16>>,
    pub(crate) interval: Duration,
    pub(crate) mark: u32,
    pub(crate) transition_socket_limit: usize,
    pub(crate) metrics: Arc<Hysteria2PortHoppingMetrics>,
}

impl Hysteria2PortHoppingRuntimeConfig {
    pub(crate) fn new(
        addresses: Vec<IpAddr>,
        ports: Arc<Vec<u16>>,
        interval: Duration,
        mark: u32,
        transition_socket_limit: usize,
        metrics: Arc<Hysteria2PortHoppingMetrics>,
    ) -> Result<Self, String> {
        if addresses.is_empty() {
            return Err("Hysteria2 port hopping needs a resolved address".to_owned());
        }
        if ports.is_empty() {
            return Err("Hysteria2 port hopping needs a normalized port".to_owned());
        }
        if interval.is_zero() {
            return Err("Hysteria2 port hopping interval must be nonzero".to_owned());
        }
        if transition_socket_limit < 3 {
            return Err(
                "Hysteria2 port hopping transition socket budget must cover three sockets"
                    .to_owned(),
            );
        }
        Ok(Self {
            addresses: Arc::new(addresses),
            ports,
            interval,
            mark,
            transition_socket_limit,
            metrics,
        })
    }
}

pub(crate) struct Hysteria2PortHoppingRuntime {
    inner: Arc<dyn quinn::Runtime>,
    config: Hysteria2PortHoppingRuntimeConfig,
    logical_remote: SocketAddr,
}

impl Hysteria2PortHoppingRuntime {
    pub(crate) fn new(
        inner: Arc<dyn quinn::Runtime>,
        config: Hysteria2PortHoppingRuntimeConfig,
        logical_remote: SocketAddr,
    ) -> Self {
        Self {
            inner,
            config,
            logical_remote,
        }
    }
}

impl fmt::Debug for Hysteria2PortHoppingRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Hysteria2PortHoppingRuntime")
            .field("inner", &self.inner)
            .field("addressCount", &self.config.addresses.len())
            .field("portCount", &self.config.ports.len())
            .field("interval", &self.config.interval)
            .field("logicalRemote", &self.logical_remote)
            .finish_non_exhaustive()
    }
}

impl quinn::Runtime for Hysteria2PortHoppingRuntime {
    fn new_timer(&self, instant: std::time::Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        self.inner.new_timer(instant)
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.inner.spawn(future);
    }

    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        let logical_local = socket.local_addr()?;
        let bind = SocketAddr::new(logical_local.ip(), 0);
        let initial = self.inner.wrap_udp_socket(socket)?;
        self.config.metrics.socket_opened();
        let state = Arc::new(Hysteria2PortHoppingState {
            runtime: Arc::clone(&self.inner),
            addresses: Arc::clone(&self.config.addresses),
            ports: Arc::clone(&self.config.ports),
            interval: self.config.interval,
            mark: self.config.mark,
            transition_socket_limit: self.config.transition_socket_limit,
            bind,
            logical_remote: self.logical_remote,
            metrics: Arc::clone(&self.config.metrics),
            paths: std::sync::RwLock::new(Hysteria2PortHoppingPaths {
                current: initial,
                previous: None,
                destination: self.logical_remote,
                generation: 1,
            }),
        });
        let weak = Arc::downgrade(&state);
        let runtime = Arc::clone(&self.inner);
        self.inner.spawn(Box::pin(async move {
            run_hysteria2_port_hopping(weak, runtime).await;
        }));
        Ok(Arc::new(Hysteria2PortHoppingUdpSocket {
            state,
            poll_previous_first: AtomicBool::new(false),
        }))
    }

    fn now(&self) -> std::time::Instant {
        self.inner.now()
    }
}

struct Hysteria2PortHoppingPaths {
    current: Arc<dyn quinn::AsyncUdpSocket>,
    previous: Option<Arc<dyn quinn::AsyncUdpSocket>>,
    destination: SocketAddr,
    generation: u64,
}

struct Hysteria2PortHoppingState {
    runtime: Arc<dyn quinn::Runtime>,
    addresses: Arc<Vec<IpAddr>>,
    ports: Arc<Vec<u16>>,
    interval: Duration,
    mark: u32,
    transition_socket_limit: usize,
    bind: SocketAddr,
    logical_remote: SocketAddr,
    metrics: Arc<Hysteria2PortHoppingMetrics>,
    paths: std::sync::RwLock<Hysteria2PortHoppingPaths>,
}

impl Hysteria2PortHoppingState {
    fn hop(&self) {
        let started = Instant::now();
        self.metrics.transition_started();
        let active_socket_count = {
            let paths = self.paths.read().unwrap();
            1 + usize::from(paths.previous.is_some())
        };
        if active_socket_count.saturating_add(1) > self.transition_socket_limit {
            self.metrics.transition_finished(started, false);
            return;
        }
        let socket = match std::net::UdpSocket::bind(self.bind) {
            Ok(socket) => socket,
            Err(_) => {
                self.metrics.transition_finished(started, false);
                return;
            }
        };
        if self.mark != 0 && set_socket_mark(socket.as_raw_fd(), self.mark).is_err() {
            self.metrics.transition_finished(started, false);
            return;
        }
        let next = match self.runtime.wrap_udp_socket(socket) {
            Ok(socket) => socket,
            Err(_) => {
                self.metrics.transition_finished(started, false);
                return;
            }
        };
        self.metrics.socket_opened();
        let dropped_previous = {
            let mut paths = self.paths.write().unwrap();
            paths.destination =
                select_hysteria2_hop_remote(&self.addresses, &self.ports, paths.destination);
            let old_current = std::mem::replace(&mut paths.current, next);
            let dropped_previous = paths.previous.replace(old_current).is_some();
            paths.generation = paths.generation.wrapping_add(1).max(1);
            dropped_previous
        };
        if dropped_previous {
            self.metrics.sockets_closed(1);
        }
        self.metrics.transition_finished(started, true);
    }

    fn rewrite_received_remote(&self, metadata: &mut [udp::RecvMeta], count: usize) {
        for received in metadata.iter_mut().take(count) {
            received.addr = self.logical_remote;
        }
    }
}

fn select_hysteria2_hop_remote(
    addresses: &[IpAddr],
    ports: &[u16],
    current: SocketAddr,
) -> SocketAddr {
    let address_index = fastrand::usize(..addresses.len());
    let port_index = fastrand::usize(..ports.len());
    let mut selected = SocketAddr::new(addresses[address_index], ports[port_index]);
    if selected == current && addresses.len().saturating_mul(ports.len()) > 1 {
        selected = if ports.len() > 1 {
            SocketAddr::new(
                addresses[address_index],
                ports[(port_index + 1) % ports.len()],
            )
        } else {
            SocketAddr::new(
                addresses[(address_index + 1) % addresses.len()],
                ports[port_index],
            )
        };
    }
    selected
}

impl Drop for Hysteria2PortHoppingState {
    fn drop(&mut self) {
        let socket_count = self
            .paths
            .get_mut()
            .map(|paths| 1 + usize::from(paths.previous.is_some()))
            .unwrap_or(0);
        self.metrics.sockets_closed(socket_count);
    }
}

async fn run_hysteria2_port_hopping(
    state: std::sync::Weak<Hysteria2PortHoppingState>,
    runtime: Arc<dyn quinn::Runtime>,
) {
    loop {
        let Some(active) = state.upgrade() else {
            return;
        };
        let wake_at = runtime
            .now()
            .checked_add(active.interval)
            .unwrap_or_else(|| runtime.now());
        drop(active);
        let mut timer = runtime.new_timer(wake_at);
        poll_fn(|context| timer.as_mut().poll(context)).await;
        let Some(active) = state.upgrade() else {
            return;
        };
        active.hop();
    }
}

struct Hysteria2PortHoppingUdpSocket {
    state: Arc<Hysteria2PortHoppingState>,
    poll_previous_first: AtomicBool,
}

impl fmt::Debug for Hysteria2PortHoppingUdpSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Hysteria2PortHoppingUdpSocket")
            .field("bind", &self.state.bind)
            .field("remote", &self.state.logical_remote)
            .field("addressCount", &self.state.addresses.len())
            .field("portCount", &self.state.ports.len())
            .finish_non_exhaustive()
    }
}

impl quinn::AsyncUdpSocket for Hysteria2PortHoppingUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        let (socket, generation) = {
            let paths = self.state.paths.read().unwrap();
            (Arc::clone(&paths.current), paths.generation)
        };
        let poller = Arc::clone(&socket).create_io_poller();
        Box::pin(Hysteria2PortHoppingPoller {
            state: Arc::clone(&self.state),
            socket,
            generation,
            poller,
        })
    }

    fn try_send(&self, transmit: &udp::Transmit<'_>) -> io::Result<()> {
        let (socket, destination) = {
            let paths = self.state.paths.read().unwrap();
            (Arc::clone(&paths.current), paths.destination)
        };
        let transmit = udp::Transmit {
            destination,
            ecn: transmit.ecn,
            contents: transmit.contents,
            segment_size: transmit.segment_size,
            src_ip: transmit.src_ip,
        };
        socket.try_send(&transmit)
    }

    fn poll_recv(
        &self,
        context: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let (current, previous) = {
            let paths = self.state.paths.read().unwrap();
            (Arc::clone(&paths.current), paths.previous.clone())
        };
        let Some(previous) = previous else {
            return self.poll_receive_path(&current, context, buffers, metadata);
        };

        let previous_first = self.poll_previous_first.fetch_xor(true, Ordering::Relaxed);
        let (first, second) = if previous_first {
            (&previous, &current)
        } else {
            (&current, &previous)
        };
        match self.poll_receive_path(first, context, buffers, metadata) {
            Poll::Pending => self.poll_receive_path(second, context, buffers, metadata),
            ready => ready,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.state.paths.read().unwrap().current.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.state
            .paths
            .read()
            .unwrap()
            .current
            .max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.state
            .paths
            .read()
            .unwrap()
            .current
            .max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.state.paths.read().unwrap().current.may_fragment()
    }
}

impl Hysteria2PortHoppingUdpSocket {
    fn poll_receive_path(
        &self,
        socket: &Arc<dyn quinn::AsyncUdpSocket>,
        context: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        match socket.poll_recv(context, buffers, metadata) {
            Poll::Ready(Ok(count)) => {
                self.state.rewrite_received_remote(metadata, count);
                Poll::Ready(Ok(count))
            }
            other => other,
        }
    }
}

struct Hysteria2PortHoppingPoller {
    state: Arc<Hysteria2PortHoppingState>,
    socket: Arc<dyn quinn::AsyncUdpSocket>,
    generation: u64,
    poller: Pin<Box<dyn quinn::UdpPoller>>,
}

impl fmt::Debug for Hysteria2PortHoppingPoller {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Hysteria2PortHoppingPoller")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl quinn::UdpPoller for Hysteria2PortHoppingPoller {
    fn poll_writable(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        let replacement = {
            let paths = this.state.paths.read().unwrap();
            (paths.generation != this.generation)
                .then(|| (Arc::clone(&paths.current), paths.generation))
        };
        if let Some((socket, generation)) = replacement {
            this.poller = Arc::clone(&socket).create_io_poller();
            this.socket = socket;
            this.generation = generation;
        }
        this.poller.as_mut().poll_writable(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn wait_for_metric(
        metrics: &Hysteria2PortHoppingMetrics,
        field: &str,
        expected_minimum: u64,
    ) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if metrics.snapshot()[field].as_u64().unwrap_or_default() >= expected_minimum {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("port-hopping metric reached expected value");
    }

    async fn receive_one(socket: &Arc<dyn quinn::AsyncUdpSocket>) -> (Vec<u8>, SocketAddr) {
        let mut storage = vec![0_u8; 2_048];
        let (count, len, addr) = tokio::time::timeout(Duration::from_secs(1), async {
            poll_fn(|context| {
                let mut buffers = [IoSliceMut::new(&mut storage)];
                let mut metadata = [udp::RecvMeta::default()];
                match socket.poll_recv(context, &mut buffers, &mut metadata) {
                    Poll::Ready(Ok(count)) => {
                        Poll::Ready((count, metadata[0].len, metadata[0].addr))
                    }
                    Poll::Ready(Err(error)) => panic!("receive port-hopping datagram: {error}"),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await
        })
        .await
        .expect("receive port-hopping datagram before timeout");
        assert_eq!(count, 1);
        storage.truncate(len);
        (storage, addr)
    }

    #[tokio::test]
    async fn hopping_keeps_current_and_previous_sockets_without_retaining_the_task() {
        let first_remote = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second_remote = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_remote_addr = first_remote.local_addr().unwrap();
        let metrics = Arc::new(Hysteria2PortHoppingMetrics::default());
        let config = Hysteria2PortHoppingRuntimeConfig::new(
            vec![first_remote_addr.ip()],
            Arc::new(vec![
                first_remote_addr.port(),
                second_remote.local_addr().unwrap().port(),
            ]),
            Duration::from_millis(20),
            0,
            3,
            Arc::clone(&metrics),
        )
        .unwrap();
        let runtime = Hysteria2PortHoppingRuntime::new(
            quinn::default_runtime().unwrap(),
            config,
            first_remote_addr,
        );
        let initial = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = quinn::Runtime::wrap_udp_socket(&runtime, initial).unwrap();
        let initial_local = socket.local_addr().unwrap();

        wait_for_metric(&metrics, "cumulativeSuccesses", 1).await;
        let current_local = socket.local_addr().unwrap();
        assert_ne!(initial_local, current_local);
        first_remote
            .send_to(b"previous", initial_local)
            .await
            .unwrap();
        first_remote
            .send_to(b"current", current_local)
            .await
            .unwrap();

        let first = receive_one(&socket).await;
        let second = receive_one(&socket).await;
        let mut payloads = [first.0, second.0];
        payloads.sort();
        assert_eq!(payloads, [b"current".to_vec(), b"previous".to_vec()]);
        assert_eq!(first.1, first_remote_addr);
        assert_eq!(second.1, first_remote_addr);

        wait_for_metric(&metrics, "cumulativeSuccesses", 2).await;
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot["activeSockets"], 2);
        assert_eq!(snapshot["highWaterSockets"], 3);
        assert_eq!(snapshot["highWaterTransitions"], 1);

        drop(socket);
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if metrics.snapshot()["activeSockets"] == 0 {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("port-hopping sockets released after owner drop");
    }

    #[tokio::test]
    async fn sustained_current_and_previous_receive_paths_are_polled_fairly() {
        const PACKETS_PER_PATH: usize = 32;

        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let logical_remote = sender.local_addr().unwrap();
        let runtime = quinn::default_runtime().unwrap();
        let current = runtime
            .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let previous = runtime
            .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let current_local = current.local_addr().unwrap();
        let previous_local = previous.local_addr().unwrap();
        let metrics = Arc::new(Hysteria2PortHoppingMetrics::default());
        metrics.socket_opened();
        metrics.socket_opened();
        let state = Arc::new(Hysteria2PortHoppingState {
            runtime,
            addresses: Arc::new(vec![logical_remote.ip()]),
            ports: Arc::new(vec![logical_remote.port()]),
            interval: Duration::from_secs(30),
            mark: 0,
            transition_socket_limit: 3,
            bind: "127.0.0.1:0".parse().unwrap(),
            logical_remote,
            metrics: Arc::clone(&metrics),
            paths: std::sync::RwLock::new(Hysteria2PortHoppingPaths {
                current,
                previous: Some(previous),
                destination: logical_remote,
                generation: 2,
            }),
        });
        let socket: Arc<dyn quinn::AsyncUdpSocket> = Arc::new(Hysteria2PortHoppingUdpSocket {
            state,
            poll_previous_first: AtomicBool::new(false),
        });

        for sequence in 0..PACKETS_PER_PATH {
            sender
                .send_to(format!("c{sequence:02}").as_bytes(), current_local)
                .await
                .unwrap();
            sender
                .send_to(format!("p{sequence:02}").as_bytes(), previous_local)
                .await
                .unwrap();
        }

        let mut path_order = Vec::with_capacity(PACKETS_PER_PATH * 2);
        for _ in 0..PACKETS_PER_PATH * 2 {
            let (payload, source) = receive_one(&socket).await;
            assert_eq!(source, logical_remote);
            path_order.push(payload[0]);
        }
        assert!(
            path_order.windows(2).all(|pair| pair[0] != pair[1]),
            "current and previous receive paths must alternate while both remain readable"
        );
        assert_eq!(
            path_order.iter().filter(|path| **path == b'c').count(),
            PACKETS_PER_PATH
        );
        assert_eq!(
            path_order.iter().filter(|path| **path == b'p').count(),
            PACKETS_PER_PATH
        );

        drop(socket);
        assert_eq!(metrics.snapshot()["activeSockets"], 0);
    }

    #[tokio::test]
    async fn failed_hop_preserves_the_last_working_socket() {
        let runtime = quinn::default_runtime().unwrap();
        let initial = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let current = runtime.wrap_udp_socket(initial).unwrap();
        let current_local = current.local_addr().unwrap();
        let metrics = Arc::new(Hysteria2PortHoppingMetrics::default());
        metrics.socket_opened();
        let state = Hysteria2PortHoppingState {
            runtime,
            addresses: Arc::new(vec!["127.0.0.1".parse().unwrap()]),
            ports: Arc::new(vec![443]),
            interval: Duration::from_secs(30),
            mark: 0,
            transition_socket_limit: 3,
            bind: "192.0.2.1:0".parse().unwrap(),
            logical_remote: "127.0.0.1:443".parse().unwrap(),
            metrics: Arc::clone(&metrics),
            paths: std::sync::RwLock::new(Hysteria2PortHoppingPaths {
                current,
                previous: None,
                destination: "127.0.0.1:443".parse().unwrap(),
                generation: 1,
            }),
        };

        state.hop();
        assert_eq!(
            state.paths.read().unwrap().current.local_addr().unwrap(),
            current_local
        );
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot["cumulativeSuccesses"], 0);
        assert_eq!(snapshot["cumulativeFailures"], 1);
        assert_eq!(snapshot["activeSockets"], 1);
        drop(state);
        assert_eq!(metrics.snapshot()["activeSockets"], 0);
    }
}
