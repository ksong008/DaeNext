use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicI32, Ordering},
};
use std::time::Instant;

mod h2_manager;
pub(super) use self::h2_manager::select_xhttp_h2_xmux_client;

mod h3_manager;
pub(super) use self::h3_manager::select_xhttp_h3_xmux_client;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct XhttpXmuxKey {
    origin: String,
    server_host: String,
    server_port: u16,
    server_name: String,
    alpn: Vec<String>,
    stream_host: String,
    stream_path: String,
    mode: ResidentXhttpMode,
    allow_insecure: bool,
    tls_fragment: Option<(usize, usize, u64, u64)>,
    xmux: ResidentXhttpXmuxPlan,
    mark: u32,
    mptcp: bool,
}

pub(super) struct XhttpXmuxUsage {
    pub(super) open_usage: AtomicI32,
    pub(super) left_requests: AtomicI32,
    pub(super) unreusable_at: Option<Instant>,
}

#[derive(Clone)]
pub(crate) struct XhttpXmuxClientLease {
    pub(super) usage: Arc<XhttpXmuxUsage>,
}

#[derive(Clone)]
pub(crate) struct XhttpXmuxRequestHandle {
    pub(super) usage: Arc<XhttpXmuxUsage>,
}

pub(super) struct XhttpXmuxH2SelectedClient {
    pub(super) sender: h2::client::SendRequest<Bytes>,
    pub(super) lease: XhttpXmuxClientLease,
}

pub(super) struct XhttpXmuxH3SelectedClient {
    pub(super) client: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    pub(super) lease: XhttpXmuxClientLease,
}

impl XhttpXmuxKey {
    pub(super) fn primary(
        proxy: &ResidentProxyPlan,
        endpoint: &ResidentXhttpEndpointPlan,
        xmux: &ResidentXhttpXmuxPlan,
        mark: u32,
        mptcp: bool,
    ) -> Self {
        let fingerprint = proxy
            .utls_fingerprint
            .as_ref()
            .map(|fingerprint| fingerprint.canonical.as_str())
            .unwrap_or_default();
        Self::new(
            format!(
                "primary:{}:{}:{}:{}",
                proxy.graph_link_hash,
                proxy.tls,
                fingerprint,
                proxy.reality.is_some()
            ),
            endpoint,
            xmux,
            mark,
            mptcp,
        )
    }

    pub(super) fn endpoint(
        endpoint: &ResidentXhttpEndpointPlan,
        xmux: &ResidentXhttpXmuxPlan,
        mark: u32,
        mptcp: bool,
    ) -> Self {
        Self::new("endpoint".to_owned(), endpoint, xmux, mark, mptcp)
    }

    fn new(
        origin: String,
        endpoint: &ResidentXhttpEndpointPlan,
        xmux: &ResidentXhttpXmuxPlan,
        mark: u32,
        mptcp: bool,
    ) -> Self {
        Self {
            origin,
            server_host: endpoint.server_host.clone(),
            server_port: endpoint.server_port,
            server_name: endpoint.server_name.clone(),
            alpn: endpoint.alpn.clone(),
            stream_host: endpoint.stream_host.clone(),
            stream_path: endpoint.stream_path.clone(),
            mode: endpoint.mode,
            allow_insecure: endpoint.allow_insecure,
            tls_fragment: endpoint.tls_fragment.as_ref().map(|fragment| {
                (
                    fragment.min_length,
                    fragment.max_length,
                    fragment.min_interval_ms,
                    fragment.max_interval_ms,
                )
            }),
            xmux: xmux.clone().official_normalized(),
            mark,
            mptcp,
        }
    }
}

impl XhttpXmuxClientLease {
    pub(super) fn open(usage: Arc<XhttpXmuxUsage>) -> Self {
        usage.open_usage.fetch_add(1, Ordering::AcqRel);
        Self { usage }
    }

    pub(super) fn request_handle(&self) -> XhttpXmuxRequestHandle {
        XhttpXmuxRequestHandle {
            usage: Arc::clone(&self.usage),
        }
    }

    pub(super) fn note_request(&self) -> i32 {
        self.usage.left_requests.fetch_sub(1, Ordering::AcqRel) - 1
    }
}

impl XhttpXmuxRequestHandle {
    pub(super) fn use_for_packet_up_post(&self) -> bool {
        let left = self.usage.left_requests.fetch_sub(1, Ordering::AcqRel) - 1;
        left > 0
            && !self
                .usage
                .unreusable_at
                .is_some_and(|deadline| Instant::now() > deadline)
    }
}

impl Drop for XhttpXmuxClientLease {
    fn drop(&mut self) {
        self.usage.open_usage.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(super) fn note_xhttp_xmux_request(xmux_lease: Option<&XhttpXmuxClientLease>) {
    if let Some(lease) = xmux_lease {
        let _ = lease.note_request();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn xmux_usage(left_requests: i32, unreusable_at: Option<Instant>) -> Arc<XhttpXmuxUsage> {
        Arc::new(XhttpXmuxUsage {
            open_usage: AtomicI32::new(0),
            left_requests: AtomicI32::new(left_requests),
            unreusable_at,
        })
    }

    #[test]
    fn xhttp_xmux_packet_up_uses_official_left_request_switch_boundary() {
        let handle = XhttpXmuxRequestHandle {
            usage: xmux_usage(2, None),
        };

        assert!(handle.use_for_packet_up_post());
        assert_eq!(handle.usage.left_requests.load(Ordering::Acquire), 1);
        assert!(!handle.use_for_packet_up_post());
        assert_eq!(handle.usage.left_requests.load(Ordering::Acquire), 0);
    }

    #[test]
    fn xhttp_xmux_packet_up_switches_when_client_is_past_reusable_deadline() {
        let handle = XhttpXmuxRequestHandle {
            usage: xmux_usage(10, Some(Instant::now() - Duration::from_secs(1))),
        };

        assert!(!handle.use_for_packet_up_post());
        assert_eq!(handle.usage.left_requests.load(Ordering::Acquire), 9);
    }

    #[test]
    fn xhttp_xmux_request_handle_does_not_extend_open_usage_lease() {
        let usage = xmux_usage(4, None);
        assert_eq!(usage.open_usage.load(Ordering::Acquire), 0);

        let handle = {
            let lease = XhttpXmuxClientLease::open(Arc::clone(&usage));
            assert_eq!(usage.open_usage.load(Ordering::Acquire), 1);
            let handle = lease.request_handle();
            assert!(handle.use_for_packet_up_post());
            handle
        };

        assert_eq!(usage.open_usage.load(Ordering::Acquire), 0);
        assert_eq!(handle.usage.left_requests.load(Ordering::Acquire), 3);
    }
}
