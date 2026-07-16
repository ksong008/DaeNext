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

mod capacity;
use self::capacity::{XhttpXmuxConnectionCapacity, can_release_retiring_owner};

mod lifecycle;
use self::lifecycle::{XhttpXmuxManagerHandle, XhttpXmuxManagerLifecycle, XhttpXmuxOpeningLease};

mod state_signal;
use self::state_signal::{XhttpXmuxStateSignal, XhttpXmuxStateWait};

mod key;
pub(super) use self::key::XhttpXmuxKey;

#[cfg(test)]
mod test_support;

pub(super) struct XhttpXmuxUsage {
    pub(super) open_usage: AtomicI32,
    pub(super) left_requests: AtomicI32,
    pub(super) unreusable_at: Option<Instant>,
    state_signal: XhttpXmuxStateSignal,
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
        let left = self.usage.left_requests.fetch_sub(1, Ordering::AcqRel) - 1;
        self.usage.state_signal.notify();
        left
    }
}

impl XhttpXmuxRequestHandle {
    pub(super) fn use_for_packet_up_post(&self) -> bool {
        let left = self.usage.left_requests.fetch_sub(1, Ordering::AcqRel) - 1;
        self.usage.state_signal.notify();
        left > 0
            && self
                .usage
                .unreusable_at
                .is_none_or(|deadline| Instant::now() <= deadline)
    }
}

impl Drop for XhttpXmuxClientLease {
    fn drop(&mut self) {
        self.usage.open_usage.fetch_sub(1, Ordering::AcqRel);
        self.usage.state_signal.notify();
    }
}

pub(super) fn note_xhttp_xmux_request(xmux_lease: Option<&XhttpXmuxClientLease>) {
    if let Some(lease) = xmux_lease {
        let _ = lease.note_request();
    }
}

pub(crate) fn clear_xhttp_xmux_managers(runtime_generation: u64) -> XhttpXmuxClearReport {
    XhttpXmuxClearReport {
        h2: h2_manager::clear_xhttp_h2_xmux_managers(runtime_generation),
        h3: h3_manager::clear_xhttp_h3_xmux_managers(runtime_generation),
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct XhttpXmuxClearReport {
    pub(crate) h2: XhttpXmuxManagerClearReport,
    pub(crate) h3: XhttpXmuxManagerClearReport,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct XhttpXmuxManagerClearReport {
    pub(crate) managers: usize,
    pub(crate) clients: usize,
    pub(crate) locked_managers: usize,
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
            state_signal: XhttpXmuxStateSignal::new(),
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
