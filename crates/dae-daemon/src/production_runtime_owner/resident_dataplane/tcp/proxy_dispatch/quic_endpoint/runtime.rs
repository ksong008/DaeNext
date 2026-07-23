use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use futures_util::future::{AbortHandle, AbortRegistration, Abortable};

use super::metrics::QuicEndpointObservation;

pub(super) struct EndpointDriverTrackingRuntime {
    inner: Arc<dyn quinn::Runtime>,
    observation: Arc<QuicEndpointObservation>,
    endpoint_driver_claimed: AtomicBool,
    endpoint_driver_abort: std::sync::Mutex<Option<AbortRegistration>>,
}

#[derive(Clone)]
pub(super) struct EndpointDriverReleaseHandle {
    abort: AbortHandle,
}

impl EndpointDriverReleaseHandle {
    pub(super) fn release(&self) {
        self.abort.abort();
    }
}

impl std::fmt::Debug for EndpointDriverTrackingRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EndpointDriverTrackingRuntime")
            .field("inner", &self.inner)
            .field("provenance", &self.observation.provenance())
            .finish_non_exhaustive()
    }
}

impl EndpointDriverTrackingRuntime {
    pub(super) fn new(
        inner: Arc<dyn quinn::Runtime>,
        observation: Arc<QuicEndpointObservation>,
    ) -> (Self, EndpointDriverReleaseHandle) {
        let (abort, registration) = AbortHandle::new_pair();
        (
            Self {
                inner,
                observation,
                endpoint_driver_claimed: AtomicBool::new(false),
                endpoint_driver_abort: std::sync::Mutex::new(Some(registration)),
            },
            EndpointDriverReleaseHandle { abort },
        )
    }

    pub(super) fn endpoint_driver_claimed(&self) -> bool {
        self.endpoint_driver_claimed.load(Ordering::Acquire)
    }
}

impl quinn::Runtime for EndpointDriverTrackingRuntime {
    fn new_timer(&self, instant: std::time::Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        self.inner.new_timer(instant)
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        // Quinn 0.11 new_with_abstract_socket synchronously performs its first Runtime::spawn for
        // EndpointDriver. The same Runtime is later reused by connections, so only that first
        // constructor-time spawn is wrapped and all subsequent Quinn tasks are delegated verbatim.
        if self.endpoint_driver_claimed.swap(true, Ordering::AcqRel) {
            self.inner.spawn(future);
            return;
        }
        self.observation.endpoint_driver_started();
        let observation = Arc::clone(&self.observation);
        let completion = EndpointDriverCompletion { observation };
        let registration = self
            .endpoint_driver_abort
            .lock()
            .unwrap()
            .take()
            .expect("first Quinn EndpointDriver spawn owns its abort registration");
        self.inner.spawn(Box::pin(async move {
            let _completion = completion;
            let _ = Abortable::new(future, registration).await;
        }));
    }

    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        self.inner.wrap_udp_socket(socket)
    }

    fn now(&self) -> std::time::Instant {
        self.inner.now()
    }
}

struct EndpointDriverCompletion {
    observation: Arc<QuicEndpointObservation>,
}

impl Drop for EndpointDriverCompletion {
    fn drop(&mut self) {
        self.observation.endpoint_driver_finished();
    }
}
