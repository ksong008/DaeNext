mod admission;
mod charge;
mod drain;
mod metrics;
mod model;
mod runtime;
mod socket;

use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use dae_runtime_control::{AbsoluteDeadline, OwnerAdmissionRejection, OwnerCancellationSignal};

pub use self::drain::{
    QuicEndpointDrainReport, quic_endpoint_drain_deadlines,
    wait_quic_endpoints_idle_or_released_until, wait_quic_endpoints_idle_until,
};
pub use self::metrics::{
    configure_quic_endpoint_observability_retention, quic_endpoint_metrics_snapshot,
};
pub use self::model::{
    QuicEndpointCallerClass, QuicEndpointIdentityRole, QuicEndpointOpenContext,
    QuicEndpointProtocol, QuicEndpointUnderlay, inherit_quic_endpoint_observation,
    scope_quic_endpoint_observation,
};

pub use self::admission::{QuicEndpointAdmissionContext, configure_quic_endpoint_admission};
use self::charge::QuicEndpointCharge;
use self::metrics::QuicEndpointObservation;
use self::runtime::{EndpointDriverReleaseHandle, EndpointDriverTrackingRuntime};
use self::socket::ObservedQuicUdpSocket;
use dae_resident_core::set_socket_mark;

pub struct ObservedQuicEndpoint {
    endpoint: quinn::Endpoint,
    handle_lifecycle: Arc<EndpointHandleLifecycle>,
}

struct EndpointHandleLifecycle {
    observation: Arc<QuicEndpointObservation>,
    driver_release: EndpointDriverReleaseHandle,
}

#[derive(Clone)]
pub(crate) struct QuicEndpointReleaseProbe {
    signal: Arc<metrics::QuicEndpointReleaseSignal>,
    driver_release: EndpointDriverReleaseHandle,
}

impl QuicEndpointReleaseProbe {
    pub(crate) fn force_driver_release(&self) {
        self.driver_release.release();
    }

    pub(crate) async fn released(&self) {
        self.signal.wait().await;
    }
}

impl Clone for ObservedQuicEndpoint {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            handle_lifecycle: Arc::clone(&self.handle_lifecycle),
        }
    }
}

impl std::fmt::Debug for ObservedQuicEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ObservedQuicEndpoint")
            .field("endpoint", &self.endpoint)
            .field(
                "provenance",
                &self.handle_lifecycle.observation.provenance(),
            )
            .finish()
    }
}

impl std::ops::Deref for ObservedQuicEndpoint {
    type Target = quinn::Endpoint;

    fn deref(&self) -> &Self::Target {
        &self.endpoint
    }
}

impl std::ops::DerefMut for ObservedQuicEndpoint {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.endpoint
    }
}

impl Drop for ObservedQuicEndpoint {
    fn drop(&mut self) {
        if Arc::strong_count(&self.handle_lifecycle) == 1 {
            self.handle_lifecycle
                .observation
                .endpoint_handles_released();
        }
    }
}

impl ObservedQuicEndpoint {
    pub fn mark_ready(&self) {
        self.handle_lifecycle.observation.mark_ready();
    }

    pub fn mark_failed(&self) {
        self.handle_lifecycle.observation.mark_failed();
    }

    pub fn close(&self, error_code: quinn::VarInt, reason: &[u8]) {
        self.handle_lifecycle.observation.explicit_close_requested();
        self.endpoint.close(error_code, reason);
    }

    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await;
        self.handle_lifecycle.observation.wait_idle_completed();
    }

    pub(crate) fn release_probe(&self) -> QuicEndpointReleaseProbe {
        QuicEndpointReleaseProbe {
            signal: self.handle_lifecycle.observation.release_signal(),
            driver_release: self.handle_lifecycle.driver_release.clone(),
        }
    }
}

pub async fn wait_quic_endpoint_idle_after_close_for(
    endpoint: &ObservedQuicEndpoint,
    timeout: std::time::Duration,
) -> bool {
    tokio::time::timeout(timeout, endpoint.wait_idle())
        .await
        .is_ok()
}

pub fn open_marked_quic_endpoint_for_remote(
    mark: u32,
    remote: SocketAddr,
    context: QuicEndpointOpenContext,
    deadline: AbsoluteDeadline,
    cancellation: &OwnerCancellationSignal,
) -> Result<ObservedQuicEndpoint, String> {
    open_observed_quic_endpoint(
        mark,
        quinn::default_runtime(),
        remote,
        quic_bind_addr_for_remote(remote),
        QuicEndpointUnderlay::Ordinary,
        context,
        QuicEndpointAdmissionContext::new(deadline, cancellation),
    )
}

fn quic_bind_addr_for_remote(remote: SocketAddr) -> SocketAddr {
    match remote {
        SocketAddr::V4(_) => {
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
        }
        SocketAddr::V6(_) => {
            SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicEndpointOpenError {
    Admission(OwnerAdmissionRejection),
    Construction,
}

pub fn open_observed_quic_endpoint(
    mark: u32,
    runtime: Option<Arc<dyn quinn::Runtime>>,
    remote: SocketAddr,
    bind: SocketAddr,
    underlay: QuicEndpointUnderlay,
    context: QuicEndpointOpenContext,
    admission_context: QuicEndpointAdmissionContext<'_>,
) -> Result<ObservedQuicEndpoint, String> {
    let endpoint_config = quinn_boring::helpers::default_endpoint_config();
    let admission_charge = QuicEndpointCharge::before_socket(
        &endpoint_config,
        underlay,
        context.protocol().uses_http3(),
    )?;
    let reservation = admission::reserve_quic_endpoint(admission_charge, admission_context)?;
    finish_open_observed_quic_endpoint(
        mark,
        runtime,
        remote,
        bind,
        underlay,
        context,
        endpoint_config,
        admission_charge,
        reservation,
    )
}

pub async fn open_observed_quic_endpoint_waiting(
    mark: u32,
    runtime: Option<Arc<dyn quinn::Runtime>>,
    remote: SocketAddr,
    bind: SocketAddr,
    underlay: QuicEndpointUnderlay,
    context: QuicEndpointOpenContext,
    admission_context: QuicEndpointAdmissionContext<'_>,
) -> Result<ObservedQuicEndpoint, QuicEndpointOpenError> {
    let endpoint_config = quinn_boring::helpers::default_endpoint_config();
    let admission_charge = QuicEndpointCharge::before_socket(
        &endpoint_config,
        underlay,
        context.protocol().uses_http3(),
    )
    .map_err(|_| QuicEndpointOpenError::Construction)?;
    let reservation =
        match admission::reserve_quic_endpoint_until(admission_charge, admission_context).await {
            Ok(reservation) => reservation,
            Err(admission::ReserveQuicEndpointError::Admission(rejection)) => {
                return Err(QuicEndpointOpenError::Admission(rejection));
            }
            Err(admission::ReserveQuicEndpointError::Configuration) => {
                return Err(QuicEndpointOpenError::Construction);
            }
        };
    finish_open_observed_quic_endpoint(
        mark,
        runtime,
        remote,
        bind,
        underlay,
        context,
        endpoint_config,
        admission_charge,
        reservation,
    )
    .map_err(|_| QuicEndpointOpenError::Construction)
}

#[allow(clippy::too_many_arguments)]
fn finish_open_observed_quic_endpoint(
    mark: u32,
    runtime: Option<Arc<dyn quinn::Runtime>>,
    remote: SocketAddr,
    bind: SocketAddr,
    underlay: QuicEndpointUnderlay,
    context: QuicEndpointOpenContext,
    endpoint_config: quinn::EndpointConfig,
    admission_charge: QuicEndpointCharge,
    reservation: dae_runtime_control::OwnerReservation,
) -> Result<ObservedQuicEndpoint, String> {
    let socket = UdpSocket::bind(bind).map_err(|error| format!("bind QUIC UDP socket: {error}"))?;
    if mark != 0 {
        set_socket_mark(socket.as_raw_fd(), mark)
            .map_err(|error| format!("set QUIC UDP SO_MARK {mark}: {error}"))?;
    }
    let runtime = runtime.ok_or_else(|| "no quinn runtime available".to_owned())?;
    let socket = runtime
        .wrap_udp_socket(socket)
        .map_err(|error| format!("wrap QUIC UDP socket: {error}"))?;
    let charge = QuicEndpointCharge::for_wrapped_underlay(
        &endpoint_config,
        socket.max_receive_segments(),
        underlay,
        context.protocol().uses_http3(),
    )?;
    if charge.total_bytes > admission_charge.total_bytes {
        return Err(format!(
            "wrapped QUIC socket charge {} exceeds pre-socket reservation {}",
            charge.total_bytes, admission_charge.total_bytes
        ));
    }
    let provenance = context.finalize(remote, bind, mark, underlay, charge, admission_charge);
    let observation = QuicEndpointObservation::register(provenance, reservation);
    let socket = Arc::new(ObservedQuicUdpSocket::new(socket, Arc::clone(&observation)));
    let (tracking_runtime, driver_release) =
        EndpointDriverTrackingRuntime::new(runtime, Arc::clone(&observation));
    let tracking_runtime = Arc::new(tracking_runtime);
    let runtime: Arc<dyn quinn::Runtime> = tracking_runtime.clone();
    let endpoint =
        match quinn::Endpoint::new_with_abstract_socket(endpoint_config, None, socket, runtime) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                observation.mark_failed();
                return Err(format!("create QUIC endpoint: {error}"));
            }
        };
    if !tracking_runtime.endpoint_driver_claimed() {
        observation.mark_failed();
        endpoint.close(0_u32.into(), b"EndpointDriver observation invariant failed");
        return Err("Quinn endpoint constructor did not spawn its EndpointDriver".to_owned());
    }
    observation.endpoint_created();
    Ok(ObservedQuicEndpoint {
        endpoint,
        handle_lifecycle: Arc::new(EndpointHandleLifecycle {
            observation,
            driver_release,
        }),
    })
}

#[cfg(test)]
mod tests;
