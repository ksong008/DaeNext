mod admission;
mod charge;
mod metrics;
mod model;
mod runtime;
mod socket;

use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::Arc;

#[cfg(test)]
use dae_runtime_control::{AbsoluteDeadline, OwnerCancellationSignal};

pub(crate) use self::metrics::quic_endpoint_metrics_snapshot;
pub(crate) use self::model::{
    QuicEndpointCallerClass, QuicEndpointIdentityRole, QuicEndpointOpenContext,
    QuicEndpointProtocol, QuicEndpointUnderlay, inherit_quic_endpoint_observation,
    scope_quic_endpoint_observation,
};

pub(super) use self::admission::QuicEndpointAdmissionContext;
use self::charge::QuicEndpointCharge;
use self::metrics::QuicEndpointObservation;
use self::runtime::EndpointDriverTrackingRuntime;
use self::socket::ObservedQuicUdpSocket;
use super::quic_helpers::set_socket_mark;

pub(crate) struct ObservedQuicEndpoint {
    endpoint: quinn::Endpoint,
    handle_lifecycle: Arc<EndpointHandleLifecycle>,
}

struct EndpointHandleLifecycle {
    observation: Arc<QuicEndpointObservation>,
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
    pub(crate) fn mark_ready(&self) {
        self.handle_lifecycle.observation.mark_ready();
    }

    pub(crate) fn mark_failed(&self) {
        self.handle_lifecycle.observation.mark_failed();
    }

    pub(crate) fn close(&self, error_code: quinn::VarInt, reason: &[u8]) {
        self.handle_lifecycle.observation.explicit_close_requested();
        self.endpoint.close(error_code, reason);
    }

    pub(crate) async fn wait_idle(&self) {
        self.endpoint.wait_idle().await;
        self.handle_lifecycle.observation.wait_idle_completed();
    }
}

pub(super) fn open_observed_quic_endpoint(
    mark: u32,
    runtime: Option<Arc<dyn quinn::Runtime>>,
    remote: SocketAddr,
    bind: SocketAddr,
    underlay: QuicEndpointUnderlay,
    context: QuicEndpointOpenContext,
    admission_context: QuicEndpointAdmissionContext<'_>,
) -> Result<ObservedQuicEndpoint, String> {
    let endpoint_config = quinn::EndpointConfig::default();
    let admission_charge = QuicEndpointCharge::before_socket(
        &endpoint_config,
        underlay,
        context.protocol().uses_http3(),
    )?;
    let reservation = admission::reserve_quic_endpoint(admission_charge, admission_context)?;
    let socket = UdpSocket::bind(bind).map_err(|error| format!("bind QUIC UDP socket: {error}"))?;
    if mark != 0 {
        set_socket_mark(socket.as_raw_fd(), mark)
            .map_err(|error| format!("set QUIC UDP SO_MARK {mark}: {error}"))?;
    }
    let runtime = runtime.ok_or_else(|| "no quinn runtime available".to_owned())?;
    let socket = runtime
        .wrap_udp_socket(socket)
        .map_err(|error| format!("wrap QUIC UDP socket: {error}"))?;
    let charge = QuicEndpointCharge::for_socket(
        &endpoint_config,
        socket.max_receive_segments(),
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
    let tracking_runtime = Arc::new(EndpointDriverTrackingRuntime::new(
        runtime,
        Arc::clone(&observation),
    ));
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
        handle_lifecycle: Arc::new(EndpointHandleLifecycle { observation }),
    })
}

#[cfg(test)]
mod tests;
