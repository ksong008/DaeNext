use std::sync::Arc;
use std::time::Duration;

use crate::error::OutboundError;
use crate::shared_transport::QuicCongestionController;

pub const DEFAULT_TUIC_ALPN: &str = "h3";
pub const DEFAULT_TUIC_SERVER_NAME: &str = "localhost";
pub const DEFAULT_TUIC_KEEPALIVE_SECS: u64 = 3;
pub const DEFAULT_TUIC_HANDSHAKE_IDLE_TIMEOUT_SECS: u64 = 8;
pub const DEFAULT_TUIC_INITIAL_STREAM_RECEIVE_WINDOW: u64 = 2 * 1024 * 1024;
pub const DEFAULT_TUIC_MAX_STREAM_RECEIVE_WINDOW: u64 = 32 * 1024 * 1024;
pub const DEFAULT_TUIC_INITIAL_CONNECTION_RECEIVE_WINDOW: u64 = 32 * 1024 * 1024;
pub const DEFAULT_TUIC_MAX_CONNECTION_RECEIVE_WINDOW: u64 = 64 * 1024 * 1024;
pub const DEFAULT_TUIC_MAX_UDP_RELAY_PACKET_SIZE: usize = 1400;

pub type TuicCongestionController = QuicCongestionController;

#[cfg(any(test, feature = "test-support"))]
pub(super) fn build_tuic_server_config(
    server_name: &str,
    alpn: &[String],
) -> Result<quinn::ServerConfig, OutboundError> {
    let identity = crate::shared_transport::test_support::self_signed_tls_identity(&[server_name])
        .map_err(|err| bad_tls(format!("generate TUIC BoringSSL cert: {err}")))?;
    crate::shared_transport::test_support::boring_quic_server_config(
        &identity,
        &alpn_protocols(alpn),
        Arc::new(tuic_transport_config(None)?),
    )
    .map_err(|err| bad_tls(format!("TUIC BoringSSL server QUIC TLS: {err}")))
}

pub(super) fn build_tuic_client_config(
    alpn: &[String],
    allow_insecure: bool,
) -> Result<quinn::ClientConfig, OutboundError> {
    build_tuic_client_config_with_congestion(alpn, allow_insecure, TuicCongestionController::Bbr)
}

pub(super) fn build_tuic_client_config_with_congestion(
    alpn: &[String],
    allow_insecure: bool,
    congestion: TuicCongestionController,
) -> Result<quinn::ClientConfig, OutboundError> {
    build_tuic_client_config_with_session_cache(alpn, allow_insecure, congestion, None)
}

pub(super) fn build_tuic_client_config_with_session_cache(
    alpn: &[String],
    allow_insecure: bool,
    congestion: TuicCongestionController,
    session_cache: Option<crate::shared_transport::boring_quic::BoringQuicSessionCache>,
) -> Result<quinn::ClientConfig, OutboundError> {
    let transport = Arc::new(tuic_transport_config(Some(congestion))?);
    let policy =
        crate::shared_transport::boring_quic::BoringQuicClientPolicy::new(alpn_protocols(alpn))?
            .allow_insecure(allow_insecure)
            .zero_rtt(false);
    crate::shared_transport::boring_quic::build_boring_quic_client_config_with_session_cache(
        &policy,
        transport,
        session_cache,
    )
    .map_err(|err| bad_tls(format!("TUIC BoringSSL QUIC TLS: {err}")))
}

pub(super) fn normalize_alpn(alpn: &[String]) -> Vec<String> {
    if alpn.is_empty() {
        vec![DEFAULT_TUIC_ALPN.to_owned()]
    } else {
        alpn.to_vec()
    }
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn selected_alpn(connection: &quinn::Connection) -> String {
    crate::shared_transport::boring_quic::selected_connection_alpn(connection)
        .map(|protocol| String::from_utf8_lossy(&protocol).into_owned())
        .unwrap_or_default()
}

fn alpn_protocols(alpn: &[String]) -> Vec<Vec<u8>> {
    normalize_alpn(alpn)
        .into_iter()
        .map(|protocol| protocol.into_bytes())
        .collect()
}

fn tuic_transport_config(
    congestion: Option<TuicCongestionController>,
) -> Result<quinn::TransportConfig, OutboundError> {
    let mut transport = quinn::TransportConfig::default();
    if let Some(congestion) = congestion {
        congestion.install(&mut transport);
    }
    transport.keep_alive_interval(Some(Duration::from_secs(DEFAULT_TUIC_KEEPALIVE_SECS)));
    transport.max_idle_timeout(Some(
        Duration::from_secs(DEFAULT_TUIC_HANDSHAKE_IDLE_TIMEOUT_SECS)
            .try_into()
            .map_err(|err| bad_tls(format!("TUIC idle timeout config: {err}")))?,
    ));
    transport.datagram_receive_buffer_size(Some(64 * 1024));
    transport.datagram_send_buffer_size(64 * 1024);
    Ok(transport)
}

fn bad_tls(message: impl Into<String>) -> OutboundError {
    OutboundError::BadTuic(message.into())
}
