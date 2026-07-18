use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig};
use rcgen::generate_simple_self_signed;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::error::OutboundError;

use super::Hysteria2CongestionRuntime;
use super::tls_policy::{
    Hysteria2ApplicationProtocol, Hysteria2CertificateVerification, Hysteria2TlsIdentity,
};
use super::tls_verifier::Hysteria2ServerCertVerifier;

pub const DEFAULT_HYSTERIA2_ALPN: &str = Hysteria2ApplicationProtocol::Http3.wire_value();
pub const DEFAULT_HYSTERIA2_SERVER_NAME: &str = "localhost";
pub const DEFAULT_HYSTERIA2_KEEPALIVE_SECS: u64 = 10;
pub const DEFAULT_HYSTERIA2_MAX_IDLE_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_HYSTERIA2_MTU_DISCOVERY_UPPER_BOUND: u16 = 1452;
const HYSTERIA2_MINIMUM_QUIC_UDP_PAYLOAD: u16 = 1200;

pub(super) fn build_hysteria2_server_config(
    server_name: &str,
) -> Result<(quinn::ServerConfig, CertificateDer<'static>), OutboundError> {
    let certified = generate_simple_self_signed(vec![server_name.to_owned()])
        .map_err(|err| bad_tls(format!("generate Hysteria2 cert: {err}")))?;
    let cert_der = certified.cert.der().clone();
    let key_der =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    let mut crypto =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .map_err(|err| bad_tls(format!("Hysteria2 server cert config: {err}")))?;
    crypto.alpn_protocols = vec![DEFAULT_HYSTERIA2_ALPN.as_bytes().to_vec()];
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(crypto)
            .map_err(|err| bad_tls(format!("Hysteria2 server QUIC TLS: {err}")))?,
    ));
    config.transport_config(Arc::new(hysteria2_transport_config(0, None)?));
    Ok((config, cert_der))
}

pub fn build_hysteria2_runtime_client_config(
    identity: &Hysteria2TlsIdentity,
) -> Result<quinn::ClientConfig, OutboundError> {
    build_hysteria2_runtime_client_config_with_udp_overhead(identity, 0)
}

pub fn build_hysteria2_runtime_client_config_with_udp_overhead(
    identity: &Hysteria2TlsIdentity,
    udp_packet_overhead: usize,
) -> Result<quinn::ClientConfig, OutboundError> {
    build_hysteria2_runtime_client_config_with_congestion(identity, udp_packet_overhead, None)
}

pub fn build_hysteria2_runtime_client_config_with_congestion(
    identity: &Hysteria2TlsIdentity,
    udp_packet_overhead: usize,
    congestion: Option<Arc<Hysteria2CongestionRuntime>>,
) -> Result<quinn::ClientConfig, OutboundError> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let crypto = build_hysteria2_rustls_client_config(identity, roots)?;
    let mut config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto)
            .map_err(|err| bad_tls(format!("Hysteria2 client QUIC TLS: {err}")))?,
    ));
    config.transport_config(Arc::new(hysteria2_transport_config(
        udp_packet_overhead,
        congestion,
    )?));
    Ok(config)
}

fn build_hysteria2_rustls_client_config(
    identity: &Hysteria2TlsIdentity,
    roots: RootCertStore,
) -> Result<rustls::ClientConfig, OutboundError> {
    let builder = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]);
    let mut crypto = match (
        identity.policy().verification(),
        identity.policy().has_leaf_certificate_pin(),
    ) {
        (Hysteria2CertificateVerification::WebPki, false) => {
            builder.with_root_certificates(roots).with_no_client_auth()
        }
        _ => builder
            .dangerous()
            .with_custom_certificate_verifier(Hysteria2ServerCertVerifier::new(
                identity.policy(),
                Arc::new(roots),
            )?)
            .with_no_client_auth(),
    };
    crypto.alpn_protocols = vec![
        identity
            .application_protocol()
            .wire_value()
            .as_bytes()
            .to_vec(),
    ];
    Ok(crypto)
}

pub(super) fn selected_alpn(connection: &quinn::Connection) -> String {
    connection
        .handshake_data()
        .and_then(|data| data.downcast::<HandshakeData>().ok())
        .and_then(|data| data.protocol.clone())
        .map(|protocol| String::from_utf8_lossy(&protocol).to_string())
        .unwrap_or_default()
}

fn hysteria2_transport_config(
    udp_packet_overhead: usize,
    congestion: Option<Arc<Hysteria2CongestionRuntime>>,
) -> Result<quinn::TransportConfig, OutboundError> {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(DEFAULT_HYSTERIA2_KEEPALIVE_SECS)));
    transport.max_idle_timeout(Some(
        Duration::from_secs(DEFAULT_HYSTERIA2_MAX_IDLE_TIMEOUT_SECS)
            .try_into()
            .map_err(|err| bad_tls(format!("Hysteria2 idle timeout config: {err}")))?,
    ));
    transport.datagram_receive_buffer_size(Some(64 * 1024));
    transport.datagram_send_buffer_size(64 * 1024);
    let mtu_upper_bound = hysteria2_mtu_discovery_upper_bound(udp_packet_overhead)?;
    let mut mtu_discovery = quinn::MtuDiscoveryConfig::default();
    mtu_discovery.upper_bound(mtu_upper_bound);
    transport.mtu_discovery_config(Some(mtu_discovery));
    if let Some(congestion) = congestion {
        transport.congestion_controller_factory(congestion);
    }
    Ok(transport)
}

fn hysteria2_mtu_discovery_upper_bound(udp_packet_overhead: usize) -> Result<u16, OutboundError> {
    let udp_packet_overhead = u16::try_from(udp_packet_overhead)
        .map_err(|_| bad_tls("Hysteria2 UDP packet overhead exceeds u16"))?;
    let upper_bound = DEFAULT_HYSTERIA2_MTU_DISCOVERY_UPPER_BOUND
        .checked_sub(udp_packet_overhead)
        .ok_or_else(|| bad_tls("Hysteria2 UDP packet overhead exceeds MTU upper bound"))?;
    if upper_bound < HYSTERIA2_MINIMUM_QUIC_UDP_PAYLOAD {
        return Err(bad_tls(format!(
            "Hysteria2 UDP packet overhead leaves QUIC MTU below {HYSTERIA2_MINIMUM_QUIC_UDP_PAYLOAD} bytes"
        )));
    }
    Ok(upper_bound)
}

fn bad_tls(message: impl Into<String>) -> OutboundError {
    OutboundError::BadHysteria2(message.into())
}

#[cfg(test)]
#[path = "tls/tests.rs"]
mod tests;
