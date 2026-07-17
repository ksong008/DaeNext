use super::request::{xhttp_h3_packet_up_request, xhttp_h3_request, xhttp_session_path_suffix};
use super::xmux::{
    XhttpXmuxClientLease, XhttpXmuxKey, XhttpXmuxRequestHandle, note_xhttp_xmux_request,
    select_xhttp_h3_xmux_client,
};
use super::*;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};

pub(crate) struct XhttpH3Connection {
    endpoint: ObservedQuicEndpoint,
    connection: quinn::Connection,
    pub(super) client: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver_task: tokio::task::JoinHandle<()>,
}

pub(super) struct XhttpH3EndpointClient {
    pub(super) client: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    pub(super) connection: Option<XhttpH3Connection>,
    pub(super) xmux_lease: Option<XhttpXmuxClientLease>,
}
pub(super) async fn open_xhttp_h3_proxy_client(
    proxy: &ResidentProxyPlan,
    endpoint: &ResidentXhttpEndpointPlan,
    mark: u32,
) -> Result<XhttpH3EndpointClient, String> {
    let Some(xmux) = &proxy.xhttp_xmux else {
        let resolved = XhttpResolvedEndpoint::resolve(endpoint).await?;
        let connection = open_xhttp_h3_connection(
            proxy,
            endpoint,
            resolved.candidates(),
            mark,
            QuicEndpointIdentityRole::XhttpPrimary,
            None,
        )
        .await?;
        return Ok(XhttpH3EndpointClient {
            client: connection.client.clone(),
            connection: Some(connection),
            xmux_lease: None,
        });
    };
    let resolved = XhttpResolvedEndpoint::resolve(endpoint).await?;
    let key = XhttpXmuxKey::primary(proxy, endpoint, resolved.identity(), xmux, mark, false);
    let provenance_identity = key.quic_provenance_identity();
    let selected = select_xhttp_h3_xmux_client(key, xmux.clone(), || async {
        let connection = open_xhttp_h3_connection(
            proxy,
            endpoint,
            resolved.candidates(),
            mark,
            QuicEndpointIdentityRole::XhttpPrimary,
            Some(provenance_identity),
        )
        .await?;
        Ok(XhttpH3EndpointClient {
            client: connection.client.clone(),
            connection: Some(connection),
            xmux_lease: None,
        })
    })
    .await?;
    Ok(XhttpH3EndpointClient {
        client: selected.client,
        connection: None,
        xmux_lease: Some(selected.lease),
    })
}

pub(super) async fn open_xhttp_h3_endpoint_client(
    proxy: &ResidentProxyPlan,
    endpoint: &ResidentXhttpEndpointPlan,
    mark: u32,
) -> Result<XhttpH3EndpointClient, String> {
    let Some(xmux) = &endpoint.xmux else {
        let resolved = XhttpResolvedEndpoint::resolve(endpoint).await?;
        let connection = open_xhttp_h3_connection(
            proxy,
            endpoint,
            resolved.candidates(),
            mark,
            QuicEndpointIdentityRole::XhttpDownload,
            None,
        )
        .await?;
        return Ok(XhttpH3EndpointClient {
            client: connection.client.clone(),
            connection: Some(connection),
            xmux_lease: None,
        });
    };
    let resolved = XhttpResolvedEndpoint::resolve(endpoint).await?;
    let key = XhttpXmuxKey::download(proxy, endpoint, resolved.identity(), xmux, mark, false);
    let provenance_identity = key.quic_provenance_identity();
    let selected = select_xhttp_h3_xmux_client(key, xmux.clone(), || async {
        let connection = open_xhttp_h3_connection(
            proxy,
            endpoint,
            resolved.candidates(),
            mark,
            QuicEndpointIdentityRole::XhttpDownload,
            Some(provenance_identity),
        )
        .await?;
        Ok(XhttpH3EndpointClient {
            client: connection.client.clone(),
            connection: Some(connection),
            xmux_lease: None,
        })
    })
    .await?;
    Ok(XhttpH3EndpointClient {
        client: selected.client,
        connection: None,
        xmux_lease: Some(selected.lease),
    })
}

async fn open_xhttp_h3_connection(
    proxy: &ResidentProxyPlan,
    endpoint: &ResidentXhttpEndpointPlan,
    candidates: &[SocketAddr],
    mark: u32,
    role: QuicEndpointIdentityRole,
    shared_transport_identity: Option<[u8; 32]>,
) -> Result<XhttpH3Connection, String> {
    let deadline =
        dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), RESIDENT_CONNECT_TIMEOUT);
    let client_config = build_xhttp_h3_client_config(endpoint)?;
    let transport_identity = shared_transport_identity
        .unwrap_or_else(|| xhttp_h3_transport_identity(proxy, endpoint, role));
    let endpoint_context = QuicEndpointOpenContext::for_proxy(
        QuicEndpointProtocol::XhttpHttp3,
        QuicEndpointCallerClass::TcpData,
        proxy,
        role,
        &[&transport_identity],
    );
    let (_, quic_endpoint, connection) = connect_quic_endpoint_candidates_async(
        candidates,
        &endpoint.server_name,
        deadline,
        "connect xHTTP H3 QUIC endpoint",
        |remote, deadline, cancellation| {
            let mut quic_endpoint = open_marked_quic_endpoint_for_remote(
                mark,
                remote,
                endpoint_context.clone(),
                deadline,
                cancellation,
            )?;
            quic_endpoint.set_default_client_config(client_config.clone());
            Ok(quic_endpoint)
        },
    )
    .await?;
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let remaining = deadline
        .remaining_at(Instant::now())
        .ok_or_else(|| "create xHTTP H3 client deadline elapsed".to_owned())?;
    let (mut driver, client) = match time::timeout(remaining, h3::client::new(h3_connection)).await
    {
        Err(_) => {
            quic_endpoint.mark_failed();
            return Err("create xHTTP H3 client timeout".to_owned());
        }
        Ok(Err(err)) => {
            quic_endpoint.mark_failed();
            return Err(format!("create xHTTP H3 client: {err:?}"));
        }
        Ok(Ok(client)) => client,
    };
    let driver_task = tokio::spawn(async move {
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
    });
    quic_endpoint.mark_ready();
    Ok(XhttpH3Connection {
        endpoint: quic_endpoint,
        connection,
        client,
        driver_task,
    })
}

fn xhttp_h3_transport_identity(
    proxy: &ResidentProxyPlan,
    endpoint: &ResidentXhttpEndpointPlan,
    role: QuicEndpointIdentityRole,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    update_xhttp_h3_identity_part(&mut digest, b"dae/xhttp/h3-transport/v1");
    update_xhttp_h3_identity_part(&mut digest, endpoint.server_host.as_bytes());
    update_xhttp_h3_identity_part(&mut digest, &endpoint.server_port.to_be_bytes());
    update_xhttp_h3_identity_part(&mut digest, endpoint.server_name.as_bytes());
    for alpn in &endpoint.alpn {
        update_xhttp_h3_identity_part(&mut digest, alpn.as_bytes());
    }
    update_xhttp_h3_identity_part(&mut digest, &[u8::from(endpoint.allow_insecure)]);
    update_xhttp_h3_identity_part(&mut digest, endpoint.stream_host.as_bytes());
    update_xhttp_h3_identity_part(&mut digest, endpoint.stream_path.as_bytes());
    update_xhttp_h3_identity_part(&mut digest, endpoint.mode.as_str().as_bytes());
    if let Some(fragment) = &endpoint.tls_fragment {
        update_xhttp_h3_identity_part(&mut digest, &fragment.min_length.to_be_bytes());
        update_xhttp_h3_identity_part(&mut digest, &fragment.max_length.to_be_bytes());
        update_xhttp_h3_identity_part(&mut digest, &fragment.min_interval_ms.to_be_bytes());
        update_xhttp_h3_identity_part(&mut digest, &fragment.max_interval_ms.to_be_bytes());
    }
    if let Some(reality) = &endpoint.reality {
        update_xhttp_h3_identity_part(&mut digest, &reality.public_key);
        update_xhttp_h3_identity_part(&mut digest, &reality.short_id);
        update_xhttp_h3_identity_part(&mut digest, reality.spider_x.as_bytes());
    }
    if role == QuicEndpointIdentityRole::XhttpPrimary
        && let Some(fingerprint) = &proxy.utls_fingerprint
    {
        update_xhttp_h3_identity_part(&mut digest, fingerprint.source.as_bytes());
        update_xhttp_h3_identity_part(&mut digest, fingerprint.requested.as_bytes());
        update_xhttp_h3_identity_part(&mut digest, fingerprint.name.as_bytes());
        update_xhttp_h3_identity_part(&mut digest, fingerprint.canonical.as_bytes());
        update_xhttp_h3_identity_part(&mut digest, fingerprint.family.as_bytes());
        update_xhttp_h3_identity_part(&mut digest, fingerprint.client.as_bytes());
        update_xhttp_h3_identity_part(&mut digest, &[u8::from(fingerprint.randomized)]);
        update_xhttp_h3_identity_part(&mut digest, fingerprint.alpn_policy.as_bytes());
        for alpn in &fingerprint.default_alpn {
            update_xhttp_h3_identity_part(&mut digest, alpn.as_bytes());
        }
    }
    digest.finalize().into()
}

fn update_xhttp_h3_identity_part(digest: &mut Sha256, part: &[u8]) {
    digest.update((part.len() as u64).to_be_bytes());
    digest.update(part);
}

impl XhttpH3Connection {
    pub(super) fn is_finished(&self) -> bool {
        self.driver_task.is_finished()
    }

    pub(super) fn abort_with_reason(self, reason: &[u8]) {
        self.connection.close(0_u32.into(), reason);
        self.driver_task.abort();
    }

    pub(super) async fn close(self, reason: &[u8]) {
        self.connection.close(0_u32.into(), reason);
        self.driver_task.abort();
        self.endpoint.wait_idle().await;
    }
}

pub(crate) async fn open_xhttp_h3_download_stream(
    endpoint: &impl ResidentXhttpEndpointView,
    mut client: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    session_id: &str,
    xmux_lease: Option<&XhttpXmuxClientLease>,
) -> Result<h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>, String> {
    note_xhttp_xmux_request(xmux_lease);
    let request = xhttp_h3_request(
        http::Method::GET,
        endpoint,
        &xhttp_session_path_suffix(session_id, None),
        false,
    )?;
    let mut stream = time::timeout(RESIDENT_CONNECT_TIMEOUT, client.send_request(request))
        .await
        .map_err(|_| "xHTTP H3 download request timeout".to_owned())?
        .map_err(|err| format!("send xHTTP H3 download request: {err:?}"))?;
    time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.finish())
        .await
        .map_err(|_| "finish xHTTP H3 download request timeout".to_owned())?
        .map_err(|err| format!("finish xHTTP H3 download request: {err:?}"))?;
    let response = time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.recv_response())
        .await
        .map_err(|_| "xHTTP H3 download response timeout".to_owned())?
        .map_err(|err| format!("read xHTTP H3 download response: {err:?}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "xHTTP H3 download response status {}",
            response.status()
        ));
    }
    Ok(stream)
}

pub(crate) async fn send_xhttp_h3_packet_up_request(
    client: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    endpoint: &impl ResidentXhttpEndpointView,
    session_id: &str,
    seq: u64,
    payload: Bytes,
) -> Result<(), String> {
    let (request, body) = xhttp_h3_packet_up_request(endpoint, session_id, seq, payload)?;
    let mut stream = time::timeout(RESIDENT_CONNECT_TIMEOUT, client.send_request(request))
        .await
        .map_err(|_| "xHTTP H3 packet-up request timeout".to_owned())?
        .map_err(|err| format!("send xHTTP H3 packet-up request: {err:?}"))?;
    if let Some(body) = body {
        time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.send_data(body))
            .await
            .map_err(|_| "send xHTTP H3 packet-up body timeout".to_owned())?
            .map_err(|err| format!("send xHTTP H3 packet-up body: {err:?}"))?;
    }
    time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.finish())
        .await
        .map_err(|_| "finish xHTTP H3 packet-up body timeout".to_owned())?
        .map_err(|err| format!("finish xHTTP H3 packet-up body: {err:?}"))?;
    let response = time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.recv_response())
        .await
        .map_err(|_| "xHTTP H3 packet-up response timeout".to_owned())?
        .map_err(|err| format!("recv xHTTP H3 packet-up response: {err:?}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "xHTTP H3 packet-up response status {}",
            response.status()
        ));
    }
    drain_xhttp_h3_response_body(stream).await
}

pub(super) async fn refresh_xhttp_h3_packet_up_client_if_needed(
    proxy: &ResidentProxyPlan,
    endpoint: &ResidentXhttpEndpointPlan,
    mark: u32,
    client: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    connection: &mut Option<XhttpH3Connection>,
    xmux_request: &mut Option<XhttpXmuxRequestHandle>,
) -> Result<(), String> {
    let Some(request) = xmux_request.as_ref() else {
        return Ok(());
    };
    if request.use_for_packet_up_post() {
        return Ok(());
    }

    let replacement = open_xhttp_h3_proxy_client(proxy, endpoint, mark).await?;
    *client = replacement.client;
    if let Some(new_connection) = replacement.connection
        && let Some(old_connection) = connection.replace(new_connection)
    {
        old_connection
            .close(b"resident xhttp h3 packet-up client replaced")
            .await;
    }
    *xmux_request = replacement
        .xmux_lease
        .as_ref()
        .map(XhttpXmuxClientLease::request_handle);
    drop(replacement.xmux_lease);
    Ok(())
}

async fn drain_xhttp_h3_response_body(
    mut stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<(), String> {
    loop {
        let chunk = time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.recv_data())
            .await
            .map_err(|_| "xHTTP H3 packet-up response body timeout".to_owned())?
            .map_err(|err| format!("read xHTTP H3 packet-up response body: {err:?}"))?;
        if chunk.is_none() {
            return Ok(());
        }
    }
}

fn build_xhttp_h3_client_config(
    endpoint: &ResidentXhttpEndpointPlan,
) -> Result<quinn::ClientConfig, String> {
    let mut crypto = if endpoint.allow_insecure {
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(AcceptAnyXhttpH3Verifier::new())
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let mut config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto)
            .map_err(|err| format!("xHTTP H3 client QUIC TLS config: {err}"))?,
    ));
    config.transport_config(Arc::new(xhttp_h3_transport_config()?));
    Ok(config)
}

fn xhttp_h3_transport_config() -> Result<quinn::TransportConfig, String> {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(
        dae_outbound::shared_transport::XHTTP_H3_KEEPALIVE_SECS,
    )));
    transport.max_idle_timeout(Some(
        Duration::from_secs(dae_outbound::shared_transport::XHTTP_H3_HANDSHAKE_IDLE_TIMEOUT_SECS)
            .try_into()
            .map_err(|err| format!("xHTTP H3 idle timeout config: {err}"))?,
    ));
    transport.datagram_receive_buffer_size(None);
    transport.datagram_send_buffer_size(0);
    Ok(transport)
}

#[derive(Debug)]
struct AcceptAnyXhttpH3Verifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl AcceptAnyXhttpH3Verifier {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        })
    }
}

impl ServerCertVerifier for AcceptAnyXhttpH3Verifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
