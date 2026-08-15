use super::h3_boring_tls::build_chrome_boring_xhttp_h3_client_config_with_system_ca;
use super::request::{xhttp_h3_packet_up_request, xhttp_h3_request, xhttp_session_path_suffix};
use super::xmux::{
    XhttpXmuxClientLease, XhttpXmuxKey, XhttpXmuxRequestHandle, note_xhttp_xmux_request,
    select_xhttp_h3_xmux_client,
};
use super::*;
use dae_runtime_control::OwnerGeneration;
use sha2::{Digest, Sha256};

use crate::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
use crate::plan::ResidentXhttpQuicTlsProvider;

pub(crate) struct XhttpH3Connection {
    endpoint: Arc<std::sync::Mutex<Option<ObservedQuicEndpoint>>>,
    connection: quinn::Connection,
    pub(super) client: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver_task: Option<tokio::task::JoinHandle<()>>,
}

pub(super) struct XhttpH3EndpointClient {
    pub(super) client: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    pub(super) connection: Option<XhttpH3Connection>,
    pub(super) xmux_lease: Option<XhttpXmuxClientLease>,
}

type XhttpH3OwnerOpenFuture = Pin<
    Box<dyn std::future::Future<Output = Result<XhttpH3EndpointClient, String>> + Send + 'static>,
>;
pub(super) async fn open_xhttp_h3_proxy_client(
    binding: &ResidentProxyBinding,
    endpoint: &ResidentXhttpEndpointPlan,
) -> Result<XhttpH3EndpointClient, String> {
    let proxy = binding.plan();
    let mark = binding.effective_socket_mark();
    let Some(xmux) = binding.persistent_xhttp_xmux() else {
        let resolved = XhttpResolvedEndpoint::resolve(endpoint).await?;
        let connection = open_xhttp_h3_connection(
            proxy,
            binding.runtime_generation(),
            endpoint,
            resolved.candidates(),
            mark,
            QuicEndpointIdentityRole::XhttpPrimary,
            None,
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
    let key = XhttpXmuxKey::primary(binding, endpoint, resolved.identity(), xmux, mark, false)?;
    let provenance_identity = key.quic_provenance_identity();
    let selected = select_xhttp_h3_xmux_client(
        key,
        xmux.clone(),
        |session_cache| -> XhttpH3OwnerOpenFuture {
            let owner_proxy = Arc::clone(binding.shared_plan());
            let owner_generation = binding.runtime_generation();
            let owner_endpoint = endpoint.clone();
            let owner_candidates = resolved.candidates().to_vec();
            Box::pin(async move {
                let connection = open_xhttp_h3_connection(
                    &owner_proxy,
                    owner_generation,
                    &owner_endpoint,
                    &owner_candidates,
                    mark,
                    QuicEndpointIdentityRole::XhttpPrimary,
                    Some(provenance_identity),
                    session_cache,
                )
                .await?;
                Ok(XhttpH3EndpointClient {
                    client: connection.client.clone(),
                    connection: Some(connection),
                    xmux_lease: None,
                })
            })
        },
    )
    .await?;
    Ok(XhttpH3EndpointClient {
        client: selected.client,
        connection: None,
        xmux_lease: Some(selected.lease),
    })
}

pub(super) async fn open_xhttp_h3_endpoint_client(
    binding: &ResidentProxyBinding,
    endpoint: &ResidentXhttpEndpointPlan,
) -> Result<XhttpH3EndpointClient, String> {
    let proxy = binding.plan();
    let mark = binding.effective_socket_mark();
    let Some(xmux) = binding.persistent_xhttp_download_xmux() else {
        let resolved = XhttpResolvedEndpoint::resolve(endpoint).await?;
        let connection = open_xhttp_h3_connection(
            proxy,
            binding.runtime_generation(),
            endpoint,
            resolved.candidates(),
            mark,
            QuicEndpointIdentityRole::XhttpDownload,
            None,
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
    let key = XhttpXmuxKey::download(binding, endpoint, resolved.identity(), xmux, mark, false)?;
    let provenance_identity = key.quic_provenance_identity();
    let selected = select_xhttp_h3_xmux_client(
        key,
        xmux.clone(),
        |session_cache| -> XhttpH3OwnerOpenFuture {
            let owner_proxy = Arc::clone(binding.shared_plan());
            let owner_generation = binding.runtime_generation();
            let owner_endpoint = endpoint.clone();
            let owner_candidates = resolved.candidates().to_vec();
            Box::pin(async move {
                let connection = open_xhttp_h3_connection(
                    &owner_proxy,
                    owner_generation,
                    &owner_endpoint,
                    &owner_candidates,
                    mark,
                    QuicEndpointIdentityRole::XhttpDownload,
                    Some(provenance_identity),
                    session_cache,
                )
                .await?;
                Ok(XhttpH3EndpointClient {
                    client: connection.client.clone(),
                    connection: Some(connection),
                    xmux_lease: None,
                })
            })
        },
    )
    .await?;
    Ok(XhttpH3EndpointClient {
        client: selected.client,
        connection: None,
        xmux_lease: Some(selected.lease),
    })
}

async fn open_xhttp_h3_connection(
    proxy: &ResidentProxyPlan,
    generation: OwnerGeneration,
    endpoint: &ResidentXhttpEndpointPlan,
    candidates: &[SocketAddr],
    mark: u32,
    role: QuicEndpointIdentityRole,
    shared_transport_identity: Option<[u8; 32]>,
    session_cache: Option<dae_outbound::shared_transport::boring_quic::BoringQuicSessionCache>,
) -> Result<XhttpH3Connection, String> {
    let deadline =
        dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), RESIDENT_CONNECT_TIMEOUT);
    let tls_provider = xhttp_h3_tls_provider(endpoint, role)?;
    let system_ca = xhttp_h3_system_ca_snapshot(endpoint)?;
    let client_config = build_xhttp_h3_client_config_with_system_ca(
        endpoint,
        tls_provider,
        system_ca.clone(),
        session_cache,
    )?;
    let transport_identity = shared_transport_identity.unwrap_or_else(|| {
        xhttp_h3_transport_identity(
            endpoint,
            role,
            tls_provider,
            system_ca.as_deref().map(|snapshot| snapshot.identity()),
        )
    });
    let endpoint_context = QuicEndpointOpenContext::for_proxy(
        QuicEndpointProtocol::XhttpHttp3,
        QuicEndpointCallerClass::TcpData,
        generation,
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
            connection.close(0x101_u32.into(), b"xhttp h3 client timeout");
            quic_endpoint.close(0x101_u32.into(), b"xhttp h3 client timeout");
            wait_quic_endpoint_idle_after_close(&quic_endpoint).await;
            return Err("create xHTTP H3 client timeout".to_owned());
        }
        Ok(Err(err)) => {
            quic_endpoint.mark_failed();
            connection.close(0x101_u32.into(), b"xhttp h3 client failed");
            quic_endpoint.close(0x101_u32.into(), b"xhttp h3 client failed");
            wait_quic_endpoint_idle_after_close(&quic_endpoint).await;
            return Err(format!("create xHTTP H3 client: {err:?}"));
        }
        Ok(Ok(client)) => client,
    };
    quic_endpoint.mark_ready();
    let endpoint = Arc::new(std::sync::Mutex::new(Some(quic_endpoint)));
    let driver_endpoint = Arc::clone(&endpoint);
    let driver_task = tokio::spawn(async move {
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
        let endpoint = driver_endpoint
            .lock()
            .ok()
            .and_then(|mut endpoint| endpoint.take());
        if let Some(endpoint) = endpoint {
            endpoint.wait_idle().await;
        }
    });
    Ok(XhttpH3Connection {
        endpoint,
        connection,
        client,
        driver_task: Some(driver_task),
    })
}

fn xhttp_h3_transport_identity(
    endpoint: &ResidentXhttpEndpointPlan,
    role: QuicEndpointIdentityRole,
    tls_provider: ResidentXhttpQuicTlsProvider,
    system_ca: Option<&dae_outbound::shared_transport::SystemCaIdentity>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    update_xhttp_h3_identity_part(&mut digest, b"dae/xhttp/h3-transport/v2");
    update_xhttp_h3_identity_part(&mut digest, role.as_str().as_bytes());
    update_xhttp_h3_identity_part(&mut digest, tls_provider.as_str().as_bytes());
    let session_namespace = xhttp_h3_session_namespace(endpoint, role, tls_provider, system_ca);
    update_xhttp_h3_identity_part(&mut digest, &session_namespace);
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
    digest.finalize().into()
}

fn xhttp_h3_session_namespace(
    endpoint: &ResidentXhttpEndpointPlan,
    role: QuicEndpointIdentityRole,
    tls_provider: ResidentXhttpQuicTlsProvider,
    system_ca: Option<&dae_outbound::shared_transport::SystemCaIdentity>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    update_xhttp_h3_identity_part(&mut digest, b"dae/xhttp/h3-session/v1");
    update_xhttp_h3_identity_part(&mut digest, role.as_str().as_bytes());
    update_xhttp_h3_identity_part(&mut digest, tls_provider.as_str().as_bytes());
    update_xhttp_h3_identity_part(&mut digest, endpoint.server_name.as_bytes());
    for alpn in &endpoint.alpn {
        update_xhttp_h3_identity_part(&mut digest, alpn.as_bytes());
    }
    update_xhttp_h3_identity_part(&mut digest, &[u8::from(endpoint.allow_insecure)]);
    if let Some(system_ca) = system_ca {
        update_xhttp_h3_identity_part(&mut digest, system_ca.path.to_string_lossy().as_bytes());
        update_xhttp_h3_identity_part(&mut digest, system_ca.sha256.as_bytes());
        update_xhttp_h3_identity_part(
            &mut digest,
            &(system_ca.certificate_count as u64).to_be_bytes(),
        );
    }
    if let Some(ech) = &endpoint.ech {
        update_xhttp_h3_identity_part(&mut digest, ech.config_list_sha256());
    }
    if let Some(reality) = &endpoint.reality {
        update_xhttp_h3_identity_part(&mut digest, &reality.public_key);
        update_xhttp_h3_identity_part(&mut digest, &reality.short_id);
        update_xhttp_h3_identity_part(&mut digest, reality.spider_x.as_bytes());
        if let Some(mldsa65_verify) = &reality.mldsa65_verify {
            update_xhttp_h3_identity_part(&mut digest, mldsa65_verify.sha256());
        }
    }
    if let Some(fingerprint) = &endpoint.utls_fingerprint {
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

fn xhttp_h3_tls_provider(
    endpoint: &ResidentXhttpEndpointPlan,
    role: QuicEndpointIdentityRole,
) -> Result<ResidentXhttpQuicTlsProvider, String> {
    match role {
        QuicEndpointIdentityRole::XhttpPrimary | QuicEndpointIdentityRole::XhttpDownload => {
            ResidentXhttpQuicTlsProvider::for_endpoint(endpoint.utls_fingerprint.as_ref())
        }
        _ => Err("xHTTP H3 received a non-xHTTP endpoint identity role".to_owned()),
    }
}

fn xhttp_h3_system_ca_snapshot(
    endpoint: &ResidentXhttpEndpointPlan,
) -> Result<Option<Arc<dae_outbound::shared_transport::SystemCaSnapshot>>, String> {
    if endpoint.allow_insecure || endpoint.reality.is_some() {
        return Ok(None);
    }
    dae_outbound::shared_transport::system_ca_snapshot()
        .map(Some)
        .map_err(|err| format!("load xHTTP H3 system CA bundle: {err}"))
}

fn update_xhttp_h3_identity_part(digest: &mut Sha256, part: &[u8]) {
    digest.update((part.len() as u64).to_be_bytes());
    digest.update(part);
}

impl XhttpH3Connection {
    pub(super) fn is_finished(&self) -> bool {
        self.driver_task
            .as_ref()
            .is_none_or(tokio::task::JoinHandle::is_finished)
    }

    fn take_endpoint(&self) -> Option<ObservedQuicEndpoint> {
        self.endpoint
            .lock()
            .ok()
            .and_then(|mut endpoint| endpoint.take())
    }

    pub(super) fn abort_with_reason(mut self, reason: &[u8]) {
        self.connection.close(0_u32.into(), reason);
        if let Some(endpoint) = self.take_endpoint() {
            endpoint.close(0_u32.into(), reason);
        }
        if let Some(task) = self.driver_task.take() {
            abort_and_reap_xhttp_task(task);
        }
    }

    pub(super) async fn close(mut self, reason: &[u8]) {
        self.connection.close(0_u32.into(), reason);
        if let Some(endpoint) = self.take_endpoint() {
            endpoint.close(0_u32.into(), reason);
            if let Some(task) = self.driver_task.take() {
                abort_and_reap_xhttp_task(task);
            }
            endpoint.wait_idle().await;
        } else if let Some(mut task) = self.driver_task.take()
            && time::timeout(RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE, &mut task)
                .await
                .is_err()
        {
            abort_and_reap_xhttp_task(task);
        }
    }
}

impl Drop for XhttpH3Connection {
    fn drop(&mut self) {
        self.connection
            .close(0_u32.into(), b"resident xhttp connection dropped");
        if let Some(endpoint) = self.take_endpoint() {
            endpoint.close(0_u32.into(), b"resident xhttp connection dropped");
        }
        if let Some(task) = self.driver_task.take() {
            abort_and_reap_xhttp_task(task);
        }
    }
}

fn xhttp_h3_stream_error_retires_carrier(error: &h3::error::StreamError) -> bool {
    match error {
        h3::error::StreamError::ConnectionError(_)
        | h3::error::StreamError::RemoteClosing
        | h3::error::StreamError::Undefined(_) => true,
        h3::error::StreamError::RemoteTerminate { code, .. }
        | h3::error::StreamError::StreamError { code, .. } => {
            *code == h3::error::Code::H3_REQUEST_REJECTED
        }
        _ => false,
    }
}

pub(super) fn note_xhttp_h3_stream_error(
    error: &h3::error::StreamError,
    xmux_lease: Option<&XhttpXmuxClientLease>,
) {
    if xhttp_h3_stream_error_retires_carrier(error)
        && let Some(lease) = xmux_lease
    {
        lease.retire_physical();
    }
}

fn note_xhttp_h3_request_error(
    error: &h3::error::StreamError,
    xmux_request: Option<&XhttpXmuxRequestHandle>,
) {
    if xhttp_h3_stream_error_retires_carrier(error)
        && let Some(request) = xmux_request
    {
        request.retire_physical();
    }
}

pub(super) async fn open_xhttp_h3_request(
    client: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    request: http::Request<()>,
    xmux_lease: Option<&XhttpXmuxClientLease>,
    timeout_error: &'static str,
    error_context: &'static str,
) -> Result<h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>, String> {
    let result = time::timeout(RESIDENT_CONNECT_TIMEOUT, client.send_request(request))
        .await
        .map_err(|_| timeout_error.to_owned())?;
    result.map_err(|error| {
        note_xhttp_h3_stream_error(&error, xmux_lease);
        format!("{error_context}: {error:?}")
    })
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
    let mut stream = open_xhttp_h3_request(
        &mut client,
        request,
        xmux_lease,
        "xHTTP H3 download request timeout",
        "send xHTTP H3 download request",
    )
    .await?;
    time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.finish())
        .await
        .map_err(|_| "finish xHTTP H3 download request timeout".to_owned())?
        .map_err(|err| {
            note_xhttp_h3_stream_error(&err, xmux_lease);
            format!("finish xHTTP H3 download request: {err:?}")
        })?;
    let response = time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.recv_response())
        .await
        .map_err(|_| "xHTTP H3 download response timeout".to_owned())?
        .map_err(|err| {
            note_xhttp_h3_stream_error(&err, xmux_lease);
            format!("read xHTTP H3 download response: {err:?}")
        })?;
    if !response.status().is_success() {
        return Err(format!(
            "xHTTP H3 download response status {}",
            response.status()
        ));
    }
    Ok(stream)
}

pub(crate) async fn begin_xhttp_h3_packet_up_request(
    client: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    endpoint: &impl ResidentXhttpEndpointView,
    session_id: &str,
    seq: u64,
    payload: Bytes,
    xmux_request: Option<&XhttpXmuxRequestHandle>,
) -> Result<XhttpPacketUpCompletion, String> {
    let (request, body) = xhttp_h3_packet_up_request(endpoint, session_id, seq, payload)?;
    let stream = time::timeout(RESIDENT_CONNECT_TIMEOUT, client.send_request(request))
        .await
        .map_err(|_| "xHTTP H3 packet-up request timeout".to_owned())?;
    let mut stream = stream.map_err(|error| {
        note_xhttp_h3_request_error(&error, xmux_request);
        format!("send xHTTP H3 packet-up request: {error:?}")
    })?;
    if let Some(body) = body {
        time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.send_data(body))
            .await
            .map_err(|_| "send xHTTP H3 packet-up body timeout".to_owned())?
            .map_err(|err| {
                note_xhttp_h3_request_error(&err, xmux_request);
                format!("send xHTTP H3 packet-up body: {err:?}")
            })?;
    }
    time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.finish())
        .await
        .map_err(|_| "finish xHTTP H3 packet-up body timeout".to_owned())?
        .map_err(|err| {
            note_xhttp_h3_request_error(&err, xmux_request);
            format!("finish xHTTP H3 packet-up body: {err:?}")
        })?;
    let xmux_request = xmux_request.cloned();
    Ok(Box::pin(async move {
        let response = time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.recv_response())
            .await
            .map_err(|_| "xHTTP H3 packet-up response timeout".to_owned())?
            .map_err(|err| {
                note_xhttp_h3_request_error(&err, xmux_request.as_ref());
                format!("recv xHTTP H3 packet-up response: {err:?}")
            })?;
        if !response.status().is_success() {
            return Err(format!(
                "xHTTP H3 packet-up response status {}",
                response.status()
            ));
        }
        drain_xhttp_h3_response_body(stream, xmux_request.as_ref()).await
    }))
}

pub(super) async fn replace_xhttp_h3_packet_up_client(
    binding: &ResidentProxyBinding,
    endpoint: &ResidentXhttpEndpointPlan,
    client: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    connection: &mut Option<XhttpH3Connection>,
    xmux_lease: &mut Option<XhttpXmuxClientLease>,
    xmux_request: &mut Option<XhttpXmuxRequestHandle>,
) -> Result<(), String> {
    if xmux_request.is_none() {
        return Ok(());
    }

    xmux_request.take();
    drop(xmux_lease.take());
    let replacement = open_xhttp_h3_proxy_client(binding, endpoint).await?;
    let old_connection = install_xhttp_h3_packet_up_replacement(
        client,
        connection,
        xmux_lease,
        xmux_request,
        replacement,
    );
    if let Some(old_connection) = old_connection {
        old_connection
            .close(b"resident xhttp h3 packet-up client replaced")
            .await;
    }
    Ok(())
}

fn install_xhttp_h3_packet_up_replacement(
    client: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    connection: &mut Option<XhttpH3Connection>,
    xmux_lease: &mut Option<XhttpXmuxClientLease>,
    xmux_request: &mut Option<XhttpXmuxRequestHandle>,
    replacement: XhttpH3EndpointClient,
) -> Option<XhttpH3Connection> {
    *client = replacement.client;
    let old_connection = replacement
        .connection
        .and_then(|new_connection| connection.replace(new_connection));
    *xmux_request = replacement
        .xmux_lease
        .as_ref()
        .map(XhttpXmuxClientLease::request_handle);
    *xmux_lease = replacement.xmux_lease;
    old_connection
}

async fn drain_xhttp_h3_response_body(
    mut stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    xmux_request: Option<&XhttpXmuxRequestHandle>,
) -> Result<(), String> {
    loop {
        let chunk = time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.recv_data())
            .await
            .map_err(|_| "xHTTP H3 packet-up response body timeout".to_owned())?
            .map_err(|err| {
                note_xhttp_h3_request_error(&err, xmux_request);
                format!("read xHTTP H3 packet-up response body: {err:?}")
            })?;
        if chunk.is_none() {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod request_error_tests {
    use super::*;

    #[test]
    fn remote_goaway_retires_the_h3_carrier() {
        assert!(xhttp_h3_stream_error_retires_carrier(
            &h3::error::StreamError::RemoteClosing
        ));
    }

    #[test]
    fn request_header_limit_does_not_retire_the_h3_carrier() {
        assert!(!xhttp_h3_stream_error_retires_carrier(
            &h3::error::StreamError::HeaderTooBig {
                actual_size: 2,
                max_size: 1,
            }
        ));
    }
}

#[cfg(test)]
mod owner_live_tests;

#[cfg(test)]
mod packet_up_tests;

#[cfg(test)]
fn build_xhttp_h3_client_config(
    endpoint: &ResidentXhttpEndpointPlan,
    tls_provider: ResidentXhttpQuicTlsProvider,
    session_cache: Option<dae_outbound::shared_transport::boring_quic::BoringQuicSessionCache>,
) -> Result<quinn::ClientConfig, String> {
    let system_ca = xhttp_h3_system_ca_snapshot(endpoint)?;
    build_xhttp_h3_client_config_with_system_ca(endpoint, tls_provider, system_ca, session_cache)
}

fn build_xhttp_h3_client_config_with_system_ca(
    endpoint: &ResidentXhttpEndpointPlan,
    tls_provider: ResidentXhttpQuicTlsProvider,
    system_ca: Option<Arc<dae_outbound::shared_transport::SystemCaSnapshot>>,
    session_cache: Option<dae_outbound::shared_transport::boring_quic::BoringQuicSessionCache>,
) -> Result<quinn::ClientConfig, String> {
    if endpoint.ech.is_some() {
        return Err(format!(
            "xHTTP H3 ECH is unavailable with {}: the QUIC TLS provider does not expose per-connection ECH acceptance and authenticated retry configs",
            tls_provider.as_str()
        ));
    }
    if endpoint.reality.is_some() {
        return Err(format!(
            "xHTTP H3 Reality is unavailable with {}: the QUIC TLS carrier has no Reality executor",
            tls_provider.as_str()
        ));
    }
    if tls_provider == ResidentXhttpQuicTlsProvider::ChromeBoring {
        return build_chrome_boring_xhttp_h3_client_config_with_system_ca(
            endpoint,
            system_ca,
            session_cache,
        );
    }
    let policy =
        dae_outbound::shared_transport::boring_quic::BoringQuicClientPolicy::new(
            [b"h3".as_slice()],
        )
        .map_err(|err| format!("build xHTTP H3 BoringSSL QUIC policy: {err}"))?
        .allow_insecure(endpoint.allow_insecure)
        .zero_rtt(false);
    dae_outbound::shared_transport::boring_quic::build_boring_quic_client_config_with_session_cache_and_system_ca_snapshot(
        &policy,
        Arc::new(xhttp_h3_transport_config()?),
        session_cache,
        system_ca,
    )
    .map_err(|err| format!("build xHTTP H3 BoringSSL QUIC config: {err}"))
}

pub(super) fn xhttp_h3_transport_config() -> Result<quinn::TransportConfig, String> {
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
