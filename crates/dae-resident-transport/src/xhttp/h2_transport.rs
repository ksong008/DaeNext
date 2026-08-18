use super::request::{xhttp_h2_packet_up_request, xhttp_h2_request, xhttp_session_path_suffix};
use super::xmux::{
    XhttpXmuxClientLease, XhttpXmuxKey, XhttpXmuxRequestHandle, note_xhttp_xmux_request,
    select_xhttp_h2_xmux_client,
};
use super::*;

pub struct XhttpH2EndpointSender {
    pub sender: h2::client::SendRequest<Bytes>,
    pub connection_task: Option<tokio::task::JoinHandle<()>>,
    pub xmux_lease: Option<XhttpXmuxClientLease>,
}

type XhttpH2OwnerOpenFuture = Pin<
    Box<dyn std::future::Future<Output = Result<XhttpH2EndpointSender, String>> + Send + 'static>,
>;

pub async fn open_xhttp_h2_proxy_sender(
    binding: &ResidentProxyBinding,
    endpoint: &ResidentXhttpEndpointPlan,
    mptcp: bool,
) -> Result<XhttpH2EndpointSender, String> {
    let mark = binding.effective_socket_mark();
    let Some(xmux) = binding.persistent_xhttp_xmux() else {
        let client = open_async_resident_tls_client_with_binding(binding, mptcp).await?;
        let (sender, connection_task) = open_xhttp_h2_sender(client).await?;
        return Ok(XhttpH2EndpointSender {
            sender,
            connection_task: Some(connection_task),
            xmux_lease: None,
        });
    };
    let resolved = XhttpResolvedEndpoint::resolve(endpoint).await?;
    let key = XhttpXmuxKey::primary(binding, endpoint, resolved.identity(), xmux, mark, mptcp)?;
    let selected = select_xhttp_h2_xmux_client(key, xmux.clone(), || -> XhttpH2OwnerOpenFuture {
        let owner_proxy = Arc::clone(binding.shared_plan());
        let owner_candidates = resolved.candidates().to_vec();
        Box::pin(async move {
            let client = open_async_vless_tls_client_with_flow_at_candidates(
                &owner_proxy,
                &owner_candidates,
                mark,
                mptcp,
            )
            .await?;
            let (sender, connection_task) = open_xhttp_h2_sender(client).await?;
            Ok(XhttpH2EndpointSender {
                sender,
                connection_task: Some(connection_task),
                xmux_lease: None,
            })
        })
    })
    .await?;
    Ok(XhttpH2EndpointSender {
        sender: selected.sender,
        connection_task: None,
        xmux_lease: Some(selected.lease),
    })
}

pub async fn open_xhttp_h2_endpoint_sender(
    binding: &ResidentProxyBinding,
    endpoint: &ResidentXhttpEndpointPlan,
    mptcp: bool,
) -> Result<XhttpH2EndpointSender, String> {
    let mark = binding.effective_socket_mark();
    let Some(xmux) = binding.persistent_xhttp_download_xmux() else {
        let client = open_async_xhttp_endpoint_tls_client(endpoint, mark, mptcp).await?;
        let (sender, connection_task) = open_xhttp_h2_sender(client).await?;
        return Ok(XhttpH2EndpointSender {
            sender,
            connection_task: Some(connection_task),
            xmux_lease: None,
        });
    };
    let resolved = XhttpResolvedEndpoint::resolve(endpoint).await?;
    let key = XhttpXmuxKey::download(binding, endpoint, resolved.identity(), xmux, mark, mptcp)?;
    let selected = select_xhttp_h2_xmux_client(key, xmux.clone(), || -> XhttpH2OwnerOpenFuture {
        let owner_endpoint = endpoint.clone();
        let owner_candidates = resolved.candidates().to_vec();
        Box::pin(async move {
            let client = open_async_xhttp_endpoint_tls_client_at_candidates(
                &owner_endpoint,
                &owner_candidates,
                mark,
                mptcp,
            )
            .await?;
            let (sender, connection_task) = open_xhttp_h2_sender(client).await?;
            Ok(XhttpH2EndpointSender {
                sender,
                connection_task: Some(connection_task),
                xmux_lease: None,
            })
        })
    })
    .await?;
    Ok(XhttpH2EndpointSender {
        sender: selected.sender,
        connection_task: None,
        xmux_lease: Some(selected.lease),
    })
}

async fn open_xhttp_h2_sender(
    client: AsyncResidentTlsClient,
) -> Result<(h2::client::SendRequest<Bytes>, tokio::task::JoinHandle<()>), String> {
    let mut h2_builder = h2::client::Builder::new();
    H2CarrierOwnerResourceProfile::selected().configure_client_builder(&mut h2_builder);
    let (sender, connection) =
        time::timeout(RESIDENT_CONNECT_TIMEOUT, h2_builder.handshake(client))
            .await
            .map_err(|_| "xHTTP HTTP/2 handshake timeout".to_owned())?
            .map_err(|err| format!("xHTTP HTTP/2 client handshake: {err}"))?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok((sender, connection_task))
}

pub async fn open_xhttp_h2_download_stream(
    sender: &mut h2::client::SendRequest<Bytes>,
    endpoint: &ResidentXhttpEndpointPlan,
    session_id: &str,
    xmux_lease: Option<&XhttpXmuxClientLease>,
) -> Result<h2::RecvStream, String> {
    note_xhttp_xmux_request(xmux_lease);
    let request = xhttp_h2_request(
        http::Method::GET,
        endpoint,
        &xhttp_session_path_suffix(session_id, None),
        false,
    )?;
    let (response, _send_stream) = sender
        .send_request(request, true)
        .map_err(|err| format!("send xHTTP HTTP/2 download request headers: {err}"))?;
    let response = time::timeout(RESIDENT_CONNECT_TIMEOUT, response)
        .await
        .map_err(|_| "xHTTP HTTP/2 download response headers timeout".to_owned())?
        .map_err(|err| format!("read xHTTP HTTP/2 download response headers: {err}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "xHTTP HTTP/2 download response status {}",
            response.status()
        ));
    }
    Ok(response.into_body())
}

pub async fn begin_xhttp_h2_packet_up_request(
    sender: &mut h2::client::SendRequest<Bytes>,
    endpoint: &impl ResidentXhttpEndpointView,
    session_id: &str,
    seq: u64,
    payload: Bytes,
) -> Result<XhttpPacketUpCompletion, String> {
    time::timeout(
        RESIDENT_CONNECT_TIMEOUT,
        std::future::poll_fn(|cx| sender.poll_ready(cx)),
    )
    .await
    .map_err(|_| "xHTTP HTTP/2 packet-up request readiness timeout".to_owned())?
    .map_err(|err| format!("prepare xHTTP HTTP/2 packet-up request: {err}"))?;
    let (request, body) = xhttp_h2_packet_up_request(endpoint, session_id, seq, payload)?;
    let end_stream = body.is_none();
    let (response, mut send_stream) = sender
        .send_request(request, end_stream)
        .map_err(|err| format!("send xHTTP HTTP/2 packet-up request headers: {err}"))?;
    if let Some(body) = body {
        send_h2_data_with_context(&mut send_stream, body, true, "xHTTP HTTP/2 packet-up").await?;
    }
    Ok(Box::pin(async move {
        let response = time::timeout(RESIDENT_CONNECT_TIMEOUT, response)
            .await
            .map_err(|_| "xHTTP HTTP/2 packet-up response headers timeout".to_owned())?
            .map_err(|err| format!("read xHTTP HTTP/2 packet-up response headers: {err}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "xHTTP HTTP/2 packet-up response status {}",
                response.status()
            ));
        }
        drain_xhttp_h2_response_body(response.into_body()).await
    }))
}

pub async fn replace_xhttp_h2_packet_up_client(
    binding: &ResidentProxyBinding,
    endpoint: &ResidentXhttpEndpointPlan,
    mptcp: bool,
    sender: &mut h2::client::SendRequest<Bytes>,
    connection_task: &mut Option<tokio::task::JoinHandle<()>>,
    xmux_lease: &mut Option<XhttpXmuxClientLease>,
    xmux_request: &mut Option<XhttpXmuxRequestHandle>,
) -> Result<(), String> {
    if xmux_request.is_none() {
        return Ok(());
    }

    if let Some(task) = connection_task.take() {
        task.abort();
    }
    xmux_request.take();
    drop(xmux_lease.take());
    let replacement = open_xhttp_h2_proxy_sender(binding, endpoint, mptcp).await?;
    *sender = replacement.sender;
    *connection_task = replacement.connection_task;
    *xmux_request = replacement
        .xmux_lease
        .as_ref()
        .map(XhttpXmuxClientLease::request_handle);
    *xmux_lease = replacement.xmux_lease;
    Ok(())
}

pub async fn drain_xhttp_h2_response_body(mut body: h2::RecvStream) -> Result<(), String> {
    loop {
        let data = time::timeout(RESIDENT_CONNECT_TIMEOUT, body.data())
            .await
            .map_err(|_| "xHTTP HTTP/2 packet-up response body timeout".to_owned())?;
        let Some(data) = data else {
            return Ok(());
        };
        let bytes =
            data.map_err(|err| format!("read xHTTP HTTP/2 packet-up response body: {err}"))?;
        body.flow_control()
            .release_capacity(bytes.len())
            .map_err(|err| format!("release xHTTP HTTP/2 packet-up response capacity: {err}"))?;
    }
}

#[cfg(test)]
#[path = "h2_transport/tests.rs"]
mod tests;
