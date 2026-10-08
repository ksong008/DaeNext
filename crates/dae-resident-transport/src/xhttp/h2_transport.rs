mod idle;
use super::request::{xhttp_h2_packet_up_request, xhttp_h2_request, xhttp_session_path_suffix};
use super::xmux::{
    XhttpXmuxClientLease, XhttpXmuxKey, XhttpXmuxRequestHandle, note_xhttp_xmux_request,
    select_xhttp_h2_xmux_client,
};
use super::*;
use idle::{ReadActivity, ReadActivityIo};

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
    let keep_alive = xhttp_keep_alive_interval(endpoint.xmux.as_ref(), Duration::from_secs(45))?;
    let Some(xmux) = binding.persistent_xhttp_xmux() else {
        let client = open_async_resident_tls_client_with_binding(binding, mptcp).await?;
        let (sender, connection_task) = open_xhttp_h2_sender(client, keep_alive).await?;
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
            let (sender, connection_task) = open_xhttp_h2_sender(client, keep_alive).await?;
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
    let keep_alive = xhttp_keep_alive_interval(endpoint.xmux.as_ref(), Duration::from_secs(45))?;
    let Some(xmux) = binding.persistent_xhttp_download_xmux() else {
        let client = open_async_xhttp_endpoint_tls_client(endpoint, mark, mptcp).await?;
        let (sender, connection_task) = open_xhttp_h2_sender(client, keep_alive).await?;
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
            let (sender, connection_task) = open_xhttp_h2_sender(client, keep_alive).await?;
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
    keep_alive: Option<Duration>,
) -> Result<(h2::client::SendRequest<Bytes>, tokio::task::JoinHandle<()>), String> {
    let mut h2_builder = h2::client::Builder::new();
    let resources = H2CarrierOwnerResourceProfile::selected();
    h2_builder
        .initial_window_size(resources.stream_receive_window_bytes())
        .initial_connection_window_size(resources.connection_receive_window_bytes());
    let activity = Arc::new(ReadActivity::new());
    let client = ReadActivityIo::new(client, Arc::clone(&activity));
    let (sender, connection) =
        time::timeout(RESIDENT_CONNECT_TIMEOUT, h2_builder.handshake(client))
            .await
            .map_err(|_| "xHTTP HTTP/2 handshake timeout".to_owned())?
            .map_err(|err| format!("xHTTP HTTP/2 client handshake: {err}"))?;
    let connection_task = tokio::spawn(drive_xhttp_h2_connection(
        connection,
        keep_alive,
        RESIDENT_CONNECT_TIMEOUT,
        Some(activity),
    ));
    Ok((sender, connection_task))
}

async fn drive_xhttp_h2_connection<T>(
    mut connection: h2::client::Connection<T, Bytes>,
    keep_alive: Option<Duration>,
    pong_timeout: Duration,
    activity: Option<Arc<ReadActivity>>,
) where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let Some(interval) = keep_alive else {
        let _ = connection.await;
        return;
    };
    let Some(mut ping_pong) = connection.ping_pong() else {
        let _ = connection.await;
        return;
    };
    tokio::pin!(connection);
    loop {
        // Any received bytes postpone the next probe. Reuse the carrier task.
        let deadline = activity.as_ref().map_or_else(
            || time::Instant::now() + interval,
            |activity| activity.deadline(interval),
        );
        tokio::select! {
            _ = &mut connection => return,
            _ = time::sleep_until(deadline) => {},
        }
        if activity
            .as_ref()
            .is_some_and(|activity| activity.deadline(interval) > time::Instant::now())
        {
            continue;
        }
        tokio::select! {
            _ = &mut connection => return,
            pong = time::timeout(pong_timeout, ping_pong.ping(h2::Ping::opaque())) => {
                if !matches!(pong, Ok(Ok(_))) {
                    return;
                }
            }
        }
    }
}

pub async fn open_xhttp_h2_download_stream(
    sender: &mut h2::client::SendRequest<Bytes>,
    endpoint: &ResidentXhttpEndpointPlan,
    session_id: &str,
    xmux_lease: Option<&XhttpXmuxClientLease>,
) -> Result<XhttpResponseBody<h2::RecvStream>, String> {
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
    Ok(xhttp_h2_response_body(response, "xHTTP HTTP/2 download"))
}

pub(super) fn xhttp_h2_response_body(
    response: h2::client::ResponseFuture,
    context: &'static str,
) -> XhttpResponseBody<h2::RecvStream> {
    XhttpResponseBody::pending(context, async move {
        let response = response
            .await
            .map_err(|err| format!("read {context} response headers: {err}"))?;
        if !response.status().is_success() {
            return Err(format!("{context} response status {}", response.status()));
        }
        Ok(response.into_body())
    })
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
