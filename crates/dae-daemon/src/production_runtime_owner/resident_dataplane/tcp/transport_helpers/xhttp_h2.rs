use super::*;
use bytes::Buf;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};

pub(crate) trait ResidentXhttpEndpointView {
    fn server_name(&self) -> &str;
    fn stream_host(&self) -> &str;
    fn stream_path(&self) -> &str;
}

impl ResidentXhttpEndpointView for ResidentProxyPlan {
    fn server_name(&self) -> &str {
        &self.server_name
    }

    fn stream_host(&self) -> &str {
        &self.stream_host
    }

    fn stream_path(&self) -> &str {
        &self.stream_path
    }
}

impl ResidentXhttpEndpointView for ResidentXhttpEndpointPlan {
    fn server_name(&self) -> &str {
        &self.server_name
    }

    fn stream_host(&self) -> &str {
        &self.stream_host
    }

    fn stream_path(&self) -> &str {
        &self.stream_path
    }
}

pub(crate) struct XhttpPacketUpParts {
    pub(crate) session_id: String,
    pub(crate) upload: XhttpUploadClient,
    pub(crate) download: XhttpDownloadClient,
    pub(crate) upload_underlay: &'static str,
    pub(crate) upload_http_version: ResidentXhttpHttpVersion,
    pub(crate) download_separate: bool,
}

pub(crate) enum XhttpUploadClient {
    H1 {
        proxy: Box<ResidentProxyPlan>,
        endpoint: ResidentXhttpEndpointPlan,
        mark: u32,
        mptcp: bool,
    },
    H2 {
        endpoint: ResidentXhttpEndpointPlan,
        sender: h2::client::SendRequest<Bytes>,
        connection_task: tokio::task::JoinHandle<()>,
    },
    H3 {
        endpoint: ResidentXhttpEndpointPlan,
        connection: XhttpH3Connection,
    },
}

pub(crate) enum XhttpDownloadClient {
    H1 {
        body: XhttpH1DownloadBody,
    },
    H2 {
        recv: h2::RecvStream,
        _keepalive_sender: Option<h2::client::SendRequest<Bytes>>,
        connection_task: Option<tokio::task::JoinHandle<()>>,
    },
    H3 {
        recv: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
        connection: Option<XhttpH3Connection>,
    },
}

pub(crate) struct XhttpH3Connection {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    client: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver_task: tokio::task::JoinHandle<()>,
}

pub(crate) struct XhttpH1DownloadBody {
    client: AsyncResidentTlsClient,
    buffer: VecDeque<u8>,
    state: XhttpH1BodyState,
}

#[derive(Debug)]
enum XhttpH1BodyState {
    ChunkSize,
    ChunkData(usize),
    ChunkCrlf,
    Trailer,
    Identity,
    Done,
}

pub(crate) async fn open_xhttp_packet_up_parts(
    proxy: &ResidentProxyPlan,
    mark: u32,
    mptcp: bool,
) -> Result<XhttpPacketUpParts, String> {
    let session_id = new_xhttp_session_id();
    let upload_endpoint = ResidentXhttpEndpointPlan::from_proxy(proxy);
    let download_endpoint = proxy
        .xhttp_download
        .clone()
        .unwrap_or_else(|| upload_endpoint.clone());
    let download_separate = proxy.xhttp_download.is_some();
    let upload_http_version = if proxy.tls == "reality" {
        ResidentXhttpHttpVersion::H2
    } else {
        upload_endpoint.http_version()
    };
    let download_http_version = download_endpoint.http_version();
    match (upload_http_version, download_http_version) {
        (ResidentXhttpHttpVersion::H1, ResidentXhttpHttpVersion::H1) => {
            let recv = open_xhttp_h1_download_stream(
                proxy,
                &download_endpoint,
                mark,
                mptcp,
                &session_id,
                download_separate,
            )
            .await?;
            Ok(XhttpPacketUpParts {
                session_id,
                upload: XhttpUploadClient::H1 {
                    proxy: Box::new(proxy.clone()),
                    endpoint: upload_endpoint,
                    mark,
                    mptcp,
                },
                download: XhttpDownloadClient::H1 { body: recv },
                upload_underlay: xhttp_primary_tls_underlay_name(proxy),
                upload_http_version,
                download_separate,
            })
        }
        (ResidentXhttpHttpVersion::H1, ResidentXhttpHttpVersion::H2) => {
            let mut download_sender =
                open_xhttp_h2_endpoint_sender(&download_endpoint, mark, mptcp).await?;
            let recv = open_xhttp_h2_download_stream(
                &mut download_sender.sender,
                &download_endpoint,
                &session_id,
            )
            .await?;
            Ok(XhttpPacketUpParts {
                session_id,
                upload: XhttpUploadClient::H1 {
                    proxy: Box::new(proxy.clone()),
                    endpoint: upload_endpoint,
                    mark,
                    mptcp,
                },
                download: XhttpDownloadClient::H2 {
                    recv,
                    _keepalive_sender: Some(download_sender.sender),
                    connection_task: Some(download_sender.connection_task),
                },
                upload_underlay: xhttp_primary_tls_underlay_name(proxy),
                upload_http_version,
                download_separate,
            })
        }
        (ResidentXhttpHttpVersion::H1, ResidentXhttpHttpVersion::H3) => {
            let download_connection = open_xhttp_h3_connection(&download_endpoint, mark).await?;
            let recv = open_xhttp_h3_download_stream(
                &download_endpoint,
                download_connection.client.clone(),
                &session_id,
            )
            .await?;
            Ok(XhttpPacketUpParts {
                session_id,
                upload: XhttpUploadClient::H1 {
                    proxy: Box::new(proxy.clone()),
                    endpoint: upload_endpoint,
                    mark,
                    mptcp,
                },
                download: XhttpDownloadClient::H3 {
                    recv,
                    connection: Some(download_connection),
                },
                upload_underlay: xhttp_primary_tls_underlay_name(proxy),
                upload_http_version,
                download_separate,
            })
        }
        (ResidentXhttpHttpVersion::H2, ResidentXhttpHttpVersion::H1) => {
            let client = open_async_vless_tls_client_with_flow(proxy, mark, mptcp).await?;
            let upload_underlay = async_tls_underlay_name(&client);
            let (sender, connection_task) = open_xhttp_h2_sender(client).await?;
            let recv = open_xhttp_h1_download_stream(
                proxy,
                &download_endpoint,
                mark,
                mptcp,
                &session_id,
                true,
            )
            .await?;
            Ok(XhttpPacketUpParts {
                session_id,
                upload: XhttpUploadClient::H2 {
                    endpoint: upload_endpoint,
                    sender,
                    connection_task,
                },
                download: XhttpDownloadClient::H1 { body: recv },
                upload_underlay,
                upload_http_version,
                download_separate,
            })
        }
        (ResidentXhttpHttpVersion::H2, ResidentXhttpHttpVersion::H2) if !download_separate => {
            let client = open_async_vless_tls_client_with_flow(proxy, mark, mptcp).await?;
            let upload_underlay = async_tls_underlay_name(&client);
            let (mut sender, connection_task) = open_xhttp_h2_sender(client).await?;
            let recv =
                open_xhttp_h2_download_stream(&mut sender, &upload_endpoint, &session_id).await?;
            Ok(XhttpPacketUpParts {
                session_id,
                upload: XhttpUploadClient::H2 {
                    endpoint: upload_endpoint,
                    sender,
                    connection_task,
                },
                download: XhttpDownloadClient::H2 {
                    recv,
                    _keepalive_sender: None,
                    connection_task: None,
                },
                upload_underlay,
                upload_http_version,
                download_separate,
            })
        }
        (ResidentXhttpHttpVersion::H2, ResidentXhttpHttpVersion::H2) => {
            let client = open_async_vless_tls_client_with_flow(proxy, mark, mptcp).await?;
            let upload_underlay = async_tls_underlay_name(&client);
            let (sender, connection_task) = open_xhttp_h2_sender(client).await?;
            let mut download_sender =
                open_xhttp_h2_endpoint_sender(&download_endpoint, mark, mptcp).await?;
            let recv = open_xhttp_h2_download_stream(
                &mut download_sender.sender,
                &download_endpoint,
                &session_id,
            )
            .await?;
            Ok(XhttpPacketUpParts {
                session_id,
                upload: XhttpUploadClient::H2 {
                    endpoint: upload_endpoint,
                    sender,
                    connection_task,
                },
                download: XhttpDownloadClient::H2 {
                    recv,
                    _keepalive_sender: Some(download_sender.sender),
                    connection_task: Some(download_sender.connection_task),
                },
                upload_underlay,
                upload_http_version,
                download_separate,
            })
        }
        (ResidentXhttpHttpVersion::H2, ResidentXhttpHttpVersion::H3) => {
            let client = open_async_vless_tls_client_with_flow(proxy, mark, mptcp).await?;
            let upload_underlay = async_tls_underlay_name(&client);
            let (sender, connection_task) = open_xhttp_h2_sender(client).await?;
            let download_connection = open_xhttp_h3_connection(&download_endpoint, mark).await?;
            let recv = open_xhttp_h3_download_stream(
                &download_endpoint,
                download_connection.client.clone(),
                &session_id,
            )
            .await?;
            Ok(XhttpPacketUpParts {
                session_id,
                upload: XhttpUploadClient::H2 {
                    endpoint: upload_endpoint,
                    sender,
                    connection_task,
                },
                download: XhttpDownloadClient::H3 {
                    recv,
                    connection: Some(download_connection),
                },
                upload_underlay,
                upload_http_version,
                download_separate,
            })
        }
        (ResidentXhttpHttpVersion::H3, ResidentXhttpHttpVersion::H1) => {
            let upload_underlay = "quinn-h3";
            let upload_connection = open_xhttp_h3_connection(&upload_endpoint, mark).await?;
            let recv = open_xhttp_h1_download_stream(
                proxy,
                &download_endpoint,
                mark,
                mptcp,
                &session_id,
                true,
            )
            .await?;
            Ok(XhttpPacketUpParts {
                session_id,
                upload: XhttpUploadClient::H3 {
                    endpoint: upload_endpoint,
                    connection: upload_connection,
                },
                download: XhttpDownloadClient::H1 { body: recv },
                upload_underlay,
                upload_http_version,
                download_separate,
            })
        }
        (ResidentXhttpHttpVersion::H3, ResidentXhttpHttpVersion::H2) => {
            let upload_underlay = "quinn-h3";
            let upload_connection = open_xhttp_h3_connection(&upload_endpoint, mark).await?;
            let mut download_sender =
                open_xhttp_h2_endpoint_sender(&download_endpoint, mark, mptcp).await?;
            let recv = open_xhttp_h2_download_stream(
                &mut download_sender.sender,
                &download_endpoint,
                &session_id,
            )
            .await?;
            Ok(XhttpPacketUpParts {
                session_id,
                upload: XhttpUploadClient::H3 {
                    endpoint: upload_endpoint,
                    connection: upload_connection,
                },
                download: XhttpDownloadClient::H2 {
                    recv,
                    _keepalive_sender: Some(download_sender.sender),
                    connection_task: Some(download_sender.connection_task),
                },
                upload_underlay,
                upload_http_version,
                download_separate,
            })
        }
        (ResidentXhttpHttpVersion::H3, ResidentXhttpHttpVersion::H3) if !download_separate => {
            let upload_underlay = "quinn-h3";
            let upload_connection = open_xhttp_h3_connection(&upload_endpoint, mark).await?;
            let recv = open_xhttp_h3_download_stream(
                &upload_endpoint,
                upload_connection.client.clone(),
                &session_id,
            )
            .await?;
            Ok(XhttpPacketUpParts {
                session_id,
                upload: XhttpUploadClient::H3 {
                    endpoint: upload_endpoint,
                    connection: upload_connection,
                },
                download: XhttpDownloadClient::H3 {
                    recv,
                    connection: None,
                },
                upload_underlay,
                upload_http_version,
                download_separate,
            })
        }
        (ResidentXhttpHttpVersion::H3, ResidentXhttpHttpVersion::H3) => {
            let upload_underlay = "quinn-h3";
            let upload_connection = open_xhttp_h3_connection(&upload_endpoint, mark).await?;
            let download_connection = open_xhttp_h3_connection(&download_endpoint, mark).await?;
            let recv = open_xhttp_h3_download_stream(
                &download_endpoint,
                download_connection.client.clone(),
                &session_id,
            )
            .await?;
            Ok(XhttpPacketUpParts {
                session_id,
                upload: XhttpUploadClient::H3 {
                    endpoint: upload_endpoint,
                    connection: upload_connection,
                },
                download: XhttpDownloadClient::H3 {
                    recv,
                    connection: Some(download_connection),
                },
                upload_underlay,
                upload_http_version,
                download_separate,
            })
        }
    }
}

struct XhttpH2EndpointSender {
    sender: h2::client::SendRequest<Bytes>,
    connection_task: tokio::task::JoinHandle<()>,
}

async fn open_xhttp_h2_endpoint_sender(
    endpoint: &ResidentXhttpEndpointPlan,
    mark: u32,
    mptcp: bool,
) -> Result<XhttpH2EndpointSender, String> {
    let client = open_async_xhttp_endpoint_tls_client(endpoint, mark, mptcp).await?;
    let (sender, connection_task) = open_xhttp_h2_sender(client).await?;
    Ok(XhttpH2EndpointSender {
        sender,
        connection_task,
    })
}

async fn open_xhttp_h2_sender(
    client: AsyncResidentTlsClient,
) -> Result<(h2::client::SendRequest<Bytes>, tokio::task::JoinHandle<()>), String> {
    let (sender, connection) =
        time::timeout(RESIDENT_CONNECT_TIMEOUT, h2::client::handshake(client))
            .await
            .map_err(|_| "xHTTP HTTP/2 handshake timeout".to_owned())?
            .map_err(|err| format!("xHTTP HTTP/2 client handshake: {err}"))?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok((sender, connection_task))
}

fn xhttp_primary_tls_underlay_name(proxy: &ResidentProxyPlan) -> &'static str {
    if proxy.tls == "reality" {
        "reality"
    } else if proxy.utls_fingerprint.is_some() {
        "boringssl"
    } else {
        "rustls"
    }
}

async fn open_xhttp_h1_download_stream(
    proxy: &ResidentProxyPlan,
    endpoint: &ResidentXhttpEndpointPlan,
    mark: u32,
    mptcp: bool,
    session_id: &str,
    separate_endpoint: bool,
) -> Result<XhttpH1DownloadBody, String> {
    let client = if separate_endpoint {
        open_async_xhttp_endpoint_tls_client(endpoint, mark, mptcp).await?
    } else {
        open_async_vless_tls_client_with_flow(proxy, mark, mptcp).await?
    };
    open_xhttp_h1_download_stream_with_client(client, endpoint, session_id).await
}

async fn open_xhttp_h1_download_stream_with_client(
    mut client: AsyncResidentTlsClient,
    endpoint: &ResidentXhttpEndpointPlan,
    session_id: &str,
) -> Result<XhttpH1DownloadBody, String> {
    let request = xhttp_h1_request_bytes(
        http::Method::GET,
        endpoint,
        &xhttp_session_path_suffix(session_id, None),
        None,
    );
    time::timeout(RESIDENT_CONNECT_TIMEOUT, client.write_all(&request))
        .await
        .map_err(|_| "xHTTP HTTP/1.1 download request timeout".to_owned())?
        .map_err(|err| format!("write xHTTP HTTP/1.1 download request: {err}"))?;
    time::timeout(RESIDENT_CONNECT_TIMEOUT, client.flush())
        .await
        .map_err(|_| "flush xHTTP HTTP/1.1 download request timeout".to_owned())?
        .map_err(|err| format!("flush xHTTP HTTP/1.1 download request: {err}"))?;
    let response = read_xhttp_h1_response_head(&mut client, "download").await?;
    if !(200..300).contains(&response.status) {
        return Err(format!(
            "xHTTP HTTP/1.1 download response status {}",
            response.status
        ));
    }
    Ok(XhttpH1DownloadBody::new(
        client,
        response.headers,
        response.body_prefix,
    ))
}

async fn send_xhttp_h1_packet_up_request(
    proxy: &ResidentProxyPlan,
    endpoint: &ResidentXhttpEndpointPlan,
    mark: u32,
    mptcp: bool,
    session_id: &str,
    seq: u64,
    payload: Bytes,
) -> Result<(), String> {
    let mut client = open_async_vless_tls_client_with_flow(proxy, mark, mptcp).await?;
    let request = xhttp_h1_request_bytes(
        http::Method::POST,
        endpoint,
        &xhttp_session_path_suffix(session_id, Some(seq)),
        Some(&payload),
    );
    time::timeout(RESIDENT_CONNECT_TIMEOUT, client.write_all(&request))
        .await
        .map_err(|_| "xHTTP HTTP/1.1 packet-up request timeout".to_owned())?
        .map_err(|err| format!("write xHTTP HTTP/1.1 packet-up request: {err}"))?;
    time::timeout(RESIDENT_CONNECT_TIMEOUT, client.flush())
        .await
        .map_err(|_| "flush xHTTP HTTP/1.1 packet-up request timeout".to_owned())?
        .map_err(|err| format!("flush xHTTP HTTP/1.1 packet-up request: {err}"))?;
    let response = read_xhttp_h1_response_head(&mut client, "packet-up").await?;
    if !(200..300).contains(&response.status) {
        return Err(format!(
            "xHTTP HTTP/1.1 packet-up response status {}",
            response.status
        ));
    }
    let _ = client.shutdown().await;
    Ok(())
}

struct XhttpH1ResponseHead {
    status: u16,
    headers: Vec<(String, String)>,
    body_prefix: Vec<u8>,
}

async fn read_xhttp_h1_response_head(
    client: &mut AsyncResidentTlsClient,
    context: &str,
) -> Result<XhttpH1ResponseHead, String> {
    const MAX_HEAD_BYTES: usize = 64 * 1024;
    let mut received = Vec::with_capacity(1024);
    let mut buf = [0_u8; 1024];
    loop {
        if let Some(end) = find_header_end(&received) {
            let body_prefix = received.split_off(end + 4);
            let head = &received[..end];
            return parse_xhttp_h1_response_head(head, body_prefix, context);
        }
        if received.len() >= MAX_HEAD_BYTES {
            return Err(format!(
                "xHTTP HTTP/1.1 {context} response headers exceed {MAX_HEAD_BYTES} bytes"
            ));
        }
        let read = time::timeout(RESIDENT_CONNECT_TIMEOUT, client.read(&mut buf))
            .await
            .map_err(|_| format!("xHTTP HTTP/1.1 {context} response headers timeout"))?
            .map_err(|err| format!("read xHTTP HTTP/1.1 {context} response headers: {err}"))?;
        if read == 0 {
            return Err(format!(
                "xHTTP HTTP/1.1 {context} response closed before headers"
            ));
        }
        received.extend_from_slice(&buf[..read]);
    }
}

fn parse_xhttp_h1_response_head(
    head: &[u8],
    body_prefix: Vec<u8>,
    context: &str,
) -> Result<XhttpH1ResponseHead, String> {
    let text = std::str::from_utf8(head)
        .map_err(|err| format!("xHTTP HTTP/1.1 {context} response headers utf8: {err}"))?;
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| format!("xHTTP HTTP/1.1 {context} response missing status line"))?;
    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(format!(
            "xHTTP HTTP/1.1 {context} response has unsupported version {version}"
        ));
    }
    let status = status_parts
        .next()
        .ok_or_else(|| format!("xHTTP HTTP/1.1 {context} response missing status code"))?
        .parse::<u16>()
        .map_err(|err| format!("parse xHTTP HTTP/1.1 {context} response status: {err}"))?;
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect::<Vec<_>>();
    Ok(XhttpH1ResponseHead {
        status,
        headers,
        body_prefix,
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

async fn open_xhttp_h2_download_stream(
    sender: &mut h2::client::SendRequest<Bytes>,
    endpoint: &ResidentXhttpEndpointPlan,
    session_id: &str,
) -> Result<h2::RecvStream, String> {
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

pub(crate) async fn send_xhttp_h2_packet_up_request(
    sender: &mut h2::client::SendRequest<Bytes>,
    endpoint: &impl ResidentXhttpEndpointView,
    session_id: &str,
    seq: u64,
    payload: Bytes,
) -> Result<(), String> {
    let request = xhttp_h2_request(
        http::Method::POST,
        endpoint,
        &xhttp_session_path_suffix(session_id, Some(seq)),
        true,
    )?;
    let (response, mut send_stream) = sender
        .send_request(request, false)
        .map_err(|err| format!("send xHTTP HTTP/2 packet-up request headers: {err}"))?;
    send_h2_data_with_context(&mut send_stream, payload, true, "xHTTP HTTP/2 packet-up").await?;
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
}

pub(crate) async fn send_xhttp_packet_up_request(
    upload: &mut XhttpUploadClient,
    session_id: &str,
    seq: u64,
    payload: Bytes,
) -> Result<(), String> {
    match upload {
        XhttpUploadClient::H1 {
            proxy,
            endpoint,
            mark,
            mptcp,
        } => {
            send_xhttp_h1_packet_up_request(
                proxy, endpoint, *mark, *mptcp, session_id, seq, payload,
            )
            .await
        }
        XhttpUploadClient::H2 {
            endpoint, sender, ..
        } => send_xhttp_h2_packet_up_request(sender, endpoint, session_id, seq, payload).await,
        XhttpUploadClient::H3 {
            endpoint,
            connection,
        } => {
            send_xhttp_h3_packet_up_request(
                &mut connection.client,
                endpoint,
                session_id,
                seq,
                payload,
            )
            .await
        }
    }
}

pub(crate) async fn poll_xhttp_download_data(
    download: &mut XhttpDownloadClient,
) -> Result<Option<Bytes>, String> {
    match download {
        XhttpDownloadClient::H1 { body } => {
            let data = poll_fn(|cx| match body.poll_next(cx) {
                Poll::Ready(value) => Poll::Ready(Some(value)),
                Poll::Pending => Poll::Ready(None),
            })
            .await;
            match data {
                Some(value) => value,
                None => Ok(None),
            }
        }
        XhttpDownloadClient::H2 { recv, .. } => {
            let data = {
                let data_future = recv.data();
                tokio::pin!(data_future);
                poll_fn(|cx| match data_future.as_mut().poll(cx) {
                    Poll::Ready(value) => Poll::Ready(Some(value)),
                    Poll::Pending => Poll::Ready(None),
                })
                .await
            };
            match data {
                Some(Some(Ok(bytes))) => {
                    recv.flow_control()
                        .release_capacity(bytes.len())
                        .map_err(|err| format!("release xHTTP HTTP/2 download capacity: {err}"))?;
                    Ok(Some(bytes))
                }
                Some(Some(Err(err))) => Err(format!("read xHTTP HTTP/2 download data: {err}")),
                Some(None) => Err("xHTTP HTTP/2 download stream closed".to_owned()),
                None => Ok(None),
            }
        }
        XhttpDownloadClient::H3 { recv, .. } => {
            let data_future = recv.recv_data();
            tokio::pin!(data_future);
            let data = poll_fn(|cx| match data_future.as_mut().poll(cx) {
                Poll::Ready(value) => Poll::Ready(Some(value)),
                Poll::Pending => Poll::Ready(None),
            })
            .await;
            match data {
                Some(Ok(Some(mut chunk))) => {
                    let remaining = chunk.remaining();
                    Ok(Some(chunk.copy_to_bytes(remaining)))
                }
                Some(Ok(None)) => Err("xHTTP H3 download stream closed".to_owned()),
                Some(Err(err)) => Err(format!("read xHTTP H3 download data: {err:?}")),
                None => Ok(None),
            }
        }
    }
}

pub(crate) async fn read_xhttp_download_data(
    download: &mut XhttpDownloadClient,
) -> Result<Option<Bytes>, String> {
    match download {
        XhttpDownloadClient::H1 { body } => body.read_next().await,
        XhttpDownloadClient::H2 { recv, .. } => match recv.data().await {
            Some(Ok(bytes)) => {
                recv.flow_control()
                    .release_capacity(bytes.len())
                    .map_err(|err| format!("release xHTTP HTTP/2 download capacity: {err}"))?;
                Ok(Some(bytes))
            }
            Some(Err(err)) => Err(format!("read xHTTP HTTP/2 download data: {err}")),
            None => Ok(None),
        },
        XhttpDownloadClient::H3 { recv, .. } => match recv.recv_data().await {
            Ok(Some(mut chunk)) => {
                let remaining = chunk.remaining();
                Ok(Some(chunk.copy_to_bytes(remaining)))
            }
            Ok(None) => Ok(None),
            Err(err) => Err(format!("read xHTTP H3 download data: {err:?}")),
        },
    }
}

pub(crate) async fn close_xhttp_upload_client(upload: XhttpUploadClient) {
    match upload {
        XhttpUploadClient::H1 { .. } => {}
        XhttpUploadClient::H2 {
            connection_task, ..
        } => {
            connection_task.abort();
        }
        XhttpUploadClient::H3 { connection, .. } => {
            connection.close(b"resident xhttp upload done").await;
        }
    }
}

pub(crate) async fn close_xhttp_download_client(download: XhttpDownloadClient) {
    match download {
        XhttpDownloadClient::H1 { mut body } => {
            let _ = body.client.shutdown().await;
        }
        XhttpDownloadClient::H2 {
            connection_task, ..
        } => {
            if let Some(task) = connection_task {
                task.abort();
            }
        }
        XhttpDownloadClient::H3 { connection, .. } => {
            if let Some(connection) = connection {
                connection.close(b"resident xhttp download done").await;
            }
        }
    }
}

pub(crate) fn xhttp_h2_request(
    method: http::Method,
    endpoint: &impl ResidentXhttpEndpointView,
    path_suffix: &str,
    has_body: bool,
) -> Result<http::Request<()>, String> {
    let uri = xhttp_uri(endpoint, path_suffix);
    let referer = xhttp_padding_referer(&xhttp_uri(endpoint, ""));
    let mut builder = http::Request::builder()
        .method(method)
        .uri(uri)
        .header(http::header::USER_AGENT, "Mozilla/5.0")
        .header(http::header::ACCEPT, "*/*")
        .header(http::header::ACCEPT_LANGUAGE, "en-US,en;q=0.9")
        .header(http::header::CACHE_CONTROL, "no-cache")
        .header("pragma", "no-cache")
        .header(http::header::REFERER, referer);
    if has_body {
        builder = builder.header(http::header::CONTENT_TYPE, "application/grpc");
    }
    builder
        .body(())
        .map_err(|err| format!("build xHTTP HTTP/2 request: {err}"))
}

pub(crate) fn xhttp_h1_request_bytes(
    method: http::Method,
    endpoint: &impl ResidentXhttpEndpointView,
    path_suffix: &str,
    body: Option<&Bytes>,
) -> Vec<u8> {
    let path_and_query = xhttp_path_and_query(endpoint, path_suffix);
    let referer = xhttp_padding_referer(&xhttp_uri(endpoint, ""));
    let mut request = format!(
        "{method} {path_and_query} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: Mozilla/5.0\r\n\
         Accept: */*\r\n\
         Accept-Language: en-US,en;q=0.9\r\n\
         Cache-Control: no-cache\r\n\
         Pragma: no-cache\r\n\
         Referer: {referer}\r\n\
         Connection: close\r\n",
        xhttp_authority(endpoint)
    );
    if let Some(body) = body {
        request.push_str("Content-Type: application/grpc\r\n");
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    let mut bytes = request.into_bytes();
    if let Some(body) = body {
        bytes.extend_from_slice(body);
    }
    bytes
}

pub(crate) fn xhttp_uri(endpoint: &impl ResidentXhttpEndpointView, path_suffix: &str) -> String {
    let path_and_query = xhttp_path_and_query(endpoint, path_suffix);
    format!("https://{}{}", xhttp_authority(endpoint), path_and_query)
}

fn xhttp_path_and_query(endpoint: &impl ResidentXhttpEndpointView, path_suffix: &str) -> String {
    let normalized = ir::normalize_xhttp_path_and_query(endpoint.stream_path());
    let mut path = normalized.path;
    path.push_str(path_suffix);
    if !normalized.query.is_empty() {
        path.push('?');
        path.push_str(&normalized.query);
    }
    path
}

pub(crate) fn xhttp_padding_referer(base_uri: &str) -> String {
    const DEFAULT_PADDING_LEN: usize = 128;
    let base_without_query = base_uri.split_once('?').map_or(base_uri, |(base, _)| base);
    format!(
        "{base_without_query}?x_padding={}",
        "X".repeat(DEFAULT_PADDING_LEN)
    )
}

pub(crate) fn xhttp_authority(endpoint: &impl ResidentXhttpEndpointView) -> String {
    if endpoint.stream_host().is_empty() {
        endpoint.server_name().to_owned()
    } else {
        endpoint.stream_host().to_owned()
    }
}

pub(crate) fn xhttp_session_path_suffix(session_id: &str, seq: Option<u64>) -> String {
    match seq {
        Some(seq) => format!("{session_id}/{seq}"),
        None => session_id.to_owned(),
    }
}

pub(crate) fn new_xhttp_session_id() -> String {
    let high = fastrand::u64(..);
    let low = fastrand::u64(..);
    let value = ((high as u128) << 64) | low as u128;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (value >> 96) as u32,
        ((value >> 80) & 0xffff) as u16,
        ((value >> 64) & 0xffff) as u16,
        ((value >> 48) & 0xffff) as u16,
        value & 0xffff_ffff_ffff
    )
}

impl XhttpH1DownloadBody {
    fn new(
        client: AsyncResidentTlsClient,
        headers: Vec<(String, String)>,
        body_prefix: Vec<u8>,
    ) -> Self {
        let chunked = headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value
                    .split(',')
                    .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
        });
        Self {
            client,
            buffer: VecDeque::from(body_prefix),
            state: if chunked {
                XhttpH1BodyState::ChunkSize
            } else {
                XhttpH1BodyState::Identity
            },
        }
    }

    async fn read_next(&mut self) -> Result<Option<Bytes>, String> {
        poll_fn(|cx| self.poll_next(cx)).await
    }

    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, String>> {
        loop {
            match self.state {
                XhttpH1BodyState::ChunkSize => {
                    let Some(line) = self.pop_line()? else {
                        match self.poll_fill(cx) {
                            Poll::Ready(Ok(0)) => {
                                return Poll::Ready(Err(
                                    "xHTTP HTTP/1.1 download closed before chunk size".to_owned(),
                                ));
                            }
                            Poll::Ready(Ok(_)) => continue,
                            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                            Poll::Pending => return Poll::Pending,
                        }
                    };
                    let size_text = line.split_once(';').map_or(line.as_str(), |(size, _)| size);
                    let size = usize::from_str_radix(size_text.trim(), 16)
                        .map_err(|err| format!("parse xHTTP HTTP/1.1 chunk size: {err}"))?;
                    self.state = if size == 0 {
                        XhttpH1BodyState::Trailer
                    } else {
                        XhttpH1BodyState::ChunkData(size)
                    };
                }
                XhttpH1BodyState::ChunkData(remaining) => {
                    if remaining == 0 {
                        self.state = XhttpH1BodyState::ChunkCrlf;
                        continue;
                    }
                    if self.buffer.is_empty() {
                        match self.poll_fill(cx) {
                            Poll::Ready(Ok(0)) => {
                                return Poll::Ready(Err(
                                    "xHTTP HTTP/1.1 download closed inside chunk data".to_owned(),
                                ));
                            }
                            Poll::Ready(Ok(_)) => continue,
                            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    let take = remaining.min(self.buffer.len());
                    let bytes = self.drain_bytes(take);
                    self.state = XhttpH1BodyState::ChunkData(remaining - take);
                    if remaining == take {
                        self.state = XhttpH1BodyState::ChunkCrlf;
                    }
                    return Poll::Ready(Ok(Some(Bytes::from(bytes))));
                }
                XhttpH1BodyState::ChunkCrlf => {
                    if self.buffer.len() < 2 {
                        match self.poll_fill(cx) {
                            Poll::Ready(Ok(0)) => {
                                return Poll::Ready(Err(
                                    "xHTTP HTTP/1.1 download closed before chunk CRLF".to_owned(),
                                ));
                            }
                            Poll::Ready(Ok(_)) => continue,
                            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    let cr = self.buffer.pop_front();
                    let lf = self.buffer.pop_front();
                    if cr != Some(b'\r') || lf != Some(b'\n') {
                        return Poll::Ready(Err(
                            "xHTTP HTTP/1.1 chunk data missing terminating CRLF".to_owned(),
                        ));
                    }
                    self.state = XhttpH1BodyState::ChunkSize;
                }
                XhttpH1BodyState::Trailer => {
                    let Some(line) = self.pop_line()? else {
                        match self.poll_fill(cx) {
                            Poll::Ready(Ok(0)) => {
                                return Poll::Ready(Err(
                                    "xHTTP HTTP/1.1 download closed before chunk trailer"
                                        .to_owned(),
                                ));
                            }
                            Poll::Ready(Ok(_)) => continue,
                            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                            Poll::Pending => return Poll::Pending,
                        }
                    };
                    if line.is_empty() {
                        self.state = XhttpH1BodyState::Done;
                        return Poll::Ready(Ok(None));
                    }
                }
                XhttpH1BodyState::Identity => {
                    if !self.buffer.is_empty() {
                        let bytes = self.drain_bytes(self.buffer.len());
                        return Poll::Ready(Ok(Some(Bytes::from(bytes))));
                    }
                    match self.poll_fill(cx) {
                        Poll::Ready(Ok(0)) => {
                            self.state = XhttpH1BodyState::Done;
                            return Poll::Ready(Ok(None));
                        }
                        Poll::Ready(Ok(_)) => continue,
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                XhttpH1BodyState::Done => return Poll::Ready(Ok(None)),
            }
        }
    }

    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize, String>> {
        let mut scratch = [0_u8; 8192];
        let mut read_buf = ReadBuf::new(&mut scratch);
        match Pin::new(&mut self.client).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let filled = read_buf.filled();
                let len = filled.len();
                self.buffer.extend(filled);
                Poll::Ready(Ok(len))
            }
            Poll::Ready(Err(err)) => {
                Poll::Ready(Err(format!("read xHTTP HTTP/1.1 download body: {err}")))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn pop_line(&mut self) -> Result<Option<String>, String> {
        let Some(index) = self.find_crlf() else {
            return Ok(None);
        };
        let line = self.drain_bytes(index);
        self.buffer.drain(..2);
        String::from_utf8(line)
            .map(Some)
            .map_err(|err| format!("xHTTP HTTP/1.1 chunk line utf8: {err}"))
    }

    fn find_crlf(&self) -> Option<usize> {
        self.buffer
            .iter()
            .zip(self.buffer.iter().skip(1))
            .position(|(left, right)| *left == b'\r' && *right == b'\n')
    }

    fn drain_bytes(&mut self, len: usize) -> Vec<u8> {
        self.buffer.drain(..len).collect()
    }
}

pub(crate) async fn drain_xhttp_h2_response_body(mut body: h2::RecvStream) -> Result<(), String> {
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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_tcp_over_xhttp_packet_up(
    inbound: &mut TokioTcpStream,
    upload: &mut XhttpUploadClient,
    download: &mut XhttpDownloadClient,
    session_id: &str,
    mut seq: u64,
    stop: Arc<AtomicBool>,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut inbound_closed = false;
    let mut response_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut response_stripper = VlessResponseStripper::default();

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            read = inbound.read(&mut inbound_buf), if !inbound_closed => {
                match read {
                    Ok(0) => {
                        inbound_closed = true;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        send_xhttp_packet_up_request(
                            upload,
                            session_id,
                            seq,
                            Bytes::copy_from_slice(&inbound_buf[..read]),
                        )
                        .await?;
                        seq = seq.saturating_add(1);
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read inbound TCP for xHTTP relay: {err}")),
                }
            }
            data = read_xhttp_download_data(download), if !response_closed => {
                match data? {
                    Some(bytes) => {
                        let payload = response_stripper.consume(&bytes)?;
                        if !payload.is_empty() {
                            inbound
                                .write_all(&payload)
                                .await
                                .map_err(|err| format!("write xHTTP response to inbound: {err}"))?;
                            stats.direct_to_client += payload.len();
                            metrics.add_download(payload.len());
                        }
                        last_activity = Instant::now();
                    }
                    None => {
                        response_closed = true;
                        let _ = inbound.shutdown().await;
                        last_activity = Instant::now();
                    }
                }
            }
            _ = time::sleep(RESIDENT_IDLE_SLEEP) => {
                if response_closed || (inbound_closed && response_closed) {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err("resident xHTTP relay idle timeout".to_owned());
                }
            }
        }
    }
    Ok(stats)
}

async fn open_xhttp_h3_connection(
    endpoint: &ResidentXhttpEndpointPlan,
    mark: u32,
) -> Result<XhttpH3Connection, String> {
    let mut quic_endpoint = open_marked_quic_endpoint(mark)?;
    quic_endpoint.set_default_client_config(build_xhttp_h3_client_config(endpoint)?);
    let remote = resolve_xhttp_endpoint_udp_addr_async(endpoint).await?;
    let connection = quic_endpoint
        .connect(remote, &endpoint.server_name)
        .map_err(|err| format!("connect xHTTP H3 QUIC endpoint: {err}"))?
        .await
        .map_err(|err| format!("await xHTTP H3 QUIC connect: {err}"))?;
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let (mut driver, client) = h3::client::new(h3_connection)
        .await
        .map_err(|err| format!("create xHTTP H3 client: {err:?}"))?;
    let driver_task = tokio::spawn(async move {
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
    });
    Ok(XhttpH3Connection {
        endpoint: quic_endpoint,
        connection,
        client,
        driver_task,
    })
}

async fn resolve_xhttp_endpoint_udp_addr_async(
    endpoint: &ResidentXhttpEndpointPlan,
) -> Result<SocketAddr, String> {
    let target = format!("{}:{}", endpoint.server_host, endpoint.server_port);
    tokio::net::lookup_host(target.as_str())
        .await
        .map_err(|err| format!("resolve xHTTP H3 endpoint {target}: {err}"))?
        .next()
        .ok_or_else(|| format!("resolve xHTTP H3 endpoint {target}: no address"))
}

impl XhttpH3Connection {
    async fn close(self, reason: &[u8]) {
        self.connection.close(0_u32.into(), reason);
        self.driver_task.abort();
        self.endpoint.wait_idle().await;
    }
}

pub(crate) async fn open_xhttp_h3_download_stream(
    endpoint: &impl ResidentXhttpEndpointView,
    mut client: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    session_id: &str,
) -> Result<h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>, String> {
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
    let request = xhttp_h3_request(
        http::Method::POST,
        endpoint,
        &xhttp_session_path_suffix(session_id, Some(seq)),
        true,
    )?;
    let mut stream = time::timeout(RESIDENT_CONNECT_TIMEOUT, client.send_request(request))
        .await
        .map_err(|_| "xHTTP H3 packet-up request timeout".to_owned())?
        .map_err(|err| format!("send xHTTP H3 packet-up request: {err:?}"))?;
    time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.send_data(payload))
        .await
        .map_err(|_| "send xHTTP H3 packet-up body timeout".to_owned())?
        .map_err(|err| format!("send xHTTP H3 packet-up body: {err:?}"))?;
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

fn xhttp_h3_request(
    method: http::Method,
    endpoint: &impl ResidentXhttpEndpointView,
    path_suffix: &str,
    has_body: bool,
) -> Result<http::Request<()>, String> {
    let uri = xhttp_uri(endpoint, path_suffix);
    let referer = xhttp_padding_referer(&xhttp_uri(endpoint, ""));
    let mut builder = http::Request::builder()
        .method(method)
        .uri(uri)
        .header(http::header::USER_AGENT, "Mozilla/5.0")
        .header(http::header::ACCEPT, "*/*")
        .header(http::header::ACCEPT_LANGUAGE, "en-US,en;q=0.9")
        .header(http::header::CACHE_CONTROL, "no-cache")
        .header("pragma", "no-cache")
        .header(http::header::REFERER, referer);
    if has_body {
        builder = builder.header(http::header::CONTENT_TYPE, "application/grpc");
    }
    builder
        .body(())
        .map_err(|err| format!("build xHTTP H3 request: {err}"))
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
