use super::h1::{
    XhttpH1ChunkedWriter, XhttpH1DownloadBody, open_xhttp_h1_download_stream,
    read_xhttp_h1_response_head,
};
use super::h2_transport::{
    drain_xhttp_h2_response_body, open_xhttp_h2_download_stream, open_xhttp_h2_endpoint_sender,
    open_xhttp_h2_proxy_sender,
};
use super::h3_transport::{
    open_xhttp_h3_download_stream, open_xhttp_h3_endpoint_client, open_xhttp_h3_proxy_client,
};
use super::request::{
    new_xhttp_session_id_for, write_xhttp_h1_chunk, write_xhttp_h1_chunked_request_head,
    xhttp_h2_request, xhttp_h3_request, xhttp_session_path_suffix,
};
use super::xmux::{XhttpXmuxClientLease, note_xhttp_xmux_request};
use super::*;

pub(crate) async fn open_xhttp_packet_up_parts(
    proxy: &ResidentProxyPlan,
    mark: u32,
    mptcp: bool,
) -> Result<XhttpPacketUpParts, String> {
    let session_id = new_xhttp_session_id_for(proxy.xhttp_settings());
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
                download_sender.xmux_lease.as_ref(),
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
                    connection_task: download_sender.connection_task,
                    xmux_lease: download_sender.xmux_lease,
                },
                upload_underlay: xhttp_primary_tls_underlay_name(proxy),
                upload_http_version,
                download_separate,
            })
        }
        (ResidentXhttpHttpVersion::H1, ResidentXhttpHttpVersion::H3) => {
            let download_client = open_xhttp_h3_endpoint_client(&download_endpoint, mark).await?;
            let recv = open_xhttp_h3_download_stream(
                &download_endpoint,
                download_client.client.clone(),
                &session_id,
                download_client.xmux_lease.as_ref(),
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
                    connection: download_client.connection,
                    xmux_lease: download_client.xmux_lease,
                },
                upload_underlay: xhttp_primary_tls_underlay_name(proxy),
                upload_http_version,
                download_separate,
            })
        }
        (ResidentXhttpHttpVersion::H2, ResidentXhttpHttpVersion::H1) => {
            let upload_underlay = xhttp_primary_tls_underlay_name(proxy);
            let upload_sender =
                open_xhttp_h2_proxy_sender(proxy, &upload_endpoint, mark, mptcp).await?;
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
                    proxy: Box::new(proxy.clone()),
                    endpoint: upload_endpoint,
                    mark,
                    mptcp,
                    sender: upload_sender.sender,
                    connection_task: upload_sender.connection_task,
                    xmux_request: upload_sender
                        .xmux_lease
                        .as_ref()
                        .map(XhttpXmuxClientLease::request_handle),
                    xmux_lease: upload_sender.xmux_lease,
                },
                download: XhttpDownloadClient::H1 { body: recv },
                upload_underlay,
                upload_http_version,
                download_separate,
            })
        }
        (ResidentXhttpHttpVersion::H2, ResidentXhttpHttpVersion::H2) if !download_separate => {
            let upload_underlay = xhttp_primary_tls_underlay_name(proxy);
            let mut upload_sender =
                open_xhttp_h2_proxy_sender(proxy, &upload_endpoint, mark, mptcp).await?;
            let recv = open_xhttp_h2_download_stream(
                &mut upload_sender.sender,
                &upload_endpoint,
                &session_id,
                upload_sender.xmux_lease.as_ref(),
            )
            .await?;
            Ok(XhttpPacketUpParts {
                session_id,
                upload: XhttpUploadClient::H2 {
                    proxy: Box::new(proxy.clone()),
                    endpoint: upload_endpoint,
                    mark,
                    mptcp,
                    sender: upload_sender.sender,
                    connection_task: upload_sender.connection_task,
                    xmux_request: upload_sender
                        .xmux_lease
                        .as_ref()
                        .map(XhttpXmuxClientLease::request_handle),
                    xmux_lease: upload_sender.xmux_lease,
                },
                download: XhttpDownloadClient::H2 {
                    recv,
                    _keepalive_sender: None,
                    connection_task: None,
                    xmux_lease: None,
                },
                upload_underlay,
                upload_http_version,
                download_separate,
            })
        }
        (ResidentXhttpHttpVersion::H2, ResidentXhttpHttpVersion::H2) => {
            let upload_underlay = xhttp_primary_tls_underlay_name(proxy);
            let upload_sender =
                open_xhttp_h2_proxy_sender(proxy, &upload_endpoint, mark, mptcp).await?;
            let mut download_sender =
                open_xhttp_h2_endpoint_sender(&download_endpoint, mark, mptcp).await?;
            let recv = open_xhttp_h2_download_stream(
                &mut download_sender.sender,
                &download_endpoint,
                &session_id,
                download_sender.xmux_lease.as_ref(),
            )
            .await?;
            Ok(XhttpPacketUpParts {
                session_id,
                upload: XhttpUploadClient::H2 {
                    proxy: Box::new(proxy.clone()),
                    endpoint: upload_endpoint,
                    mark,
                    mptcp,
                    sender: upload_sender.sender,
                    connection_task: upload_sender.connection_task,
                    xmux_request: upload_sender
                        .xmux_lease
                        .as_ref()
                        .map(XhttpXmuxClientLease::request_handle),
                    xmux_lease: upload_sender.xmux_lease,
                },
                download: XhttpDownloadClient::H2 {
                    recv,
                    _keepalive_sender: Some(download_sender.sender),
                    connection_task: download_sender.connection_task,
                    xmux_lease: download_sender.xmux_lease,
                },
                upload_underlay,
                upload_http_version,
                download_separate,
            })
        }
        (ResidentXhttpHttpVersion::H2, ResidentXhttpHttpVersion::H3) => {
            let upload_underlay = xhttp_primary_tls_underlay_name(proxy);
            let upload_sender =
                open_xhttp_h2_proxy_sender(proxy, &upload_endpoint, mark, mptcp).await?;
            let download_client = open_xhttp_h3_endpoint_client(&download_endpoint, mark).await?;
            let recv = open_xhttp_h3_download_stream(
                &download_endpoint,
                download_client.client.clone(),
                &session_id,
                download_client.xmux_lease.as_ref(),
            )
            .await?;
            Ok(XhttpPacketUpParts {
                session_id,
                upload: XhttpUploadClient::H2 {
                    proxy: Box::new(proxy.clone()),
                    endpoint: upload_endpoint,
                    mark,
                    mptcp,
                    sender: upload_sender.sender,
                    connection_task: upload_sender.connection_task,
                    xmux_request: upload_sender
                        .xmux_lease
                        .as_ref()
                        .map(XhttpXmuxClientLease::request_handle),
                    xmux_lease: upload_sender.xmux_lease,
                },
                download: XhttpDownloadClient::H3 {
                    recv,
                    connection: download_client.connection,
                    xmux_lease: download_client.xmux_lease,
                },
                upload_underlay,
                upload_http_version,
                download_separate,
            })
        }
        (ResidentXhttpHttpVersion::H3, ResidentXhttpHttpVersion::H1) => {
            let upload_underlay = "quinn-h3";
            let upload_client = open_xhttp_h3_proxy_client(proxy, &upload_endpoint, mark).await?;
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
                    proxy: Box::new(proxy.clone()),
                    endpoint: upload_endpoint,
                    mark,
                    client: upload_client.client,
                    connection: upload_client.connection,
                    xmux_request: upload_client
                        .xmux_lease
                        .as_ref()
                        .map(XhttpXmuxClientLease::request_handle),
                    xmux_lease: upload_client.xmux_lease,
                },
                download: XhttpDownloadClient::H1 { body: recv },
                upload_underlay,
                upload_http_version,
                download_separate,
            })
        }
        (ResidentXhttpHttpVersion::H3, ResidentXhttpHttpVersion::H2) => {
            let upload_underlay = "quinn-h3";
            let upload_client = open_xhttp_h3_proxy_client(proxy, &upload_endpoint, mark).await?;
            let mut download_sender =
                open_xhttp_h2_endpoint_sender(&download_endpoint, mark, mptcp).await?;
            let recv = open_xhttp_h2_download_stream(
                &mut download_sender.sender,
                &download_endpoint,
                &session_id,
                download_sender.xmux_lease.as_ref(),
            )
            .await?;
            Ok(XhttpPacketUpParts {
                session_id,
                upload: XhttpUploadClient::H3 {
                    proxy: Box::new(proxy.clone()),
                    endpoint: upload_endpoint,
                    mark,
                    client: upload_client.client,
                    connection: upload_client.connection,
                    xmux_request: upload_client
                        .xmux_lease
                        .as_ref()
                        .map(XhttpXmuxClientLease::request_handle),
                    xmux_lease: upload_client.xmux_lease,
                },
                download: XhttpDownloadClient::H2 {
                    recv,
                    _keepalive_sender: Some(download_sender.sender),
                    connection_task: download_sender.connection_task,
                    xmux_lease: download_sender.xmux_lease,
                },
                upload_underlay,
                upload_http_version,
                download_separate,
            })
        }
        (ResidentXhttpHttpVersion::H3, ResidentXhttpHttpVersion::H3) if !download_separate => {
            let upload_underlay = "quinn-h3";
            let upload_client = open_xhttp_h3_proxy_client(proxy, &upload_endpoint, mark).await?;
            let recv = open_xhttp_h3_download_stream(
                &upload_endpoint,
                upload_client.client.clone(),
                &session_id,
                upload_client.xmux_lease.as_ref(),
            )
            .await?;
            Ok(XhttpPacketUpParts {
                session_id,
                upload: XhttpUploadClient::H3 {
                    proxy: Box::new(proxy.clone()),
                    endpoint: upload_endpoint,
                    mark,
                    client: upload_client.client,
                    connection: upload_client.connection,
                    xmux_request: upload_client
                        .xmux_lease
                        .as_ref()
                        .map(XhttpXmuxClientLease::request_handle),
                    xmux_lease: upload_client.xmux_lease,
                },
                download: XhttpDownloadClient::H3 {
                    recv,
                    connection: None,
                    xmux_lease: None,
                },
                upload_underlay,
                upload_http_version,
                download_separate,
            })
        }
        (ResidentXhttpHttpVersion::H3, ResidentXhttpHttpVersion::H3) => {
            let upload_underlay = "quinn-h3";
            let upload_client = open_xhttp_h3_proxy_client(proxy, &upload_endpoint, mark).await?;
            let download_client = open_xhttp_h3_endpoint_client(&download_endpoint, mark).await?;
            let recv = open_xhttp_h3_download_stream(
                &download_endpoint,
                download_client.client.clone(),
                &session_id,
                download_client.xmux_lease.as_ref(),
            )
            .await?;
            Ok(XhttpPacketUpParts {
                session_id,
                upload: XhttpUploadClient::H3 {
                    proxy: Box::new(proxy.clone()),
                    endpoint: upload_endpoint,
                    mark,
                    client: upload_client.client,
                    connection: upload_client.connection,
                    xmux_request: upload_client
                        .xmux_lease
                        .as_ref()
                        .map(XhttpXmuxClientLease::request_handle),
                    xmux_lease: upload_client.xmux_lease,
                },
                download: XhttpDownloadClient::H3 {
                    recv,
                    connection: download_client.connection,
                    xmux_lease: download_client.xmux_lease,
                },
                upload_underlay,
                upload_http_version,
                download_separate,
            })
        }
    }
}

pub(crate) async fn open_xhttp_stream_parts(
    proxy: &ResidentProxyPlan,
    mark: u32,
    mptcp: bool,
    initial_payload: Bytes,
) -> Result<XhttpStreamParts, String> {
    match proxy.xhttp_mode {
        ResidentXhttpMode::PacketUp => {
            Err("xHTTP stream parts cannot be opened for packet-up mode".to_owned())
        }
        ResidentXhttpMode::StreamOne => {
            open_xhttp_stream_one_parts(proxy, mark, mptcp, initial_payload).await
        }
        ResidentXhttpMode::StreamUp => {
            open_xhttp_stream_up_parts(proxy, mark, mptcp, initial_payload).await
        }
    }
}

async fn open_xhttp_stream_one_parts(
    proxy: &ResidentProxyPlan,
    mark: u32,
    mptcp: bool,
    initial_payload: Bytes,
) -> Result<XhttpStreamParts, String> {
    let endpoint = ResidentXhttpEndpointPlan::from_proxy(proxy);
    let upload_http_version = if proxy.tls == "reality" {
        ResidentXhttpHttpVersion::H2
    } else {
        endpoint.http_version()
    };
    match upload_http_version {
        ResidentXhttpHttpVersion::H1 => {
            let mut client = open_async_vless_tls_client_with_flow(proxy, mark, mptcp).await?;
            let upload_underlay = async_tls_underlay_name(&client);
            write_xhttp_h1_chunked_request_head(&mut client, &endpoint, "", "stream-one").await?;
            write_xhttp_h1_chunk(&mut client, &initial_payload, false, "stream-one").await?;
            let (mut reader, writer) = tokio::io::split(client);
            let response = read_xhttp_h1_response_head(&mut reader, "stream-one").await?;
            if !(200..300).contains(&response.status) {
                return Err(format!(
                    "xHTTP HTTP/1.1 stream-one response status {}",
                    response.status
                ));
            }
            Ok(XhttpStreamParts {
                session_id: None,
                upload: XhttpStreamUploadClient::H1 {
                    writer: XhttpH1ChunkedWriter::from_write_half(writer),
                },
                download: XhttpDownloadClient::H1 {
                    body: XhttpH1DownloadBody::new_with_read_half(
                        reader,
                        response.headers,
                        response.body_prefix,
                    ),
                },
                upload_underlay,
                upload_http_version,
                download_separate: false,
            })
        }
        ResidentXhttpHttpVersion::H2 => {
            let upload_underlay = xhttp_primary_tls_underlay_name(proxy);
            let mut endpoint_sender =
                open_xhttp_h2_proxy_sender(proxy, &endpoint, mark, mptcp).await?;
            note_xhttp_xmux_request(endpoint_sender.xmux_lease.as_ref());
            let request = xhttp_h2_request(http::Method::POST, &endpoint, "", true)?;
            let (response, mut send_stream) = endpoint_sender
                .sender
                .send_request(request, false)
                .map_err(|err| {
                format!("send xHTTP HTTP/2 stream-one request headers: {err}")
            })?;
            send_h2_data_with_context(
                &mut send_stream,
                initial_payload,
                false,
                "xHTTP HTTP/2 stream-one",
            )
            .await?;
            let response = time::timeout(RESIDENT_CONNECT_TIMEOUT, response)
                .await
                .map_err(|_| "xHTTP HTTP/2 stream-one response headers timeout".to_owned())?
                .map_err(|err| format!("read xHTTP HTTP/2 stream-one response headers: {err}"))?;
            if !response.status().is_success() {
                return Err(format!(
                    "xHTTP HTTP/2 stream-one response status {}",
                    response.status()
                ));
            }
            Ok(XhttpStreamParts {
                session_id: None,
                upload: XhttpStreamUploadClient::H2 {
                    send_stream,
                    upload_response_task: None,
                    connection_task: None,
                    xmux_lease: endpoint_sender.xmux_lease,
                },
                download: XhttpDownloadClient::H2 {
                    recv: response.into_body(),
                    _keepalive_sender: Some(endpoint_sender.sender),
                    connection_task: endpoint_sender.connection_task,
                    xmux_lease: None,
                },
                upload_underlay,
                upload_http_version,
                download_separate: false,
            })
        }
        ResidentXhttpHttpVersion::H3 => {
            let mut endpoint_client = open_xhttp_h3_proxy_client(proxy, &endpoint, mark).await?;
            note_xhttp_xmux_request(endpoint_client.xmux_lease.as_ref());
            let request = xhttp_h3_request(http::Method::POST, &endpoint, "", true)?;
            let mut stream = time::timeout(
                RESIDENT_CONNECT_TIMEOUT,
                endpoint_client.client.send_request(request),
            )
            .await
            .map_err(|_| "xHTTP H3 stream-one request timeout".to_owned())?
            .map_err(|err| format!("send xHTTP H3 stream-one request: {err:?}"))?;
            time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.send_data(initial_payload))
                .await
                .map_err(|_| "send xHTTP H3 stream-one body timeout".to_owned())?
                .map_err(|err| format!("send xHTTP H3 stream-one body: {err:?}"))?;
            let response = time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.recv_response())
                .await
                .map_err(|_| "xHTTP H3 stream-one response timeout".to_owned())?
                .map_err(|err| format!("recv xHTTP H3 stream-one response: {err:?}"))?;
            if !response.status().is_success() {
                return Err(format!(
                    "xHTTP H3 stream-one response status {}",
                    response.status()
                ));
            }
            let shared = Arc::new(tokio::sync::Mutex::new(stream));
            Ok(XhttpStreamParts {
                session_id: None,
                upload: XhttpStreamUploadClient::H3Shared {
                    stream: Arc::clone(&shared),
                    connection: endpoint_client.connection,
                    xmux_lease: endpoint_client.xmux_lease,
                },
                download: XhttpDownloadClient::H3Shared { stream: shared },
                upload_underlay: "quinn-h3",
                upload_http_version,
                download_separate: false,
            })
        }
    }
}

async fn open_xhttp_stream_up_parts(
    proxy: &ResidentProxyPlan,
    mark: u32,
    mptcp: bool,
    initial_payload: Bytes,
) -> Result<XhttpStreamParts, String> {
    let session_id = new_xhttp_session_id_for(proxy.xhttp_settings());
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
    if !download_separate
        && upload_http_version == ResidentXhttpHttpVersion::H2
        && download_endpoint.http_version() == ResidentXhttpHttpVersion::H2
    {
        let upload_underlay = xhttp_primary_tls_underlay_name(proxy);
        let mut endpoint_sender =
            open_xhttp_h2_proxy_sender(proxy, &upload_endpoint, mark, mptcp).await?;
        let recv = open_xhttp_h2_download_stream(
            &mut endpoint_sender.sender,
            &upload_endpoint,
            &session_id,
            endpoint_sender.xmux_lease.as_ref(),
        )
        .await?;
        let mut upload_sender = endpoint_sender.sender.clone();
        note_xhttp_xmux_request(endpoint_sender.xmux_lease.as_ref());
        let request = xhttp_h2_request(
            http::Method::POST,
            &upload_endpoint,
            &xhttp_session_path_suffix(&session_id, None),
            true,
        )?;
        let (response, mut send_stream) = upload_sender
            .send_request(request, false)
            .map_err(|err| format!("send xHTTP HTTP/2 stream-up request headers: {err}"))?;
        send_h2_data_with_context(
            &mut send_stream,
            initial_payload,
            false,
            "xHTTP HTTP/2 stream-up",
        )
        .await?;
        let upload_response_task = tokio::spawn(async move {
            if let Ok(Ok(response)) = time::timeout(RESIDENT_CONNECT_TIMEOUT, response).await {
                let _ = drain_xhttp_h2_response_body(response.into_body()).await;
            }
        });
        return Ok(XhttpStreamParts {
            session_id: Some(session_id),
            upload: XhttpStreamUploadClient::H2 {
                send_stream,
                upload_response_task: Some(upload_response_task),
                connection_task: None,
                xmux_lease: endpoint_sender.xmux_lease,
            },
            download: XhttpDownloadClient::H2 {
                recv,
                _keepalive_sender: Some(endpoint_sender.sender),
                connection_task: endpoint_sender.connection_task,
                xmux_lease: None,
            },
            upload_underlay,
            upload_http_version,
            download_separate,
        });
    }
    let download = open_xhttp_download_client(
        proxy,
        &download_endpoint,
        mark,
        mptcp,
        &session_id,
        download_separate,
    )
    .await?;
    let (upload, upload_underlay) = open_xhttp_stream_upload_client(
        proxy,
        &upload_endpoint,
        upload_http_version,
        mark,
        mptcp,
        &session_id,
        initial_payload,
    )
    .await?;
    Ok(XhttpStreamParts {
        session_id: Some(session_id),
        upload,
        download,
        upload_underlay,
        upload_http_version,
        download_separate,
    })
}

async fn open_xhttp_download_client(
    proxy: &ResidentProxyPlan,
    endpoint: &ResidentXhttpEndpointPlan,
    mark: u32,
    mptcp: bool,
    session_id: &str,
    separate_endpoint: bool,
) -> Result<XhttpDownloadClient, String> {
    match endpoint.http_version() {
        ResidentXhttpHttpVersion::H1 => {
            let body = open_xhttp_h1_download_stream(
                proxy,
                endpoint,
                mark,
                mptcp,
                session_id,
                separate_endpoint,
            )
            .await?;
            Ok(XhttpDownloadClient::H1 { body })
        }
        ResidentXhttpHttpVersion::H2 => {
            let mut endpoint_sender = if separate_endpoint {
                open_xhttp_h2_endpoint_sender(endpoint, mark, mptcp).await?
            } else {
                open_xhttp_h2_proxy_sender(proxy, endpoint, mark, mptcp).await?
            };
            let recv = open_xhttp_h2_download_stream(
                &mut endpoint_sender.sender,
                endpoint,
                session_id,
                endpoint_sender.xmux_lease.as_ref(),
            )
            .await?;
            Ok(XhttpDownloadClient::H2 {
                recv,
                _keepalive_sender: Some(endpoint_sender.sender),
                connection_task: endpoint_sender.connection_task,
                xmux_lease: endpoint_sender.xmux_lease,
            })
        }
        ResidentXhttpHttpVersion::H3 => {
            let endpoint_client = if separate_endpoint {
                open_xhttp_h3_endpoint_client(endpoint, mark).await?
            } else {
                open_xhttp_h3_proxy_client(proxy, endpoint, mark).await?
            };
            let recv = open_xhttp_h3_download_stream(
                endpoint,
                endpoint_client.client.clone(),
                session_id,
                endpoint_client.xmux_lease.as_ref(),
            )
            .await?;
            Ok(XhttpDownloadClient::H3 {
                recv,
                connection: endpoint_client.connection,
                xmux_lease: endpoint_client.xmux_lease,
            })
        }
    }
}

async fn open_xhttp_stream_upload_client(
    proxy: &ResidentProxyPlan,
    endpoint: &ResidentXhttpEndpointPlan,
    upload_http_version: ResidentXhttpHttpVersion,
    mark: u32,
    mptcp: bool,
    session_id: &str,
    initial_payload: Bytes,
) -> Result<(XhttpStreamUploadClient, &'static str), String> {
    match upload_http_version {
        ResidentXhttpHttpVersion::H1 => {
            let mut client = open_async_vless_tls_client_with_flow(proxy, mark, mptcp).await?;
            let upload_underlay = async_tls_underlay_name(&client);
            write_xhttp_h1_chunked_request_head(&mut client, endpoint, session_id, "stream-up")
                .await?;
            write_xhttp_h1_chunk(&mut client, &initial_payload, false, "stream-up").await?;
            Ok((
                XhttpStreamUploadClient::H1 {
                    writer: XhttpH1ChunkedWriter::from_client(client),
                },
                upload_underlay,
            ))
        }
        ResidentXhttpHttpVersion::H2 => {
            let upload_underlay = xhttp_primary_tls_underlay_name(proxy);
            let mut endpoint_sender =
                open_xhttp_h2_proxy_sender(proxy, endpoint, mark, mptcp).await?;
            note_xhttp_xmux_request(endpoint_sender.xmux_lease.as_ref());
            let request = xhttp_h2_request(
                http::Method::POST,
                endpoint,
                &xhttp_session_path_suffix(session_id, None),
                true,
            )?;
            let (response, mut send_stream) =
                endpoint_sender
                    .sender
                    .send_request(request, false)
                    .map_err(|err| format!("send xHTTP HTTP/2 stream-up request headers: {err}"))?;
            send_h2_data_with_context(
                &mut send_stream,
                initial_payload,
                false,
                "xHTTP HTTP/2 stream-up",
            )
            .await?;
            let upload_response_task = tokio::spawn(async move {
                if let Ok(Ok(response)) = time::timeout(RESIDENT_CONNECT_TIMEOUT, response).await {
                    let _ = drain_xhttp_h2_response_body(response.into_body()).await;
                }
            });
            Ok((
                XhttpStreamUploadClient::H2 {
                    send_stream,
                    upload_response_task: Some(upload_response_task),
                    connection_task: endpoint_sender.connection_task,
                    xmux_lease: endpoint_sender.xmux_lease,
                },
                upload_underlay,
            ))
        }
        ResidentXhttpHttpVersion::H3 => {
            let mut endpoint_client = open_xhttp_h3_proxy_client(proxy, endpoint, mark).await?;
            note_xhttp_xmux_request(endpoint_client.xmux_lease.as_ref());
            let request = xhttp_h3_request(
                http::Method::POST,
                endpoint,
                &xhttp_session_path_suffix(session_id, None),
                true,
            )?;
            let mut stream = time::timeout(
                RESIDENT_CONNECT_TIMEOUT,
                endpoint_client.client.send_request(request),
            )
            .await
            .map_err(|_| "xHTTP H3 stream-up request timeout".to_owned())?
            .map_err(|err| format!("send xHTTP H3 stream-up request: {err:?}"))?;
            time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.send_data(initial_payload))
                .await
                .map_err(|_| "send xHTTP H3 stream-up body timeout".to_owned())?
                .map_err(|err| format!("send xHTTP H3 stream-up body: {err:?}"))?;
            Ok((
                XhttpStreamUploadClient::H3 {
                    stream,
                    connection: endpoint_client.connection,
                    xmux_lease: endpoint_client.xmux_lease,
                },
                "quinn-h3",
            ))
        }
    }
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
