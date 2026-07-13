use super::super::h1::open_xhttp_h1_download_stream;
use super::super::h2_transport::{
    open_xhttp_h2_download_stream, open_xhttp_h2_endpoint_sender, open_xhttp_h2_proxy_sender,
};
use super::super::h3_transport::{
    open_xhttp_h3_download_stream, open_xhttp_h3_endpoint_client, open_xhttp_h3_proxy_client,
};
use super::super::request::new_xhttp_session_id_for;
use super::super::xmux::XhttpXmuxClientLease;
use super::super::*;
use super::xhttp_primary_tls_underlay_name;

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
    let upload_http_version = proxy.xhttp_primary_http_version();
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
