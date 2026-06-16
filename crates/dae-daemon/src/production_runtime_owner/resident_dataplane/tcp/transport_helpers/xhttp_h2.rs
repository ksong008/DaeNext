use super::*;
use base64::{Engine as _, engine::general_purpose};
use bytes::Buf;
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::AtomicI32;
use tokio::io::AsyncWrite;

mod xmux;
#[cfg(test)]
use self::xmux::XhttpXmuxUsage;

mod request;

mod h3_transport;
use self::h3_transport::{
    XhttpH3Connection, XhttpH3EndpointClient, open_xhttp_h3_endpoint_client,
    open_xhttp_h3_proxy_client,
};
pub(crate) use self::h3_transport::{
    open_xhttp_h3_download_stream, send_xhttp_h3_packet_up_request,
};

mod h1;
use self::h1::{
    XhttpH1ChunkedWriter, XhttpH1DownloadBody, open_xhttp_h1_download_stream,
    read_xhttp_h1_response_head, send_xhttp_h1_packet_up_request,
};
pub(crate) use self::request::{
    new_xhttp_session_id_for, xhttp_h1_request_bytes, xhttp_h2_request, xhttp_session_path_suffix,
    xhttp_uri,
};
use self::request::{
    write_xhttp_h1_chunk, write_xhttp_h1_chunked_request_head, xhttp_h1_packet_up_request_bytes,
    xhttp_h2_packet_up_request, xhttp_h3_packet_up_request, xhttp_h3_request,
};
use self::xmux::{
    XhttpXmuxClientLease, XhttpXmuxKey, XhttpXmuxRequestHandle, select_xhttp_h2_xmux_client,
    select_xhttp_h3_xmux_client,
};

pub(crate) trait ResidentXhttpEndpointView {
    fn server_name(&self) -> &str;
    fn stream_host(&self) -> &str;
    fn stream_path(&self) -> &str;
    fn xhttp_settings(&self) -> &ResidentXhttpSettingsPlan;
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

    fn xhttp_settings(&self) -> &ResidentXhttpSettingsPlan {
        &self.xhttp_settings
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

    fn xhttp_settings(&self) -> &ResidentXhttpSettingsPlan {
        &self.settings
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

pub(crate) struct XhttpStreamParts {
    pub(crate) session_id: Option<String>,
    pub(crate) upload: XhttpStreamUploadClient,
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
        proxy: Box<ResidentProxyPlan>,
        endpoint: ResidentXhttpEndpointPlan,
        mark: u32,
        mptcp: bool,
        sender: h2::client::SendRequest<Bytes>,
        connection_task: Option<tokio::task::JoinHandle<()>>,
        xmux_lease: Option<XhttpXmuxClientLease>,
        xmux_request: Option<XhttpXmuxRequestHandle>,
    },
    H3 {
        proxy: Box<ResidentProxyPlan>,
        endpoint: ResidentXhttpEndpointPlan,
        mark: u32,
        client: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
        connection: Option<XhttpH3Connection>,
        xmux_lease: Option<XhttpXmuxClientLease>,
        xmux_request: Option<XhttpXmuxRequestHandle>,
    },
}

pub(crate) enum XhttpStreamUploadClient {
    H1 {
        writer: XhttpH1ChunkedWriter,
    },
    H2 {
        send_stream: h2::SendStream<Bytes>,
        upload_response_task: Option<tokio::task::JoinHandle<()>>,
        connection_task: Option<tokio::task::JoinHandle<()>>,
        xmux_lease: Option<XhttpXmuxClientLease>,
    },
    H3 {
        stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
        connection: Option<XhttpH3Connection>,
        xmux_lease: Option<XhttpXmuxClientLease>,
    },
    H3Shared {
        stream:
            Arc<tokio::sync::Mutex<h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>>>,
        connection: Option<XhttpH3Connection>,
        xmux_lease: Option<XhttpXmuxClientLease>,
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
        xmux_lease: Option<XhttpXmuxClientLease>,
    },
    H3 {
        recv: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
        connection: Option<XhttpH3Connection>,
        xmux_lease: Option<XhttpXmuxClientLease>,
    },
    H3Shared {
        stream:
            Arc<tokio::sync::Mutex<h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>>>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xmux_usage(left_requests: i32, unreusable_at: Option<Instant>) -> Arc<XhttpXmuxUsage> {
        Arc::new(XhttpXmuxUsage {
            open_usage: AtomicI32::new(0),
            left_requests: AtomicI32::new(left_requests),
            unreusable_at,
        })
    }

    fn test_xhttp_endpoint(settings: ResidentXhttpSettingsPlan) -> ResidentXhttpEndpointPlan {
        ResidentXhttpEndpointPlan {
            server_host: "server.invalid".to_owned(),
            server_port: 443,
            server_name: "server.invalid".to_owned(),
            alpn: vec!["h2".to_owned()],
            stream_host: "stream.invalid".to_owned(),
            stream_path: "/x?ed=2048".to_owned(),
            mode: ResidentXhttpMode::PacketUp,
            settings,
            xmux: None,
            allow_insecure: false,
            tls_fragment: None,
            reality: None,
        }
    }

    #[test]
    fn xhttp_packet_up_request_applies_header_query_extended_settings() {
        let mut settings = ResidentXhttpSettingsPlan::official_default();
        settings
            .headers
            .insert("X-Test".to_owned(), "alpha".to_owned());
        settings.x_padding_bytes = Some((4, 4));
        settings.x_padding_obfs_mode = true;
        settings.x_padding_key = "pad".to_owned();
        settings.x_padding_placement = ResidentXhttpPaddingPlacement::Query;
        settings.session_id_placement = ResidentXhttpMetaPlacement::Header;
        settings.session_id_key = "X-Sid".to_owned();
        settings.seq_placement = ResidentXhttpMetaPlacement::Query;
        settings.seq_key = "seq".to_owned();
        settings.uplink_data_placement = ResidentXhttpUplinkDataPlacement::Header;
        settings.uplink_data_key = "X-Body".to_owned();
        settings.uplink_chunk_size = Some((64, 64));
        let endpoint = test_xhttp_endpoint(settings);

        let (request, body) =
            xhttp_h2_packet_up_request(&endpoint, "sid-1", 7, Bytes::from_static(b"hello"))
                .unwrap();

        assert!(body.is_none());
        assert_eq!(
            request.uri().path_and_query().unwrap().as_str(),
            "/x/?ed=2048&pad=XXXX&seq=7"
        );
        assert_eq!(request.headers()["X-Test"], "alpha");
        assert_eq!(request.headers()["X-Sid"], "sid-1");
        assert_eq!(request.headers()["X-Body-0"], "aGVsbG8");
        assert!(!request.headers().contains_key(http::header::CONTENT_TYPE));
    }

    #[test]
    fn xhttp_packet_up_request_applies_cookie_extended_settings() {
        let mut settings = ResidentXhttpSettingsPlan::official_default();
        settings.x_padding_bytes = Some((3, 3));
        settings.x_padding_obfs_mode = true;
        settings.x_padding_placement = ResidentXhttpPaddingPlacement::Cookie;
        settings.session_id_placement = ResidentXhttpMetaPlacement::Cookie;
        settings.session_id_key = "x_session".to_owned();
        settings.seq_placement = ResidentXhttpMetaPlacement::Cookie;
        settings.seq_key = "x_seq".to_owned();
        settings.uplink_data_placement = ResidentXhttpUplinkDataPlacement::Cookie;
        settings.uplink_data_key = "x_data".to_owned();
        settings.uplink_chunk_size = Some((64, 64));
        let endpoint = test_xhttp_endpoint(settings);

        let bytes =
            xhttp_h1_packet_up_request_bytes(&endpoint, "sid-2", 5, Bytes::from_static(b"hi"))
                .unwrap();
        let request = String::from_utf8(bytes).unwrap();

        assert!(request.starts_with("POST /x/?ed=2048 HTTP/1.1\r\n"));
        assert!(
            request.contains("cookie: x_data_0=aGk; x_padding=XXX; x_session=sid-2; x_seq=5\r\n")
        );
        assert!(!request.contains("Content-Type: application/grpc\r\n"));
        assert!(!request.contains("Content-Length:"));
    }

    #[test]
    fn xhttp_xmux_packet_up_uses_official_left_request_switch_boundary() {
        let handle = XhttpXmuxRequestHandle {
            usage: xmux_usage(2, None),
        };

        assert!(handle.use_for_packet_up_post());
        assert_eq!(handle.usage.left_requests.load(Ordering::Acquire), 1);
        assert!(!handle.use_for_packet_up_post());
        assert_eq!(handle.usage.left_requests.load(Ordering::Acquire), 0);
    }

    #[test]
    fn xhttp_xmux_packet_up_switches_when_client_is_past_reusable_deadline() {
        let handle = XhttpXmuxRequestHandle {
            usage: xmux_usage(10, Some(Instant::now() - Duration::from_secs(1))),
        };

        assert!(!handle.use_for_packet_up_post());
        assert_eq!(handle.usage.left_requests.load(Ordering::Acquire), 9);
    }

    #[test]
    fn xhttp_xmux_request_handle_does_not_extend_open_usage_lease() {
        let usage = xmux_usage(4, None);
        assert_eq!(usage.open_usage.load(Ordering::Acquire), 0);

        let handle = {
            let lease = XhttpXmuxClientLease::open(Arc::clone(&usage));
            assert_eq!(usage.open_usage.load(Ordering::Acquire), 1);
            let handle = lease.request_handle();
            assert!(handle.use_for_packet_up_post());
            handle
        };

        assert_eq!(usage.open_usage.load(Ordering::Acquire), 0);
        assert_eq!(handle.usage.left_requests.load(Ordering::Acquire), 3);
    }
}

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

struct XhttpH2EndpointSender {
    sender: h2::client::SendRequest<Bytes>,
    connection_task: Option<tokio::task::JoinHandle<()>>,
    xmux_lease: Option<XhttpXmuxClientLease>,
}

async fn open_xhttp_h2_proxy_sender(
    proxy: &ResidentProxyPlan,
    endpoint: &ResidentXhttpEndpointPlan,
    mark: u32,
    mptcp: bool,
) -> Result<XhttpH2EndpointSender, String> {
    let Some(xmux) = &proxy.xhttp_xmux else {
        let client = open_async_vless_tls_client_with_flow(proxy, mark, mptcp).await?;
        let (sender, connection_task) = open_xhttp_h2_sender(client).await?;
        return Ok(XhttpH2EndpointSender {
            sender,
            connection_task: Some(connection_task),
            xmux_lease: None,
        });
    };
    let key = XhttpXmuxKey::primary(proxy, endpoint, xmux, mark, mptcp);
    let selected = select_xhttp_h2_xmux_client(key, xmux.clone(), || async {
        let client = open_async_vless_tls_client_with_flow(proxy, mark, mptcp).await?;
        let (sender, connection_task) = open_xhttp_h2_sender(client).await?;
        Ok(XhttpH2EndpointSender {
            sender,
            connection_task: Some(connection_task),
            xmux_lease: None,
        })
    })
    .await?;
    Ok(XhttpH2EndpointSender {
        sender: selected.sender,
        connection_task: None,
        xmux_lease: Some(selected.lease),
    })
}

async fn open_xhttp_h2_endpoint_sender(
    endpoint: &ResidentXhttpEndpointPlan,
    mark: u32,
    mptcp: bool,
) -> Result<XhttpH2EndpointSender, String> {
    let Some(xmux) = &endpoint.xmux else {
        let client = open_async_xhttp_endpoint_tls_client(endpoint, mark, mptcp).await?;
        let (sender, connection_task) = open_xhttp_h2_sender(client).await?;
        return Ok(XhttpH2EndpointSender {
            sender,
            connection_task: Some(connection_task),
            xmux_lease: None,
        });
    };
    let key = XhttpXmuxKey::endpoint(endpoint, xmux, mark, mptcp);
    let selected = select_xhttp_h2_xmux_client(key, xmux.clone(), || async {
        let client = open_async_xhttp_endpoint_tls_client(endpoint, mark, mptcp).await?;
        let (sender, connection_task) = open_xhttp_h2_sender(client).await?;
        Ok(XhttpH2EndpointSender {
            sender,
            connection_task: Some(connection_task),
            xmux_lease: None,
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

async fn open_xhttp_h2_download_stream(
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

async fn send_xhttp_h2_packet_up_request(
    sender: &mut h2::client::SendRequest<Bytes>,
    endpoint: &impl ResidentXhttpEndpointView,
    session_id: &str,
    seq: u64,
    payload: Bytes,
) -> Result<(), String> {
    let (request, body) = xhttp_h2_packet_up_request(endpoint, session_id, seq, payload)?;
    let end_stream = body.is_none();
    let (response, mut send_stream) = sender
        .send_request(request, end_stream)
        .map_err(|err| format!("send xHTTP HTTP/2 packet-up request headers: {err}"))?;
    if let Some(body) = body {
        send_h2_data_with_context(&mut send_stream, body, true, "xHTTP HTTP/2 packet-up").await?;
    }
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

fn note_xhttp_xmux_request(xmux_lease: Option<&XhttpXmuxClientLease>) {
    if let Some(lease) = xmux_lease {
        let _ = lease.note_request();
    }
}

async fn refresh_xhttp_h2_packet_up_client_if_needed(
    proxy: &ResidentProxyPlan,
    endpoint: &ResidentXhttpEndpointPlan,
    mark: u32,
    mptcp: bool,
    sender: &mut h2::client::SendRequest<Bytes>,
    connection_task: &mut Option<tokio::task::JoinHandle<()>>,
    xmux_request: &mut Option<XhttpXmuxRequestHandle>,
) -> Result<(), String> {
    let Some(request) = xmux_request.as_ref() else {
        return Ok(());
    };
    if request.use_for_packet_up_post() {
        return Ok(());
    }

    if let Some(task) = connection_task.take() {
        task.abort();
    }
    let replacement = open_xhttp_h2_proxy_sender(proxy, endpoint, mark, mptcp).await?;
    *sender = replacement.sender;
    *connection_task = replacement.connection_task;
    *xmux_request = replacement
        .xmux_lease
        .as_ref()
        .map(XhttpXmuxClientLease::request_handle);
    drop(replacement.xmux_lease);
    Ok(())
}

async fn refresh_xhttp_h3_packet_up_client_if_needed(
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
    if let Some(new_connection) = replacement.connection {
        if let Some(old_connection) = connection.replace(new_connection) {
            old_connection
                .close(b"resident xhttp h3 packet-up client replaced")
                .await;
        }
    }
    *xmux_request = replacement
        .xmux_lease
        .as_ref()
        .map(XhttpXmuxClientLease::request_handle);
    drop(replacement.xmux_lease);
    Ok(())
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
            proxy,
            endpoint,
            mark,
            mptcp,
            sender,
            connection_task,
            xmux_request,
            ..
        } => {
            refresh_xhttp_h2_packet_up_client_if_needed(
                proxy,
                endpoint,
                *mark,
                *mptcp,
                sender,
                connection_task,
                xmux_request,
            )
            .await?;
            send_xhttp_h2_packet_up_request(sender, endpoint, session_id, seq, payload).await
        }
        XhttpUploadClient::H3 {
            proxy,
            endpoint,
            mark,
            client,
            connection,
            xmux_request,
            ..
        } => {
            refresh_xhttp_h3_packet_up_client_if_needed(
                proxy,
                endpoint,
                *mark,
                client,
                connection,
                xmux_request,
            )
            .await?;
            send_xhttp_h3_packet_up_request(client, endpoint, session_id, seq, payload).await
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
        XhttpDownloadClient::H3Shared { stream } => {
            match poll_xhttp_h3_shared_once(stream).await? {
                Some(Some(bytes)) => Ok(Some(bytes)),
                Some(None) => Err("xHTTP H3 stream-one download stream closed".to_owned()),
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
        XhttpDownloadClient::H3Shared { stream } => loop {
            match poll_xhttp_h3_shared_once(stream).await? {
                Some(Some(bytes)) => return Ok(Some(bytes)),
                Some(None) => return Ok(None),
                None => time::sleep(RESIDENT_IDLE_SLEEP).await,
            }
        },
    }
}

async fn poll_xhttp_h3_shared_once(
    stream: &Arc<tokio::sync::Mutex<h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>>>,
) -> Result<Option<Option<Bytes>>, String> {
    let Ok(mut stream) = stream.try_lock() else {
        return Ok(None);
    };
    poll_fn(|cx| match stream.poll_recv_data(cx) {
        Poll::Ready(Ok(Some(mut chunk))) => {
            let remaining = chunk.remaining();
            Poll::Ready(Ok(Some(Some(chunk.copy_to_bytes(remaining)))))
        }
        Poll::Ready(Ok(None)) => Poll::Ready(Ok(Some(None))),
        Poll::Ready(Err(err)) => {
            Poll::Ready(Err(format!("read xHTTP H3 stream-one data: {err:?}")))
        }
        Poll::Pending => Poll::Ready(Ok(None)),
    })
    .await
}

pub(crate) async fn close_xhttp_upload_client(upload: XhttpUploadClient) {
    match upload {
        XhttpUploadClient::H1 { .. } => {}
        XhttpUploadClient::H2 {
            connection_task,
            xmux_lease,
            ..
        } => {
            if let Some(task) = connection_task {
                task.abort();
            }
            drop(xmux_lease);
        }
        XhttpUploadClient::H3 {
            connection,
            xmux_lease,
            ..
        } => {
            if let Some(connection) = connection {
                connection.close(b"resident xhttp upload done").await;
            }
            drop(xmux_lease);
        }
    }
}

pub(crate) async fn close_xhttp_download_client(download: XhttpDownloadClient) {
    match download {
        XhttpDownloadClient::H1 { mut body } => {
            body.shutdown().await;
        }
        XhttpDownloadClient::H2 {
            connection_task,
            xmux_lease,
            ..
        } => {
            if let Some(task) = connection_task {
                task.abort();
            }
            drop(xmux_lease);
        }
        XhttpDownloadClient::H3 {
            connection,
            xmux_lease,
            ..
        } => {
            if let Some(connection) = connection {
                connection.close(b"resident xhttp download done").await;
            }
            drop(xmux_lease);
        }
        XhttpDownloadClient::H3Shared { .. } => {}
    }
}

pub(crate) async fn send_xhttp_stream_data(
    upload: &mut XhttpStreamUploadClient,
    payload: Bytes,
    end_stream: bool,
) -> Result<(), String> {
    match upload {
        XhttpStreamUploadClient::H1 { writer } => writer.write_chunk(payload, end_stream).await,
        XhttpStreamUploadClient::H2 { send_stream, .. } => {
            send_h2_data_with_context(
                send_stream,
                payload,
                end_stream,
                "xHTTP HTTP/2 stream upload",
            )
            .await
        }
        XhttpStreamUploadClient::H3 { stream, .. } => {
            if !payload.is_empty() {
                time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.send_data(payload))
                    .await
                    .map_err(|_| "send xHTTP H3 stream body timeout".to_owned())?
                    .map_err(|err| format!("send xHTTP H3 stream body: {err:?}"))?;
            }
            if end_stream {
                time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.finish())
                    .await
                    .map_err(|_| "finish xHTTP H3 stream body timeout".to_owned())?
                    .map_err(|err| format!("finish xHTTP H3 stream body: {err:?}"))?;
            }
            Ok(())
        }
        XhttpStreamUploadClient::H3Shared { stream, .. } => {
            let mut stream = stream.lock().await;
            if !payload.is_empty() {
                time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.send_data(payload))
                    .await
                    .map_err(|_| "send xHTTP H3 stream-one body timeout".to_owned())?
                    .map_err(|err| format!("send xHTTP H3 stream-one body: {err:?}"))?;
            }
            if end_stream {
                time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.finish())
                    .await
                    .map_err(|_| "finish xHTTP H3 stream-one body timeout".to_owned())?
                    .map_err(|err| format!("finish xHTTP H3 stream-one body: {err:?}"))?;
            }
            Ok(())
        }
    }
}

pub(crate) async fn close_xhttp_stream_upload_client(mut upload: XhttpStreamUploadClient) {
    match &mut upload {
        XhttpStreamUploadClient::H1 { writer } => {
            let _ = writer.write_chunk(Bytes::new(), true).await;
            writer.shutdown().await;
        }
        XhttpStreamUploadClient::H2 {
            upload_response_task,
            connection_task,
            xmux_lease,
            ..
        } => {
            if let Some(task) = upload_response_task.take() {
                task.abort();
            }
            if let Some(task) = connection_task.take() {
                task.abort();
            }
            drop(xmux_lease.take());
        }
        XhttpStreamUploadClient::H3 {
            connection,
            xmux_lease,
            ..
        } => {
            if let Some(connection) = connection.take() {
                connection.close(b"resident xhttp stream upload done").await;
            }
            drop(xmux_lease.take());
        }
        XhttpStreamUploadClient::H3Shared {
            connection,
            xmux_lease,
            ..
        } => {
            if let Some(connection) = connection.take() {
                connection.close(b"resident xhttp stream-one done").await;
            }
            drop(xmux_lease.take());
        }
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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_tcp_over_xhttp_stream(
    inbound: &mut TokioTcpStream,
    upload: &mut XhttpStreamUploadClient,
    download: &mut XhttpDownloadClient,
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
                        send_xhttp_stream_data(upload, Bytes::new(), true).await?;
                        inbound_closed = true;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        send_xhttp_stream_data(
                            upload,
                            Bytes::copy_from_slice(&inbound_buf[..read]),
                            false,
                        )
                        .await?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        send_xhttp_stream_data(upload, Bytes::new(), true).await?;
                        inbound_closed = true;
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read inbound TCP for xHTTP stream relay: {err}")),
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
                                .map_err(|err| format!("write xHTTP stream response to inbound: {err}"))?;
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
                    return Err("resident xHTTP stream relay idle timeout".to_owned());
                }
            }
        }
    }
    Ok(stats)
}
