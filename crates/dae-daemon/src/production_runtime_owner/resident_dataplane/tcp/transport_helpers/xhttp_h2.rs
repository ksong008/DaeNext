use super::*;
use base64::{Engine as _, engine::general_purpose};
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::AtomicI32;
use tokio::io::AsyncWrite;

mod xmux;
#[cfg(test)]
use self::xmux::XhttpXmuxUsage;

mod request;

mod h3_transport;
use self::h3_transport::{XhttpH3Connection, XhttpH3EndpointClient};

mod h1;
use self::h1::{XhttpH1ChunkedWriter, XhttpH1DownloadBody};

mod h2_transport;
use self::h2_transport::XhttpH2EndpointSender;

mod client_io;
pub(crate) use self::client_io::{
    close_xhttp_download_client, close_xhttp_stream_upload_client, close_xhttp_upload_client,
    poll_xhttp_download_data, send_xhttp_packet_up_request, send_xhttp_stream_data,
};

mod relay;
pub(crate) use self::relay::{relay_tcp_over_xhttp_packet_up, relay_tcp_over_xhttp_stream};

mod parts;
pub(crate) use self::parts::{open_xhttp_packet_up_parts, open_xhttp_stream_parts};
use self::request::{
    xhttp_h1_packet_up_request_bytes, xhttp_h2_packet_up_request, xhttp_h3_packet_up_request,
    xhttp_h3_request,
};
pub(crate) use self::request::{
    xhttp_h1_request_bytes, xhttp_h2_request, xhttp_session_path_suffix, xhttp_uri,
};
use self::xmux::{XhttpXmuxClientLease, XhttpXmuxRequestHandle};

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
