// xHTTP stream/client enums keep live H1/H2/H3 transport ownership inline.
#![allow(clippy::large_enum_variant)]

use super::*;

mod resolved_endpoint;
use self::resolved_endpoint::XhttpResolvedEndpoint;

mod xmux;

mod request;

mod h3_boring_tls;

mod h3_transport;
use self::h3_transport::{XhttpH3Connection, XhttpH3EndpointClient};

mod h1;
use self::h1::{XhttpH1ChunkedWriter, XhttpH1DownloadBody};

mod h2_transport;
use self::h2_transport::XhttpH2EndpointSender;

mod client_io;
pub(crate) use self::client_io::{
    close_xhttp_download_client, close_xhttp_stream_upload_client, close_xhttp_upload_client,
    poll_xhttp_download_data, read_xhttp_download_data, send_xhttp_packet_up_request,
    send_xhttp_stream_data,
};

mod relay;
pub(crate) use self::relay::{relay_tcp_over_xhttp_packet_up, relay_tcp_over_xhttp_stream};

mod parts;
pub(crate) use self::parts::{open_xhttp_packet_up_parts, open_xhttp_stream_parts};
#[cfg(test)]
pub(crate) use self::request::{
    xhttp_h1_request_bytes, xhttp_h2_request, xhttp_session_path_suffix, xhttp_uri,
};
#[cfg(test)]
pub(crate) use self::xmux::shutdown_xhttp_xmux_generation_owner;
pub(crate) use self::xmux::{
    XhttpXmuxClearReport, XhttpXmuxGenerationOwnerHandle, start_xhttp_xmux_generation_owner_on,
    stop_xhttp_xmux_generation_owner,
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
        binding: ResidentProxyBinding,
        endpoint: ResidentXhttpEndpointPlan,
        mptcp: bool,
    },
    H2 {
        binding: ResidentProxyBinding,
        endpoint: ResidentXhttpEndpointPlan,
        mptcp: bool,
        sender: h2::client::SendRequest<Bytes>,
        connection_task: Option<tokio::task::JoinHandle<()>>,
        xmux_lease: Option<XhttpXmuxClientLease>,
        xmux_request: Option<XhttpXmuxRequestHandle>,
    },
    H3 {
        binding: ResidentProxyBinding,
        endpoint: ResidentXhttpEndpointPlan,
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
    H3StreamOne {
        send: h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
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
    H3StreamOne {
        recv: h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
    },
}
