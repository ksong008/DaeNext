// xHTTP stream/client enums keep live H1/H2/H3 transport ownership inline.
#![allow(clippy::large_enum_variant)]

use super::*;
use crate::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
use std::future::Future;
use std::pin::Pin;

type XhttpPacketUpCompletion = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'static>>;

mod resolved_endpoint;
use self::resolved_endpoint::XhttpResolvedEndpoint;

#[cfg(test)]
mod cancellation_tests;

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
pub use self::client_io::{
    close_xhttp_download_client, close_xhttp_stream_upload_client, close_xhttp_upload_client,
    poll_xhttp_download_data, read_xhttp_download_data, send_xhttp_packet_up_request,
    send_xhttp_stream_data,
};

mod packet_up_pipeline;
pub use self::packet_up_pipeline::XhttpPacketUpPipeline;

mod relay;
pub use self::relay::{
    relay_tcp_over_xhttp_packet_up, relay_tcp_over_xhttp_stream,
    spawn_xhttp_packet_up_payload_stream, spawn_xhttp_stream_payload_stream,
};

mod parts;
pub use self::parts::{open_xhttp_packet_up_parts, open_xhttp_stream_parts};
#[cfg(any(test, feature = "test-support"))]
pub use self::request::{
    xhttp_h1_request_bytes, xhttp_h2_request, xhttp_session_path_suffix, xhttp_uri,
};
#[cfg(any(test, feature = "test-support"))]
pub use self::xmux::shutdown_xhttp_xmux_generation_owner;
pub use self::xmux::{
    XhttpXmuxClearReport, XhttpXmuxGenerationOwnerHandle, start_xhttp_xmux_generation_owner_on,
    stop_xhttp_xmux_generation_owner,
};
use self::xmux::{XhttpXmuxClientLease, XhttpXmuxRequestHandle};

pub trait ResidentXhttpEndpointView {
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

pub struct XhttpPacketUpParts {
    pub session_id: String,
    pub upload: XhttpUploadClient,
    pub download: XhttpDownloadClient,
    pub upload_underlay: &'static str,
    pub upload_http_version: ResidentXhttpHttpVersion,
    pub download_separate: bool,
}

pub struct XhttpStreamParts {
    pub session_id: Option<String>,
    pub upload: XhttpStreamUploadClient,
    pub download: XhttpDownloadClient,
    pub upload_underlay: &'static str,
    pub upload_http_version: ResidentXhttpHttpVersion,
    pub download_separate: bool,
}

pub enum XhttpUploadClient {
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

pub enum XhttpStreamUploadClient {
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

pub enum XhttpDownloadClient {
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

fn abort_and_reap_xhttp_task(mut task: tokio::task::JoinHandle<()>) {
    task.abort();
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn(async move {
            let _ = tokio::time::timeout(RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE, &mut task).await;
        });
    }
}

impl Drop for XhttpUploadClient {
    fn drop(&mut self) {
        match self {
            Self::H1 { .. } => {}
            Self::H2 {
                connection_task,
                xmux_lease,
                ..
            } => {
                if let Some(task) = connection_task.take() {
                    abort_and_reap_xhttp_task(task);
                }
                drop(xmux_lease.take());
            }
            Self::H3 {
                connection,
                xmux_lease,
                ..
            } => {
                if let Some(connection) = connection.take() {
                    connection.abort_with_reason(b"resident xhttp upload dropped");
                }
                drop(xmux_lease.take());
            }
        }
    }
}

impl Drop for XhttpStreamUploadClient {
    fn drop(&mut self) {
        match self {
            Self::H1 { .. } => {}
            Self::H2 {
                upload_response_task,
                connection_task,
                xmux_lease,
                ..
            } => {
                if let Some(task) = upload_response_task.take() {
                    abort_and_reap_xhttp_task(task);
                }
                if let Some(task) = connection_task.take() {
                    abort_and_reap_xhttp_task(task);
                }
                drop(xmux_lease.take());
            }
            Self::H3 {
                connection,
                xmux_lease,
                ..
            }
            | Self::H3StreamOne {
                connection,
                xmux_lease,
                ..
            } => {
                if let Some(connection) = connection.take() {
                    connection.abort_with_reason(b"resident xhttp stream upload dropped");
                }
                drop(xmux_lease.take());
            }
        }
    }
}

impl Drop for XhttpDownloadClient {
    fn drop(&mut self) {
        match self {
            Self::H1 { .. } | Self::H3StreamOne { .. } => {}
            Self::H2 {
                connection_task,
                xmux_lease,
                ..
            } => {
                if let Some(task) = connection_task.take() {
                    abort_and_reap_xhttp_task(task);
                }
                drop(xmux_lease.take());
            }
            Self::H3 {
                connection,
                xmux_lease,
                ..
            } => {
                if let Some(connection) = connection.take() {
                    connection.abort_with_reason(b"resident xhttp download dropped");
                }
                drop(xmux_lease.take());
            }
        }
    }
}
