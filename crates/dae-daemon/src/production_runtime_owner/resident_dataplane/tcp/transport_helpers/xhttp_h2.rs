use super::*;
use base64::{Engine as _, engine::general_purpose};
use bytes::Buf;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::AtomicI32;
use tokio::io::AsyncWrite;

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

pub(crate) struct XhttpH1ChunkedWriter {
    writer: XhttpH1ChunkedWriterInner,
    finished: bool,
}

enum XhttpH1ChunkedWriterInner {
    Client(AsyncResidentTlsClient),
    WriteHalf(tokio::io::WriteHalf<AsyncResidentTlsClient>),
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

pub(crate) struct XhttpH3Connection {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    client: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver_task: tokio::task::JoinHandle<()>,
}

pub(crate) struct XhttpH1DownloadBody {
    reader: XhttpH1BodyReader,
    buffer: VecDeque<u8>,
    state: XhttpH1BodyState,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct XhttpXmuxKey {
    origin: String,
    server_host: String,
    server_port: u16,
    server_name: String,
    alpn: Vec<String>,
    stream_host: String,
    stream_path: String,
    mode: ResidentXhttpMode,
    allow_insecure: bool,
    tls_fragment: Option<(usize, usize, u64, u64)>,
    xmux: ResidentXhttpXmuxPlan,
    mark: u32,
    mptcp: bool,
}

struct XhttpXmuxUsage {
    open_usage: AtomicI32,
    left_requests: AtomicI32,
    unreusable_at: Option<Instant>,
}

#[derive(Clone)]
pub(crate) struct XhttpXmuxClientLease {
    usage: Arc<XhttpXmuxUsage>,
}

#[derive(Clone)]
pub(crate) struct XhttpXmuxRequestHandle {
    usage: Arc<XhttpXmuxUsage>,
}

struct XhttpXmuxH2ClientEntry {
    sender: h2::client::SendRequest<Bytes>,
    connection_task: tokio::task::JoinHandle<()>,
    usage: Arc<XhttpXmuxUsage>,
    left_usage: i32,
}

struct XhttpXmuxH2Manager {
    config: ResidentXhttpXmuxPlan,
    concurrency: i32,
    connections: i32,
    clients: Vec<XhttpXmuxH2ClientEntry>,
}

struct XhttpXmuxH2SelectedClient {
    sender: h2::client::SendRequest<Bytes>,
    lease: XhttpXmuxClientLease,
}

struct XhttpXmuxH3ClientEntry {
    client: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    connection: XhttpH3Connection,
    usage: Arc<XhttpXmuxUsage>,
    left_usage: i32,
}

struct XhttpXmuxH3Manager {
    config: ResidentXhttpXmuxPlan,
    concurrency: i32,
    connections: i32,
    clients: Vec<XhttpXmuxH3ClientEntry>,
}

struct XhttpXmuxH3SelectedClient {
    client: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    lease: XhttpXmuxClientLease,
}

static XHTTP_XMUX_H2_MANAGERS: OnceLock<
    Mutex<HashMap<XhttpXmuxKey, Arc<tokio::sync::Mutex<XhttpXmuxH2Manager>>>>,
> = OnceLock::new();
static XHTTP_XMUX_H3_MANAGERS: OnceLock<
    Mutex<HashMap<XhttpXmuxKey, Arc<tokio::sync::Mutex<XhttpXmuxH3Manager>>>>,
> = OnceLock::new();

impl XhttpXmuxKey {
    fn primary(
        proxy: &ResidentProxyPlan,
        endpoint: &ResidentXhttpEndpointPlan,
        xmux: &ResidentXhttpXmuxPlan,
        mark: u32,
        mptcp: bool,
    ) -> Self {
        let fingerprint = proxy
            .utls_fingerprint
            .as_ref()
            .map(|fingerprint| fingerprint.canonical.as_str())
            .unwrap_or_default();
        Self::new(
            format!(
                "primary:{}:{}:{}:{}",
                proxy.graph_link_hash,
                proxy.tls,
                fingerprint,
                proxy.reality.is_some()
            ),
            endpoint,
            xmux,
            mark,
            mptcp,
        )
    }

    fn endpoint(
        endpoint: &ResidentXhttpEndpointPlan,
        xmux: &ResidentXhttpXmuxPlan,
        mark: u32,
        mptcp: bool,
    ) -> Self {
        Self::new("endpoint".to_owned(), endpoint, xmux, mark, mptcp)
    }

    fn new(
        origin: String,
        endpoint: &ResidentXhttpEndpointPlan,
        xmux: &ResidentXhttpXmuxPlan,
        mark: u32,
        mptcp: bool,
    ) -> Self {
        Self {
            origin,
            server_host: endpoint.server_host.clone(),
            server_port: endpoint.server_port,
            server_name: endpoint.server_name.clone(),
            alpn: endpoint.alpn.clone(),
            stream_host: endpoint.stream_host.clone(),
            stream_path: endpoint.stream_path.clone(),
            mode: endpoint.mode,
            allow_insecure: endpoint.allow_insecure,
            tls_fragment: endpoint.tls_fragment.as_ref().map(|fragment| {
                (
                    fragment.min_length,
                    fragment.max_length,
                    fragment.min_interval_ms,
                    fragment.max_interval_ms,
                )
            }),
            xmux: xmux.clone().official_normalized(),
            mark,
            mptcp,
        }
    }
}

impl XhttpXmuxClientLease {
    fn open(usage: Arc<XhttpXmuxUsage>) -> Self {
        usage.open_usage.fetch_add(1, Ordering::AcqRel);
        Self { usage }
    }

    fn request_handle(&self) -> XhttpXmuxRequestHandle {
        XhttpXmuxRequestHandle {
            usage: Arc::clone(&self.usage),
        }
    }

    fn note_request(&self) -> i32 {
        self.usage.left_requests.fetch_sub(1, Ordering::AcqRel) - 1
    }
}

impl XhttpXmuxRequestHandle {
    fn use_for_packet_up_post(&self) -> bool {
        let left = self.usage.left_requests.fetch_sub(1, Ordering::AcqRel) - 1;
        left > 0
            && !self
                .usage
                .unreusable_at
                .is_some_and(|deadline| Instant::now() > deadline)
    }
}

impl Drop for XhttpXmuxClientLease {
    fn drop(&mut self) {
        self.usage.open_usage.fetch_sub(1, Ordering::AcqRel);
    }
}

impl XhttpXmuxH2Manager {
    fn new(config: ResidentXhttpXmuxPlan) -> Self {
        let config = config.official_normalized();
        Self {
            concurrency: ResidentXhttpXmuxPlan::sample_range(config.max_concurrency),
            connections: ResidentXhttpXmuxPlan::sample_range(config.max_connections),
            config,
            clients: Vec::new(),
        }
    }

    async fn select<F, Fut>(&mut self, new_sender: F) -> Result<XhttpXmuxH2SelectedClient, String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<XhttpH2EndpointSender, String>>,
    {
        self.prune();

        if self.reusable_len() == 0 {
            return self.new_client(new_sender).await;
        }

        if self.connections > 0 && self.reusable_len() < self.connections as usize {
            return self.new_client(new_sender).await;
        }

        let candidates = self
            .clients
            .iter()
            .enumerate()
            .filter_map(|(index, client)| {
                if self.client_reusable(client)
                    && (self.concurrency <= 0
                        || client.usage.open_usage.load(Ordering::Acquire) < self.concurrency)
                {
                    Some(index)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if candidates.is_empty() {
            return self.new_client(new_sender).await;
        }

        let index = candidates[fastrand::usize(..candidates.len())];
        let client = &mut self.clients[index];
        if client.left_usage > 0 {
            client.left_usage -= 1;
        }
        Ok(XhttpXmuxH2SelectedClient {
            sender: client.sender.clone(),
            lease: XhttpXmuxClientLease::open(Arc::clone(&client.usage)),
        })
    }

    async fn new_client<F, Fut>(
        &mut self,
        new_sender: F,
    ) -> Result<XhttpXmuxH2SelectedClient, String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<XhttpH2EndpointSender, String>>,
    {
        let sender = new_sender().await?;
        let mut left_usage = -1;
        let sampled_left_usage = ResidentXhttpXmuxPlan::sample_range(self.config.c_max_reuse_times);
        if sampled_left_usage > 0 {
            left_usage = sampled_left_usage - 1;
        }
        let mut left_requests = i32::MAX;
        let sampled_left_requests =
            ResidentXhttpXmuxPlan::sample_range(self.config.h_max_request_times);
        if sampled_left_requests > 0 {
            left_requests = sampled_left_requests;
        }
        let sampled_reusable_secs =
            ResidentXhttpXmuxPlan::sample_range(self.config.h_max_reusable_secs);
        let unreusable_at = if sampled_reusable_secs > 0 {
            Some(Instant::now() + Duration::from_secs(sampled_reusable_secs as u64))
        } else {
            None
        };
        let usage = Arc::new(XhttpXmuxUsage {
            open_usage: AtomicI32::new(0),
            left_requests: AtomicI32::new(left_requests),
            unreusable_at,
        });
        self.clients.push(XhttpXmuxH2ClientEntry {
            sender: sender.sender.clone(),
            connection_task: sender
                .connection_task
                .expect("new xmux H2 clients must own their connection task"),
            usage: Arc::clone(&usage),
            left_usage,
        });
        Ok(XhttpXmuxH2SelectedClient {
            sender: sender.sender,
            lease: XhttpXmuxClientLease::open(usage),
        })
    }

    fn prune(&mut self) {
        let now = Instant::now();
        let mut index = 0;
        while index < self.clients.len() {
            let should_retire = {
                let client = &self.clients[index];
                client.connection_task.is_finished()
                    || client.left_usage == 0
                    || client.usage.left_requests.load(Ordering::Acquire) <= 0
                    || client
                        .usage
                        .unreusable_at
                        .is_some_and(|deadline| now > deadline)
            };
            if should_retire {
                let client = self.clients.swap_remove(index);
                if client.usage.open_usage.load(Ordering::Acquire) <= 0 {
                    client.connection_task.abort();
                }
            } else {
                index += 1;
            }
        }
    }

    fn reusable_len(&self) -> usize {
        self.clients
            .iter()
            .filter(|client| self.client_reusable(client))
            .count()
    }

    fn client_reusable(&self, client: &XhttpXmuxH2ClientEntry) -> bool {
        !client.connection_task.is_finished()
            && client.left_usage != 0
            && client.usage.left_requests.load(Ordering::Acquire) > 0
            && !client
                .usage
                .unreusable_at
                .is_some_and(|deadline| Instant::now() > deadline)
    }
}

impl XhttpXmuxH3Manager {
    fn new(config: ResidentXhttpXmuxPlan) -> Self {
        let config = config.official_normalized();
        Self {
            concurrency: ResidentXhttpXmuxPlan::sample_range(config.max_concurrency),
            connections: ResidentXhttpXmuxPlan::sample_range(config.max_connections),
            config,
            clients: Vec::new(),
        }
    }

    async fn select<F, Fut>(&mut self, new_client: F) -> Result<XhttpXmuxH3SelectedClient, String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<XhttpH3EndpointClient, String>>,
    {
        self.prune();

        if self.reusable_len() == 0 {
            return self.new_client(new_client).await;
        }

        if self.connections > 0 && self.reusable_len() < self.connections as usize {
            return self.new_client(new_client).await;
        }

        let candidates = self
            .clients
            .iter()
            .enumerate()
            .filter_map(|(index, client)| {
                if self.client_reusable(client)
                    && (self.concurrency <= 0
                        || client.usage.open_usage.load(Ordering::Acquire) < self.concurrency)
                {
                    Some(index)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if candidates.is_empty() {
            return self.new_client(new_client).await;
        }

        let index = candidates[fastrand::usize(..candidates.len())];
        let client = &mut self.clients[index];
        if client.left_usage > 0 {
            client.left_usage -= 1;
        }
        Ok(XhttpXmuxH3SelectedClient {
            client: client.client.clone(),
            lease: XhttpXmuxClientLease::open(Arc::clone(&client.usage)),
        })
    }

    async fn new_client<F, Fut>(
        &mut self,
        new_client: F,
    ) -> Result<XhttpXmuxH3SelectedClient, String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<XhttpH3EndpointClient, String>>,
    {
        let client = new_client().await?;
        let mut left_usage = -1;
        let sampled_left_usage = ResidentXhttpXmuxPlan::sample_range(self.config.c_max_reuse_times);
        if sampled_left_usage > 0 {
            left_usage = sampled_left_usage - 1;
        }
        let mut left_requests = i32::MAX;
        let sampled_left_requests =
            ResidentXhttpXmuxPlan::sample_range(self.config.h_max_request_times);
        if sampled_left_requests > 0 {
            left_requests = sampled_left_requests;
        }
        let sampled_reusable_secs =
            ResidentXhttpXmuxPlan::sample_range(self.config.h_max_reusable_secs);
        let unreusable_at = if sampled_reusable_secs > 0 {
            Some(Instant::now() + Duration::from_secs(sampled_reusable_secs as u64))
        } else {
            None
        };
        let usage = Arc::new(XhttpXmuxUsage {
            open_usage: AtomicI32::new(0),
            left_requests: AtomicI32::new(left_requests),
            unreusable_at,
        });
        self.clients.push(XhttpXmuxH3ClientEntry {
            client: client.client.clone(),
            connection: client
                .connection
                .expect("new xmux H3 clients must own their connection"),
            usage: Arc::clone(&usage),
            left_usage,
        });
        Ok(XhttpXmuxH3SelectedClient {
            client: client.client,
            lease: XhttpXmuxClientLease::open(usage),
        })
    }

    fn prune(&mut self) {
        let now = Instant::now();
        let mut index = 0;
        while index < self.clients.len() {
            let should_retire = {
                let client = &self.clients[index];
                client.connection.driver_task.is_finished()
                    || client.left_usage == 0
                    || client.usage.left_requests.load(Ordering::Acquire) <= 0
                    || client
                        .usage
                        .unreusable_at
                        .is_some_and(|deadline| now > deadline)
            };
            if should_retire {
                let client = self.clients.swap_remove(index);
                if client.usage.open_usage.load(Ordering::Acquire) <= 0 {
                    client
                        .connection
                        .connection
                        .close(0_u32.into(), b"resident xhttp h3 xmux retire");
                    client.connection.driver_task.abort();
                }
            } else {
                index += 1;
            }
        }
    }

    fn reusable_len(&self) -> usize {
        self.clients
            .iter()
            .filter(|client| self.client_reusable(client))
            .count()
    }

    fn client_reusable(&self, client: &XhttpXmuxH3ClientEntry) -> bool {
        !client.connection.driver_task.is_finished()
            && client.left_usage != 0
            && client.usage.left_requests.load(Ordering::Acquire) > 0
            && !client
                .usage
                .unreusable_at
                .is_some_and(|deadline| Instant::now() > deadline)
    }
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

pub(crate) enum XhttpH1BodyReader {
    Client(AsyncResidentTlsClient),
    ReadHalf(tokio::io::ReadHalf<AsyncResidentTlsClient>),
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

struct XhttpH3EndpointClient {
    client: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    connection: Option<XhttpH3Connection>,
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

async fn select_xhttp_h2_xmux_client<F, Fut>(
    key: XhttpXmuxKey,
    xmux: ResidentXhttpXmuxPlan,
    new_sender: F,
) -> Result<XhttpXmuxH2SelectedClient, String>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<XhttpH2EndpointSender, String>>,
{
    let manager =
        {
            let mut managers = XHTTP_XMUX_H2_MANAGERS
                .get_or_init(|| Mutex::new(HashMap::new()))
                .lock()
                .map_err(|_| "resident xHTTP H2 xmux manager lock poisoned".to_owned())?;
            Arc::clone(managers.entry(key).or_insert_with(|| {
                Arc::new(tokio::sync::Mutex::new(XhttpXmuxH2Manager::new(xmux)))
            }))
        };
    let mut manager = manager.lock().await;
    manager.select(new_sender).await
}

async fn open_xhttp_h3_proxy_client(
    proxy: &ResidentProxyPlan,
    endpoint: &ResidentXhttpEndpointPlan,
    mark: u32,
) -> Result<XhttpH3EndpointClient, String> {
    let Some(xmux) = &proxy.xhttp_xmux else {
        let connection = open_xhttp_h3_connection(endpoint, mark).await?;
        return Ok(XhttpH3EndpointClient {
            client: connection.client.clone(),
            connection: Some(connection),
            xmux_lease: None,
        });
    };
    let key = XhttpXmuxKey::primary(proxy, endpoint, xmux, mark, false);
    let selected = select_xhttp_h3_xmux_client(key, xmux.clone(), || async {
        let connection = open_xhttp_h3_connection(endpoint, mark).await?;
        Ok(XhttpH3EndpointClient {
            client: connection.client.clone(),
            connection: Some(connection),
            xmux_lease: None,
        })
    })
    .await?;
    Ok(XhttpH3EndpointClient {
        client: selected.client,
        connection: None,
        xmux_lease: Some(selected.lease),
    })
}

async fn open_xhttp_h3_endpoint_client(
    endpoint: &ResidentXhttpEndpointPlan,
    mark: u32,
) -> Result<XhttpH3EndpointClient, String> {
    let Some(xmux) = &endpoint.xmux else {
        let connection = open_xhttp_h3_connection(endpoint, mark).await?;
        return Ok(XhttpH3EndpointClient {
            client: connection.client.clone(),
            connection: Some(connection),
            xmux_lease: None,
        });
    };
    let key = XhttpXmuxKey::endpoint(endpoint, xmux, mark, false);
    let selected = select_xhttp_h3_xmux_client(key, xmux.clone(), || async {
        let connection = open_xhttp_h3_connection(endpoint, mark).await?;
        Ok(XhttpH3EndpointClient {
            client: connection.client.clone(),
            connection: Some(connection),
            xmux_lease: None,
        })
    })
    .await?;
    Ok(XhttpH3EndpointClient {
        client: selected.client,
        connection: None,
        xmux_lease: Some(selected.lease),
    })
}

async fn select_xhttp_h3_xmux_client<F, Fut>(
    key: XhttpXmuxKey,
    xmux: ResidentXhttpXmuxPlan,
    new_client: F,
) -> Result<XhttpXmuxH3SelectedClient, String>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<XhttpH3EndpointClient, String>>,
{
    let manager =
        {
            let mut managers = XHTTP_XMUX_H3_MANAGERS
                .get_or_init(|| Mutex::new(HashMap::new()))
                .lock()
                .map_err(|_| "resident xHTTP H3 xmux manager lock poisoned".to_owned())?;
            Arc::clone(managers.entry(key).or_insert_with(|| {
                Arc::new(tokio::sync::Mutex::new(XhttpXmuxH3Manager::new(xmux)))
            }))
        };
    let mut manager = manager.lock().await;
    manager.select(new_client).await
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
    let request = xhttp_h1_packet_up_request_bytes(endpoint, session_id, seq, payload)?;
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

async fn read_xhttp_h1_response_head<T>(
    client: &mut T,
    context: &str,
) -> Result<XhttpH1ResponseHead, String>
where
    T: AsyncRead + Unpin,
{
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

pub(crate) fn xhttp_h2_request(
    method: http::Method,
    endpoint: &impl ResidentXhttpEndpointView,
    path_suffix: &str,
    has_body: bool,
) -> Result<http::Request<()>, String> {
    let meta = XhttpRequestMeta::from_path_suffix(path_suffix);
    let method = xhttp_effective_method(method, endpoint.xhttp_settings(), has_body)?;
    xhttp_h2_request_with_parts(method, endpoint, meta, has_body, Vec::new(), Vec::new())
}

pub(crate) fn xhttp_h1_request_bytes(
    method: http::Method,
    endpoint: &impl ResidentXhttpEndpointView,
    path_suffix: &str,
    body: Option<&Bytes>,
) -> Vec<u8> {
    let meta = XhttpRequestMeta::from_path_suffix(path_suffix);
    let method = xhttp_effective_method(method.clone(), endpoint.xhttp_settings(), body.is_some())
        .unwrap_or(method);
    let mut bytes = xhttp_h1_request_bytes_with_parts(
        method,
        endpoint,
        meta,
        body.is_some(),
        body.map(|body| body.len()),
        Vec::new(),
        Vec::new(),
    );
    if let Some(body) = body {
        bytes.extend_from_slice(body);
    }
    bytes
}

fn xhttp_h1_packet_up_request_bytes(
    endpoint: &impl ResidentXhttpEndpointView,
    session_id: &str,
    seq: u64,
    payload: Bytes,
) -> Result<Vec<u8>, String> {
    let plan = xhttp_packet_payload_plan(endpoint.xhttp_settings(), payload)?;
    let method = xhttp_method_from_settings(endpoint.xhttp_settings())?;
    let mut bytes = xhttp_h1_request_bytes_with_parts(
        method,
        endpoint,
        XhttpRequestMeta::new(Some(session_id), Some(seq.to_string())),
        false,
        plan.body.as_ref().map(Bytes::len),
        plan.headers,
        plan.cookies,
    );
    if let Some(body) = plan.body {
        bytes.extend_from_slice(&body);
    }
    Ok(bytes)
}

fn xhttp_h2_packet_up_request(
    endpoint: &impl ResidentXhttpEndpointView,
    session_id: &str,
    seq: u64,
    payload: Bytes,
) -> Result<(http::Request<()>, Option<Bytes>), String> {
    let plan = xhttp_packet_payload_plan(endpoint.xhttp_settings(), payload)?;
    let method = xhttp_method_from_settings(endpoint.xhttp_settings())?;
    let request = xhttp_h2_request_with_parts(
        method,
        endpoint,
        XhttpRequestMeta::new(Some(session_id), Some(seq.to_string())),
        plan.body.is_some(),
        plan.headers,
        plan.cookies,
    )?;
    Ok((request, plan.body))
}

fn xhttp_h3_packet_up_request(
    endpoint: &impl ResidentXhttpEndpointView,
    session_id: &str,
    seq: u64,
    payload: Bytes,
) -> Result<(http::Request<()>, Option<Bytes>), String> {
    let plan = xhttp_packet_payload_plan(endpoint.xhttp_settings(), payload)?;
    let method = xhttp_method_from_settings(endpoint.xhttp_settings())?;
    let request = xhttp_h3_request_with_parts(
        method,
        endpoint,
        XhttpRequestMeta::new(Some(session_id), Some(seq.to_string())),
        plan.body.is_some(),
        plan.headers,
        plan.cookies,
    )?;
    Ok((request, plan.body))
}

async fn write_xhttp_h1_chunked_request_head<W>(
    writer: &mut W,
    endpoint: &impl ResidentXhttpEndpointView,
    path_suffix: &str,
    context: &str,
) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    let method = xhttp_method_from_settings(endpoint.xhttp_settings())?;
    let mut request = xhttp_h1_request_head_string(
        method,
        endpoint,
        XhttpRequestMeta::from_path_suffix(path_suffix),
        true,
        None,
        Vec::new(),
        Vec::new(),
    );
    request.push_str("Transfer-Encoding: chunked\r\n\r\n");
    time::timeout(
        RESIDENT_CONNECT_TIMEOUT,
        writer.write_all(request.as_bytes()),
    )
    .await
    .map_err(|_| format!("xHTTP HTTP/1.1 {context} request headers timeout"))?
    .map_err(|err| format!("write xHTTP HTTP/1.1 {context} request headers: {err}"))?;
    time::timeout(RESIDENT_CONNECT_TIMEOUT, writer.flush())
        .await
        .map_err(|_| format!("flush xHTTP HTTP/1.1 {context} request headers timeout"))?
        .map_err(|err| format!("flush xHTTP HTTP/1.1 {context} request headers: {err}"))
}

async fn write_xhttp_h1_chunk<W>(
    writer: &mut W,
    payload: &Bytes,
    end_stream: bool,
    context: &str,
) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    if !payload.is_empty() {
        let prefix = format!("{:x}\r\n", payload.len());
        time::timeout(
            RESIDENT_CONNECT_TIMEOUT,
            writer.write_all(prefix.as_bytes()),
        )
        .await
        .map_err(|_| format!("xHTTP HTTP/1.1 {context} chunk prefix timeout"))?
        .map_err(|err| format!("write xHTTP HTTP/1.1 {context} chunk prefix: {err}"))?;
        time::timeout(RESIDENT_CONNECT_TIMEOUT, writer.write_all(payload))
            .await
            .map_err(|_| format!("xHTTP HTTP/1.1 {context} chunk body timeout"))?
            .map_err(|err| format!("write xHTTP HTTP/1.1 {context} chunk body: {err}"))?;
        time::timeout(RESIDENT_CONNECT_TIMEOUT, writer.write_all(b"\r\n"))
            .await
            .map_err(|_| format!("xHTTP HTTP/1.1 {context} chunk suffix timeout"))?
            .map_err(|err| format!("write xHTTP HTTP/1.1 {context} chunk suffix: {err}"))?;
    }
    if end_stream {
        time::timeout(RESIDENT_CONNECT_TIMEOUT, writer.write_all(b"0\r\n\r\n"))
            .await
            .map_err(|_| format!("xHTTP HTTP/1.1 {context} final chunk timeout"))?
            .map_err(|err| format!("write xHTTP HTTP/1.1 {context} final chunk: {err}"))?;
    }
    time::timeout(RESIDENT_CONNECT_TIMEOUT, writer.flush())
        .await
        .map_err(|_| format!("flush xHTTP HTTP/1.1 {context} chunk timeout"))?
        .map_err(|err| format!("flush xHTTP HTTP/1.1 {context} chunk: {err}"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct XhttpRequestMeta {
    session_id: Option<String>,
    seq: Option<String>,
}

impl XhttpRequestMeta {
    fn new(session_id: Option<&str>, seq: Option<String>) -> Self {
        Self {
            session_id: session_id.map(str::to_owned),
            seq,
        }
    }

    fn from_path_suffix(path_suffix: &str) -> Self {
        let suffix = path_suffix.trim_matches('/');
        if suffix.is_empty() {
            return Self {
                session_id: None,
                seq: None,
            };
        }
        match suffix.split_once('/') {
            Some((session_id, seq)) => Self {
                session_id: Some(session_id.to_owned()),
                seq: Some(seq.to_owned()),
            },
            None => Self {
                session_id: Some(suffix.to_owned()),
                seq: None,
            },
        }
    }
}

struct XhttpPacketPayloadPlan {
    body: Option<Bytes>,
    headers: Vec<(String, String)>,
    cookies: Vec<(String, String)>,
}

fn xhttp_packet_payload_plan(
    settings: &ResidentXhttpSettingsPlan,
    payload: Bytes,
) -> Result<XhttpPacketPayloadPlan, String> {
    match settings.uplink_data_placement {
        ResidentXhttpUplinkDataPlacement::Auto | ResidentXhttpUplinkDataPlacement::Body => {
            Ok(XhttpPacketPayloadPlan {
                body: Some(payload),
                headers: Vec::new(),
                cookies: Vec::new(),
            })
        }
        ResidentXhttpUplinkDataPlacement::Header => Ok(XhttpPacketPayloadPlan {
            body: None,
            headers: xhttp_encoded_payload_chunks(
                settings.normalized_uplink_data_key(),
                '-',
                settings,
                &payload,
            ),
            cookies: Vec::new(),
        }),
        ResidentXhttpUplinkDataPlacement::Cookie => Ok(XhttpPacketPayloadPlan {
            body: None,
            headers: Vec::new(),
            cookies: xhttp_encoded_payload_chunks(
                settings.normalized_uplink_data_key(),
                '_',
                settings,
                &payload,
            ),
        }),
    }
}

fn xhttp_encoded_payload_chunks(
    key: &str,
    separator: char,
    settings: &ResidentXhttpSettingsPlan,
    payload: &Bytes,
) -> Vec<(String, String)> {
    if payload.is_empty() || key.is_empty() {
        return Vec::new();
    }
    let encoded = general_purpose::URL_SAFE_NO_PAD.encode(payload);
    let chunk_size =
        ResidentXhttpSettingsPlan::sample_range(settings.normalized_uplink_chunk_size()).max(1)
            as usize;
    encoded
        .as_bytes()
        .chunks(chunk_size)
        .enumerate()
        .map(|(index, chunk)| {
            (
                format!("{key}{separator}{index}"),
                String::from_utf8_lossy(chunk).into_owned(),
            )
        })
        .collect()
}

struct XhttpPreparedRequestParts {
    uri: String,
    path_and_query: String,
    headers: Vec<(String, String)>,
}

fn xhttp_h2_request_with_parts(
    method: http::Method,
    endpoint: &impl ResidentXhttpEndpointView,
    meta: XhttpRequestMeta,
    grpc_body_header: bool,
    extra_headers: Vec<(String, String)>,
    extra_cookies: Vec<(String, String)>,
) -> Result<http::Request<()>, String> {
    let prepared = xhttp_prepare_request_parts(
        endpoint,
        meta,
        grpc_body_header,
        extra_headers,
        extra_cookies,
    );
    let mut builder = http::Request::builder().method(method).uri(prepared.uri);
    for (name, value) in prepared.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder
        .body(())
        .map_err(|err| format!("build xHTTP HTTP/2 request: {err}"))
}

fn xhttp_h3_request_with_parts(
    method: http::Method,
    endpoint: &impl ResidentXhttpEndpointView,
    meta: XhttpRequestMeta,
    grpc_body_header: bool,
    extra_headers: Vec<(String, String)>,
    extra_cookies: Vec<(String, String)>,
) -> Result<http::Request<()>, String> {
    let prepared = xhttp_prepare_request_parts(
        endpoint,
        meta,
        grpc_body_header,
        extra_headers,
        extra_cookies,
    );
    let mut builder = http::Request::builder().method(method).uri(prepared.uri);
    for (name, value) in prepared.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder
        .body(())
        .map_err(|err| format!("build xHTTP H3 request: {err}"))
}

fn xhttp_h1_request_bytes_with_parts(
    method: http::Method,
    endpoint: &impl ResidentXhttpEndpointView,
    meta: XhttpRequestMeta,
    grpc_body_header: bool,
    content_length: Option<usize>,
    extra_headers: Vec<(String, String)>,
    extra_cookies: Vec<(String, String)>,
) -> Vec<u8> {
    let mut request = xhttp_h1_request_head_string(
        method,
        endpoint,
        meta,
        grpc_body_header,
        content_length,
        extra_headers,
        extra_cookies,
    );
    request.push_str("\r\n");
    request.into_bytes()
}

fn xhttp_h1_request_head_string(
    method: http::Method,
    endpoint: &impl ResidentXhttpEndpointView,
    meta: XhttpRequestMeta,
    grpc_body_header: bool,
    content_length: Option<usize>,
    extra_headers: Vec<(String, String)>,
    extra_cookies: Vec<(String, String)>,
) -> String {
    let prepared = xhttp_prepare_request_parts(
        endpoint,
        meta,
        grpc_body_header,
        extra_headers,
        extra_cookies,
    );
    let mut request = format!(
        "{method} {} HTTP/1.1\r\nHost: {}\r\n",
        prepared.path_and_query,
        xhttp_authority(endpoint)
    );
    for (name, value) in prepared.headers {
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        request.push_str(&name);
        request.push_str(": ");
        request.push_str(&value);
        request.push_str("\r\n");
    }
    request.push_str("Connection: close\r\n");
    if let Some(content_length) = content_length {
        request.push_str(&format!("Content-Length: {content_length}\r\n"));
    }
    request
}

fn xhttp_prepare_request_parts(
    endpoint: &impl ResidentXhttpEndpointView,
    meta: XhttpRequestMeta,
    grpc_body_header: bool,
    extra_headers: Vec<(String, String)>,
    extra_cookies: Vec<(String, String)>,
) -> XhttpPreparedRequestParts {
    let settings = endpoint.xhttp_settings();
    let mut headers = xhttp_default_headers(settings);
    for (name, value) in extra_headers {
        xhttp_set_header(&mut headers, name, value);
    }
    let mut cookies = extra_cookies;
    let mut query = Vec::new();
    xhttp_apply_padding(endpoint, &mut headers, &mut cookies, &mut query);
    xhttp_apply_meta(settings, &meta, &mut headers, &mut cookies, &mut query);
    if grpc_body_header && !settings.no_grpc_header {
        xhttp_set_header(
            &mut headers,
            http::header::CONTENT_TYPE.as_str().to_owned(),
            "application/grpc".to_owned(),
        );
    }
    xhttp_apply_cookie_header(&mut headers, cookies);
    let path_and_query = xhttp_path_and_query_with_meta(endpoint, &meta, &query);
    let uri = format!("https://{}{}", xhttp_authority(endpoint), path_and_query);
    XhttpPreparedRequestParts {
        uri,
        path_and_query,
        headers,
    }
}

fn xhttp_default_headers(settings: &ResidentXhttpSettingsPlan) -> Vec<(String, String)> {
    let mut headers = settings
        .headers
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<Vec<_>>();
    xhttp_push_default_header(
        &mut headers,
        http::header::USER_AGENT.as_str(),
        "Mozilla/5.0",
    );
    xhttp_push_default_header(&mut headers, http::header::ACCEPT.as_str(), "*/*");
    xhttp_push_default_header(
        &mut headers,
        http::header::ACCEPT_LANGUAGE.as_str(),
        "en-US,en;q=0.9",
    );
    xhttp_push_default_header(
        &mut headers,
        http::header::CACHE_CONTROL.as_str(),
        "no-cache",
    );
    xhttp_push_default_header(&mut headers, "pragma", "no-cache");
    headers
}

fn xhttp_push_default_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    if !headers
        .iter()
        .any(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
    {
        headers.push((name.to_owned(), value.to_owned()));
    }
}

fn xhttp_set_header(headers: &mut Vec<(String, String)>, name: String, value: String) {
    headers.retain(|(candidate, _)| !candidate.eq_ignore_ascii_case(&name));
    headers.push((name, value));
}

fn xhttp_apply_cookie_header(headers: &mut Vec<(String, String)>, cookies: Vec<(String, String)>) {
    if cookies.is_empty() {
        return;
    }
    let cookie_value = cookies
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");
    if let Some((_, existing)) = headers
        .iter_mut()
        .find(|(name, _)| name.eq_ignore_ascii_case(http::header::COOKIE.as_str()))
    {
        if !existing.is_empty() {
            existing.push_str("; ");
        }
        existing.push_str(&cookie_value);
    } else {
        headers.push((http::header::COOKIE.as_str().to_owned(), cookie_value));
    }
}

fn xhttp_apply_meta(
    settings: &ResidentXhttpSettingsPlan,
    meta: &XhttpRequestMeta,
    headers: &mut Vec<(String, String)>,
    cookies: &mut Vec<(String, String)>,
    query: &mut Vec<(String, String)>,
) {
    if let Some(session_id) = meta.session_id.as_deref() {
        match settings.session_id_placement {
            ResidentXhttpMetaPlacement::Path => {}
            ResidentXhttpMetaPlacement::Query => {
                query.push((
                    settings.normalized_session_key().to_owned(),
                    session_id.to_owned(),
                ));
            }
            ResidentXhttpMetaPlacement::Header => xhttp_set_header(
                headers,
                settings.normalized_session_key().to_owned(),
                session_id.to_owned(),
            ),
            ResidentXhttpMetaPlacement::Cookie => {
                cookies.push((
                    settings.normalized_session_key().to_owned(),
                    session_id.to_owned(),
                ));
            }
        }
    }
    if let Some(seq) = meta.seq.as_deref() {
        match settings.seq_placement {
            ResidentXhttpMetaPlacement::Path => {}
            ResidentXhttpMetaPlacement::Query => {
                query.push((settings.normalized_seq_key().to_owned(), seq.to_owned()));
            }
            ResidentXhttpMetaPlacement::Header => {
                xhttp_set_header(
                    headers,
                    settings.normalized_seq_key().to_owned(),
                    seq.to_owned(),
                );
            }
            ResidentXhttpMetaPlacement::Cookie => {
                cookies.push((settings.normalized_seq_key().to_owned(), seq.to_owned()));
            }
        }
    }
}

fn xhttp_apply_padding(
    endpoint: &impl ResidentXhttpEndpointView,
    headers: &mut Vec<(String, String)>,
    cookies: &mut Vec<(String, String)>,
    query: &mut Vec<(String, String)>,
) {
    let settings = endpoint.xhttp_settings();
    let padding_len = ResidentXhttpSettingsPlan::sample_range(settings.normalized_x_padding_bytes())
        .max(0) as usize;
    let padding = xhttp_generate_padding(settings.x_padding_method, padding_len);
    if !settings.x_padding_obfs_mode {
        xhttp_set_header(
            headers,
            http::header::REFERER.as_str().to_owned(),
            xhttp_padding_referer(&xhttp_uri(endpoint, ""), &padding),
        );
        return;
    }
    match settings.x_padding_placement {
        ResidentXhttpPaddingPlacement::Header => {
            xhttp_set_header(headers, settings.x_padding_header.clone(), padding);
        }
        ResidentXhttpPaddingPlacement::QueryInHeader => {
            xhttp_set_header(
                headers,
                settings.x_padding_header.clone(),
                xhttp_query_in_header_padding(
                    &xhttp_uri(endpoint, ""),
                    &settings.x_padding_key,
                    &padding,
                ),
            );
        }
        ResidentXhttpPaddingPlacement::Query => {
            query.push((settings.x_padding_key.clone(), padding));
        }
        ResidentXhttpPaddingPlacement::Cookie => {
            cookies.push((settings.x_padding_key.clone(), padding));
        }
    }
}

fn xhttp_generate_padding(method: ResidentXhttpPaddingMethod, len: usize) -> String {
    if len == 0 {
        return String::new();
    }
    match method {
        ResidentXhttpPaddingMethod::RepeatX => "X".repeat(len),
        ResidentXhttpPaddingMethod::Tokenish => {
            const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            let token_len = ((len as f64) / 0.8).ceil().max(1.0) as usize;
            (0..token_len)
                .map(|_| BASE62[fastrand::usize(..BASE62.len())] as char)
                .collect()
        }
    }
}

fn xhttp_query_in_header_padding(base_uri: &str, key: &str, padding: &str) -> String {
    let base_without_query = base_uri.split_once('?').map_or(base_uri, |(base, _)| base);
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair(key, padding);
    let query = serializer.finish();
    format!("{base_without_query}?{query}")
}

fn xhttp_method_from_settings(
    settings: &ResidentXhttpSettingsPlan,
) -> Result<http::Method, String> {
    settings
        .uplink_http_method
        .parse::<http::Method>()
        .map_err(|err| format!("parse xHTTP uplinkHTTPMethod: {err}"))
}

fn xhttp_effective_method(
    method: http::Method,
    settings: &ResidentXhttpSettingsPlan,
    has_body: bool,
) -> Result<http::Method, String> {
    if has_body {
        xhttp_method_from_settings(settings)
    } else {
        Ok(method)
    }
}

impl XhttpH1ChunkedWriter {
    fn from_client(client: AsyncResidentTlsClient) -> Self {
        Self {
            writer: XhttpH1ChunkedWriterInner::Client(client),
            finished: false,
        }
    }

    fn from_write_half(writer: tokio::io::WriteHalf<AsyncResidentTlsClient>) -> Self {
        Self {
            writer: XhttpH1ChunkedWriterInner::WriteHalf(writer),
            finished: false,
        }
    }

    async fn write_chunk(&mut self, payload: Bytes, end_stream: bool) -> Result<(), String> {
        if self.finished {
            return Ok(());
        }
        match &mut self.writer {
            XhttpH1ChunkedWriterInner::Client(client) => {
                write_xhttp_h1_chunk(client, &payload, end_stream, "stream").await?;
            }
            XhttpH1ChunkedWriterInner::WriteHalf(writer) => {
                write_xhttp_h1_chunk(writer, &payload, end_stream, "stream").await?;
            }
        }
        self.finished = end_stream;
        Ok(())
    }

    async fn shutdown(&mut self) {
        if let XhttpH1ChunkedWriterInner::Client(client) = &mut self.writer {
            let _ = client.shutdown().await;
        }
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
                connection
                    .connection
                    .close(0_u32.into(), b"resident xhttp stream upload done");
                connection.driver_task.abort();
                connection.endpoint.wait_idle().await;
            }
            drop(xmux_lease.take());
        }
        XhttpStreamUploadClient::H3Shared {
            connection,
            xmux_lease,
            ..
        } => {
            if let Some(connection) = connection.take() {
                connection
                    .connection
                    .close(0_u32.into(), b"resident xhttp stream-one done");
                connection.driver_task.abort();
                connection.endpoint.wait_idle().await;
            }
            drop(xmux_lease.take());
        }
    }
}

pub(crate) fn xhttp_uri(endpoint: &impl ResidentXhttpEndpointView, path_suffix: &str) -> String {
    let path_and_query = xhttp_path_and_query_with_meta(
        endpoint,
        &XhttpRequestMeta::from_path_suffix(path_suffix),
        &[],
    );
    format!("https://{}{}", xhttp_authority(endpoint), path_and_query)
}

fn xhttp_path_and_query_with_meta(
    endpoint: &impl ResidentXhttpEndpointView,
    meta: &XhttpRequestMeta,
    extra_query: &[(String, String)],
) -> String {
    let normalized = ir::normalize_xhttp_path_and_query(endpoint.stream_path());
    let mut path = normalized.path;
    let settings = endpoint.xhttp_settings();
    if settings.session_id_placement == ResidentXhttpMetaPlacement::Path
        && let Some(session_id) = meta.session_id.as_deref()
    {
        append_xhttp_path_segment(&mut path, session_id);
    }
    if settings.seq_placement == ResidentXhttpMetaPlacement::Path
        && let Some(seq) = meta.seq.as_deref()
    {
        append_xhttp_path_segment(&mut path, seq);
    }
    let query = xhttp_join_query(&normalized.query, extra_query);
    if !query.is_empty() {
        path.push('?');
        path.push_str(&query);
    }
    path
}

fn append_xhttp_path_segment(path: &mut String, value: &str) {
    if !path.ends_with('/') {
        path.push('/');
    }
    path.push_str(value);
}

fn xhttp_join_query(existing: &str, extra_query: &[(String, String)]) -> String {
    if extra_query.is_empty() {
        return existing.to_owned();
    }
    let mut encoded = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in extra_query {
        encoded.append_pair(key, value);
    }
    let encoded = encoded.finish();
    if existing.is_empty() {
        encoded
    } else if encoded.is_empty() {
        existing.to_owned()
    } else {
        format!("{existing}&{encoded}")
    }
}

pub(crate) fn xhttp_padding_referer(base_uri: &str, padding: &str) -> String {
    let base_without_query = base_uri.split_once('?').map_or(base_uri, |(base, _)| base);
    xhttp_query_in_header_padding(base_without_query, "x_padding", padding)
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

pub(crate) fn new_xhttp_session_id_for(settings: &ResidentXhttpSettingsPlan) -> String {
    if !settings.session_id_table.is_empty()
        && let Some((from, to)) = settings.session_id_length
        && from > 0
        && to >= from
    {
        let len = ResidentXhttpSettingsPlan::sample_range((from, to)) as usize;
        let table = settings.session_id_table.as_bytes();
        if !table.is_empty() {
            return (0..len)
                .map(|_| table[fastrand::usize(..table.len())] as char)
                .collect();
        }
    }
    new_xhttp_uuid_session_id()
}

fn new_xhttp_uuid_session_id() -> String {
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
        Self::new_with_reader(XhttpH1BodyReader::Client(client), headers, body_prefix)
    }

    fn new_with_read_half(
        reader: tokio::io::ReadHalf<AsyncResidentTlsClient>,
        headers: Vec<(String, String)>,
        body_prefix: Vec<u8>,
    ) -> Self {
        Self::new_with_reader(XhttpH1BodyReader::ReadHalf(reader), headers, body_prefix)
    }

    fn new_with_reader(
        reader: XhttpH1BodyReader,
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
            reader,
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

    async fn shutdown(&mut self) {
        if let XhttpH1BodyReader::Client(client) = &mut self.reader {
            let _ = client.shutdown().await;
        }
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
        let poll = match &mut self.reader {
            XhttpH1BodyReader::Client(client) => Pin::new(client).poll_read(cx, &mut read_buf),
            XhttpH1BodyReader::ReadHalf(reader) => Pin::new(reader).poll_read(cx, &mut read_buf),
        };
        match poll {
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
    xmux_lease: Option<&XhttpXmuxClientLease>,
) -> Result<h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>, String> {
    note_xhttp_xmux_request(xmux_lease);
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
    let (request, body) = xhttp_h3_packet_up_request(endpoint, session_id, seq, payload)?;
    let mut stream = time::timeout(RESIDENT_CONNECT_TIMEOUT, client.send_request(request))
        .await
        .map_err(|_| "xHTTP H3 packet-up request timeout".to_owned())?
        .map_err(|err| format!("send xHTTP H3 packet-up request: {err:?}"))?;
    if let Some(body) = body {
        time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.send_data(body))
            .await
            .map_err(|_| "send xHTTP H3 packet-up body timeout".to_owned())?
            .map_err(|err| format!("send xHTTP H3 packet-up body: {err:?}"))?;
    }
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
    let meta = XhttpRequestMeta::from_path_suffix(path_suffix);
    let method = xhttp_effective_method(method, endpoint.xhttp_settings(), has_body)?;
    xhttp_h3_request_with_parts(method, endpoint, meta, has_body, Vec::new(), Vec::new())
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
