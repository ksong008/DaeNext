use std::collections::BTreeMap;
use std::io::{Cursor, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, ToSocketAddrs};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::Instant;

use boring::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion};
use dae_datapath::{TcpDirectDialOptions, magic_tcp_connect};
use rustls::{ClientConfig, ClientConnection, RootCertStore, pki_types::ServerName};

use super::XTLS_RPRX_VISION;
use super::plan::{ResidentProxyPlan, ResidentUtlsFingerprintPlan};
use super::{
    RESIDENT_CONNECT_TIMEOUT, RESIDENT_IDLE_SLEEP, TLS_RECORD_HEADER_LEN,
    TLS_RECORD_MAX_PAYLOAD_LEN,
};

pub(super) struct VlessTlsClient {
    engine: VlessTlsEngine,
}

enum VlessTlsEngine {
    Rustls {
        tcp: TcpStream,
        conn: ClientConnection,
        tls_records: TlsRecordReader,
    },
    Boring {
        tls: SslStream<TcpStream>,
        pending_plaintext: Vec<u8>,
    },
}

pub(super) enum TlsDriveOutcome {
    Progressed(bool),
    DecryptErrorRawRecord { record: Vec<u8>, error: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ResidentTlsClientConfigKey {
    flow: String,
    alpn: Vec<String>,
    allow_insecure: bool,
    utls_fingerprint: Option<ResidentTlsFingerprintConfigKey>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ResidentTlsFingerprintConfigKey {
    source: &'static str,
    requested: String,
    name: String,
    canonical: String,
    family: String,
    client: String,
    randomized: bool,
    alpn_policy: String,
}

static RUSTLS_CLIENT_CONFIG_CACHE: OnceLock<
    Mutex<BTreeMap<ResidentTlsClientConfigKey, Arc<ClientConfig>>>,
> = OnceLock::new();
static BORING_CONNECTOR_CACHE: OnceLock<
    Mutex<BTreeMap<ResidentTlsClientConfigKey, Arc<SslConnector>>>,
> = OnceLock::new();

#[derive(Default)]
pub(super) struct TlsRecordReader {
    header: Vec<u8>,
    body: Vec<u8>,
    body_len: Option<usize>,
}

impl VlessTlsClient {
    pub(super) fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), String> {
        self.raw_tcp_mut()
            .set_nonblocking(nonblocking)
            .map_err(|err| format!("set proxy tcp nonblocking: {err}"))
    }

    pub(super) fn queue_plain(&mut self, payload: &[u8], label: &str) -> Result<(), String> {
        match &mut self.engine {
            VlessTlsEngine::Rustls { conn, .. } => conn
                .writer()
                .write_all(payload)
                .map_err(|err| format!("{label}: {err}")),
            VlessTlsEngine::Boring {
                pending_plaintext, ..
            } => {
                pending_plaintext.extend_from_slice(payload);
                Ok(())
            }
        }
    }

    pub(super) fn read_plain(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.engine {
            VlessTlsEngine::Rustls { conn, .. } => conn.reader().read(buf),
            VlessTlsEngine::Boring { tls, .. } => tls.read(buf),
        }
    }

    pub(super) fn raw_read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.raw_tcp_mut().read(buf)
    }

    pub(super) fn raw_write_all_nonblocking(
        &mut self,
        mut payload: &[u8],
        stop: &AtomicBool,
        label: &str,
    ) -> Result<(), String> {
        while !payload.is_empty() && !stop.load(Ordering::Relaxed) {
            match self.raw_tcp_mut().write(payload) {
                Ok(0) => return Err(format!("{label}: wrote zero bytes")),
                Ok(written) => payload = &payload[written..],
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) =>
                {
                    thread::sleep(RESIDENT_IDLE_SLEEP);
                }
                Err(err) => return Err(format!("{label}: {err}")),
            }
        }
        Ok(())
    }

    pub(super) fn send_close_notify(&mut self) {
        match &mut self.engine {
            VlessTlsEngine::Rustls { conn, .. } => conn.send_close_notify(),
            VlessTlsEngine::Boring { tls, .. } => {
                let _ = tls.shutdown();
            }
        }
    }

    pub(super) fn idle_tls_complete(&self) -> bool {
        match &self.engine {
            VlessTlsEngine::Rustls { conn, .. } => !conn.wants_write() && !conn.wants_read(),
            VlessTlsEngine::Boring {
                pending_plaintext, ..
            } => pending_plaintext.is_empty(),
        }
    }

    fn raw_tcp_mut(&mut self) -> &mut TcpStream {
        match &mut self.engine {
            VlessTlsEngine::Rustls { tcp, .. } => tcp,
            VlessTlsEngine::Boring { tls, .. } => tls.get_mut(),
        }
    }
}

impl TlsRecordReader {
    fn read_one(
        &mut self,
        conn: &mut ClientConnection,
        tcp: &mut TcpStream,
    ) -> Result<TlsDriveOutcome, String> {
        let mut progressed = false;
        while self.header.len() < TLS_RECORD_HEADER_LEN {
            let mut byte = [0_u8; 1];
            match tcp.read(&mut byte) {
                Ok(0) => return Ok(TlsDriveOutcome::Progressed(progressed)),
                Ok(_) => {
                    self.header.push(byte[0]);
                    progressed = true;
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) =>
                {
                    return Ok(TlsDriveOutcome::Progressed(progressed));
                }
                Err(err) => return Err(format!("read VLESS TLS record header: {err}")),
            }
        }
        let record_type = self.header[0];
        if !matches!(record_type, 20 | 21 | 22 | 23) {
            return Err(format!(
                "unexpected VLESS TLS record type while driving proxy TLS: {record_type}"
            ));
        }
        let body_len = *self
            .body_len
            .get_or_insert_with(|| u16::from_be_bytes([self.header[3], self.header[4]]) as usize);
        if body_len > TLS_RECORD_MAX_PAYLOAD_LEN {
            return Err(format!("VLESS TLS record too large: {body_len} bytes"));
        }
        while self.body.len() < body_len {
            let need = body_len - self.body.len();
            let mut buf = [0_u8; 4096];
            let want = need.min(buf.len());
            match tcp.read(&mut buf[..want]) {
                Ok(0) => return Ok(TlsDriveOutcome::Progressed(progressed)),
                Ok(read) => {
                    self.body.extend_from_slice(&buf[..read]);
                    progressed = true;
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) =>
                {
                    return Ok(TlsDriveOutcome::Progressed(progressed));
                }
                Err(err) => return Err(format!("read VLESS TLS record body: {err}")),
            }
        }
        let mut record = Vec::with_capacity(TLS_RECORD_HEADER_LEN + body_len);
        record.extend_from_slice(&self.header);
        record.extend_from_slice(&self.body);
        let record_header_hex = hex_prefix(&record[..TLS_RECORD_HEADER_LEN], TLS_RECORD_HEADER_LEN);
        let record_body_prefix_hex = hex_prefix(&record[TLS_RECORD_HEADER_LEN..], 16.min(body_len));
        self.header.clear();
        self.body.clear();
        self.body_len = None;

        let mut cursor = Cursor::new(record.as_slice());
        conn.read_tls(&mut cursor)
            .map_err(|err| format!("feed VLESS TLS record: {err}"))?;
        match conn.process_new_packets() {
            Ok(_) => Ok(TlsDriveOutcome::Progressed(true)),
            Err(err) => Ok(TlsDriveOutcome::DecryptErrorRawRecord {
                record,
                error: format!(
                    "process VLESS TLS record: {err}; tls_record_header={record_header_hex} tls_record_body_prefix={record_body_prefix_hex}"
                ),
            }),
        }
    }
}

fn hex_prefix(bytes: &[u8], limit: usize) -> String {
    let take = bytes.len().min(limit);
    let mut out = String::with_capacity(take * 2);
    for byte in &bytes[..take] {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

pub(super) fn open_vless_tls_client(proxy: &ResidentProxyPlan) -> Result<VlessTlsClient, String> {
    let target = resolve_proxy_addr(proxy)?;
    let connected = magic_tcp_connect(
        target,
        &TcpDirectDialOptions {
            mark: proxy.mark,
            mptcp: proxy.mptcp,
            timeout: RESIDENT_CONNECT_TIMEOUT,
        },
    )
    .map_err(|err| format!("connect VLESS server {target}: {err}"))?;
    connected
        .stream
        .set_read_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set VLESS TCP read timeout: {err}"))?;
    connected
        .stream
        .set_write_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set VLESS TCP write timeout: {err}"))?;
    connected
        .stream
        .set_nodelay(true)
        .map_err(|err| format!("set VLESS TCP_NODELAY: {err}"))?;
    if proxy.utls_fingerprint.is_some() {
        open_boring_vless_tls_client(proxy, connected.stream)
    } else {
        open_rustls_vless_tls_client(proxy, connected.stream)
    }
}

fn open_rustls_vless_tls_client(
    proxy: &ResidentProxyPlan,
    tcp: TcpStream,
) -> Result<VlessTlsClient, String> {
    let config = rustls_vless_client_config(proxy)?;
    let server_name = ServerName::try_from(proxy.server_name.clone())
        .map_err(|err| format!("invalid VLESS TLS server name {}: {err}", proxy.server_name))?;
    let conn = ClientConnection::new(config, server_name)
        .map_err(|err| format!("create VLESS rustls client: {err}"))?;
    let mut client = VlessTlsClient {
        engine: VlessTlsEngine::Rustls {
            tcp,
            conn,
            tls_records: TlsRecordReader::default(),
        },
    };
    drive_tls_io_blocking(&mut client)?;
    Ok(client)
}

fn open_boring_vless_tls_client(
    proxy: &ResidentProxyPlan,
    tcp: TcpStream,
) -> Result<VlessTlsClient, String> {
    let connector = boring_vless_connector(proxy)?;
    let tls = connector
        .connect(&proxy.server_name, tcp)
        .map_err(|err| format!("connect VLESS BoringSSL client: {err}"))?;
    Ok(VlessTlsClient {
        engine: VlessTlsEngine::Boring {
            tls,
            pending_plaintext: Vec::new(),
        },
    })
}

fn boring_vless_connector(proxy: &ResidentProxyPlan) -> Result<Arc<SslConnector>, String> {
    let key = ResidentTlsClientConfigKey::from_proxy(proxy);
    let cache = BORING_CONNECTOR_CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    {
        let cache = cache
            .lock()
            .map_err(|_| "VLESS BoringSSL connector cache lock poisoned".to_owned())?;
        if let Some(connector) = cache.get(&key) {
            return Ok(Arc::clone(connector));
        }
    }
    let mut builder = SslConnector::builder(SslMethod::tls())
        .map_err(|err| format!("create VLESS BoringSSL connector: {err}"))?;
    builder.set_verify(SslVerifyMode::PEER);
    builder.set_read_ahead(false);
    if proxy.flow == XTLS_RPRX_VISION {
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|err| format!("set VLESS BoringSSL min TLS version: {err}"))?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|err| format!("set VLESS BoringSSL max TLS version: {err}"))?;
    }
    if let Some(fingerprint) = &proxy.utls_fingerprint {
        configure_boring_fingerprint(&mut builder, fingerprint)?;
    }
    let alpn = boring_alpn_wire(proxy)?;
    if !alpn.is_empty() {
        builder
            .set_alpn_protos(&alpn)
            .map_err(|err| format!("set VLESS BoringSSL ALPN: {err}"))?;
    }
    let connector = Arc::new(builder.build());
    let mut cache = cache
        .lock()
        .map_err(|_| "VLESS BoringSSL connector cache lock poisoned".to_owned())?;
    Ok(Arc::clone(
        cache.entry(key).or_insert_with(|| Arc::clone(&connector)),
    ))
}

impl ResidentTlsClientConfigKey {
    fn from_proxy(proxy: &ResidentProxyPlan) -> Self {
        Self {
            flow: proxy.flow.clone(),
            alpn: proxy.alpn.clone(),
            allow_insecure: proxy.allow_insecure,
            utls_fingerprint: proxy
                .utls_fingerprint
                .as_ref()
                .map(ResidentTlsFingerprintConfigKey::from_plan),
        }
    }
}

impl ResidentTlsFingerprintConfigKey {
    fn from_plan(plan: &ResidentUtlsFingerprintPlan) -> Self {
        Self {
            source: plan.source,
            requested: plan.requested.clone(),
            name: plan.name.clone(),
            canonical: plan.canonical.clone(),
            family: plan.family.clone(),
            client: plan.client.clone(),
            randomized: plan.randomized,
            alpn_policy: plan.alpn_policy.clone(),
        }
    }
}

fn rustls_vless_client_config(proxy: &ResidentProxyPlan) -> Result<Arc<ClientConfig>, String> {
    let key = ResidentTlsClientConfigKey::from_proxy(proxy);
    let cache = RUSTLS_CLIENT_CONFIG_CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    {
        let cache = cache
            .lock()
            .map_err(|_| "VLESS rustls client config cache lock poisoned".to_owned())?;
        if let Some(config) = cache.get(&key) {
            return Ok(Arc::clone(config));
        }
    }
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let builder = if proxy.flow == XTLS_RPRX_VISION {
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
    } else {
        ClientConfig::builder()
    };
    let mut config = builder.with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = proxy
        .alpn
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect();
    let config = Arc::new(config);
    let mut cache = cache
        .lock()
        .map_err(|_| "VLESS rustls client config cache lock poisoned".to_owned())?;
    Ok(Arc::clone(
        cache.entry(key).or_insert_with(|| Arc::clone(&config)),
    ))
}

fn configure_boring_fingerprint(
    builder: &mut boring::ssl::SslConnectorBuilder,
    fingerprint: &ResidentUtlsFingerprintPlan,
) -> Result<(), String> {
    match fingerprint.family.as_str() {
        "firefox" => {
            builder
                .set_curves_list("X25519:P-256:P-384:P-521")
                .map_err(|err| format!("set VLESS BoringSSL Firefox-style groups: {err}"))?;
        }
        "android" => {
            builder
                .set_curves_list("X25519:P-256")
                .map_err(|err| format!("set VLESS BoringSSL Android-style groups: {err}"))?;
        }
        _ => {
            builder.set_grease_enabled(true);
            builder
                .set_curves_list("X25519:P-256:P-384")
                .map_err(|err| format!("set VLESS BoringSSL browser-style groups: {err}"))?;
        }
    }

    if matches!(
        fingerprint.family.as_str(),
        "chrome" | "edge" | "random" | "360" | "qq"
    ) {
        builder.set_permute_extensions(true);
    }
    Ok(())
}

fn boring_alpn_wire(proxy: &ResidentProxyPlan) -> Result<Vec<u8>, String> {
    if proxy
        .utls_fingerprint
        .as_ref()
        .is_some_and(|fingerprint| fingerprint.alpn_policy == "force-no-alpn")
    {
        return Ok(Vec::new());
    }
    let mut protocols = proxy.alpn.clone();
    if protocols.is_empty()
        && proxy
            .utls_fingerprint
            .as_ref()
            .is_some_and(|fingerprint| fingerprint.alpn_policy == "force-alpn")
    {
        protocols.extend(["h2".to_owned(), "http/1.1".to_owned()]);
    }
    let mut out = Vec::new();
    for protocol in protocols {
        let bytes = protocol.as_bytes();
        if bytes.is_empty() {
            continue;
        }
        if bytes.len() > u8::MAX as usize {
            return Err(format!("VLESS ALPN item too long: {protocol}"));
        }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    Ok(out)
}

fn resolve_proxy_addr(proxy: &ResidentProxyPlan) -> Result<SocketAddrV4, String> {
    if let Ok(addr) = proxy.server_host.parse::<Ipv4Addr>() {
        return Ok(SocketAddrV4::new(addr, proxy.server_port));
    }
    (proxy.server_host.as_str(), proxy.server_port)
        .to_socket_addrs()
        .map_err(|err| {
            format!(
                "resolve VLESS server {}:{}: {err}",
                proxy.server_host, proxy.server_port
            )
        })?
        .find_map(|addr| match addr {
            SocketAddr::V4(addr) => Some(addr),
            SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| {
            format!(
                "resolve VLESS server {}:{} returned no IPv4 address",
                proxy.server_host, proxy.server_port
            )
        })
}

pub(super) fn drive_tls_io_record_aware(
    client: &mut VlessTlsClient,
) -> Result<TlsDriveOutcome, String> {
    match &mut client.engine {
        VlessTlsEngine::Rustls {
            tcp,
            conn,
            tls_records,
        } => {
            let mut progressed = false;
            while conn.wants_write() {
                match conn.write_tls(tcp) {
                    Ok(0) => break,
                    Ok(_) => progressed = true,
                    Err(err)
                        if matches!(
                            err.kind(),
                            ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                        ) =>
                    {
                        break;
                    }
                    Err(err) => return Err(format!("write VLESS TLS record: {err}")),
                }
            }
            if conn.wants_read() {
                match tls_records.read_one(conn, tcp)? {
                    TlsDriveOutcome::Progressed(read_progressed) => progressed |= read_progressed,
                    error @ TlsDriveOutcome::DecryptErrorRawRecord { .. } => return Ok(error),
                }
            }
            Ok(TlsDriveOutcome::Progressed(progressed))
        }
        VlessTlsEngine::Boring {
            tls,
            pending_plaintext,
        } => Ok(TlsDriveOutcome::Progressed(
            flush_boring_writes_nonblocking(tls, pending_plaintext)?,
        )),
    }
}

pub(super) fn flush_tls_writes(
    client: &mut VlessTlsClient,
    stop: &AtomicBool,
) -> Result<(), String> {
    match &mut client.engine {
        VlessTlsEngine::Rustls { tcp, conn, .. } => flush_rustls_writes(tcp, conn, stop),
        VlessTlsEngine::Boring {
            tls,
            pending_plaintext,
        } => {
            let started = Instant::now();
            while !pending_plaintext.is_empty() && !stop.load(Ordering::Relaxed) {
                match tls.write(pending_plaintext) {
                    Ok(0) => {
                        return Err("flush VLESS BoringSSL writes: wrote zero bytes".to_owned());
                    }
                    Ok(written) => {
                        pending_plaintext.drain(..written);
                    }
                    Err(err)
                        if matches!(
                            err.kind(),
                            ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                        ) =>
                    {
                        if started.elapsed() > RESIDENT_CONNECT_TIMEOUT {
                            return Err("flush VLESS BoringSSL writes timeout".to_owned());
                        }
                        thread::sleep(RESIDENT_IDLE_SLEEP);
                    }
                    Err(err) => return Err(format!("flush VLESS BoringSSL writes: {err}")),
                }
            }
            tls.flush()
                .map_err(|err| format!("flush VLESS BoringSSL stream: {err}"))
        }
    }
}

fn flush_rustls_writes(
    tcp: &mut TcpStream,
    conn: &mut ClientConnection,
    stop: &AtomicBool,
) -> Result<(), String> {
    let started = Instant::now();
    while conn.wants_write() && !stop.load(Ordering::Relaxed) {
        match conn.write_tls(tcp) {
            Ok(0) => return Err("flush VLESS TLS writes: wrote zero bytes".to_owned()),
            Ok(_) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                if started.elapsed() > RESIDENT_CONNECT_TIMEOUT {
                    return Err("flush VLESS TLS writes timeout".to_owned());
                }
                thread::sleep(RESIDENT_IDLE_SLEEP);
            }
            Err(err) => return Err(format!("flush VLESS TLS writes: {err}")),
        }
    }
    Ok(())
}

fn flush_boring_writes_nonblocking(
    tls: &mut SslStream<TcpStream>,
    pending_plaintext: &mut Vec<u8>,
) -> Result<bool, String> {
    let mut progressed = false;
    while !pending_plaintext.is_empty() {
        match tls.write(pending_plaintext) {
            Ok(0) => {
                return Err("flush VLESS BoringSSL writes: wrote zero bytes".to_owned());
            }
            Ok(written) => {
                pending_plaintext.drain(..written);
                progressed = true;
            }
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                break;
            }
            Err(err) => return Err(format!("flush VLESS BoringSSL writes: {err}")),
        }
    }
    Ok(progressed)
}

pub(super) fn drive_tls_io_blocking(client: &mut VlessTlsClient) -> Result<(), String> {
    match &mut client.engine {
        VlessTlsEngine::Rustls { tcp, conn, .. } => {
            let started = Instant::now();
            loop {
                match conn.complete_io(tcp) {
                    Ok(_) if !conn.is_handshaking() && !conn.wants_write() => return Ok(()),
                    Ok(_) => {}
                    Err(err)
                        if matches!(
                            err.kind(),
                            ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                        ) && started.elapsed() <= RESIDENT_CONNECT_TIMEOUT => {}
                    Err(err) => return Err(format!("drive VLESS TLS handshake: {err}")),
                }
                if started.elapsed() > RESIDENT_CONNECT_TIMEOUT {
                    return Err("VLESS TLS handshake timeout".to_owned());
                }
            }
        }
        VlessTlsEngine::Boring { .. } => Ok(()),
    }
}

pub(super) fn tls_underlay_name(client: &VlessTlsClient) -> &'static str {
    match &client.engine {
        VlessTlsEngine::Rustls { .. } => "rustls",
        VlessTlsEngine::Boring { .. } => "boringssl",
    }
}
