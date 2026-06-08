use super::*;
pub(crate) struct VlessTlsClient {
    pub(super) engine: VlessTlsEngine,
}

pub(crate) struct AsyncVlessTlsClient {
    pub(super) engine: AsyncVlessTlsEngine,
}

pub(crate) type AsyncResidentTlsClient = AsyncVlessTlsClient;

pub(crate) enum VlessTlsEngine {
    Rustls {
        tcp: ResidentTcpStream,
        conn: ClientConnection,
        tls_records: TlsRecordReader,
    },
    RealityRustls {
        tcp: ResidentTcpStream,
        conn: ClientConnection,
        tls_records: TlsRecordReader,
    },
    Boring {
        tls: SslStream<TcpStream>,
        pending_plaintext: Vec<u8>,
    },
}

pub(crate) enum AsyncVlessTlsEngine {
    Rustls {
        tls: tokio_rustls::client::TlsStream<AsyncResidentTcpStream>,
    },
    RealityRustls {
        tls: tokio_rustls::client::TlsStream<AsyncResidentTcpStream>,
    },
    Boring {
        tls: tokio_boring::SslStream<TokioTcpStream>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResidentTlsProvider {
    StandardRustls,
    RealityRustls,
    FingerprintAwareBoring,
}

impl ResidentTlsProvider {
    pub(super) fn from_proxy(proxy: &ResidentProxyPlan) -> Result<Self, String> {
        match proxy.tls.as_str() {
            "tls" => {
                if proxy.utls_fingerprint.is_some() {
                    Ok(Self::FingerprintAwareBoring)
                } else {
                    Ok(Self::StandardRustls)
                }
            }
            "reality" => Ok(Self::RealityRustls),
            other => Err(format!(
                "resident TLS factory cannot open security underlay {other} for protocol {}",
                proxy.protocol
            )),
        }
    }
}

pub(crate) enum TlsDriveOutcome {
    Progressed(bool),
    DecryptErrorRawRecord { record: Vec<u8>, error: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct ResidentTlsClientConfigKey {
    pub(super) flow: String,
    pub(super) alpn: Vec<String>,
    pub(super) allow_insecure: bool,
    pub(super) utls_fingerprint: Option<ResidentTlsFingerprintConfigKey>,
    pub(super) reality: Option<ResidentRealityConfigKey>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct ResidentTlsFingerprintConfigKey {
    pub(super) source: &'static str,
    pub(super) requested: String,
    pub(super) name: String,
    pub(super) canonical: String,
    pub(super) family: String,
    pub(super) client: String,
    pub(super) randomized: bool,
    pub(super) alpn_policy: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct ResidentRealityConfigKey {
    pub(super) public_key: [u8; 32],
    pub(super) short_id: Vec<u8>,
}

pub(crate) static RUSTLS_CLIENT_CONFIG_CACHE: OnceLock<
    Mutex<BTreeMap<ResidentTlsClientConfigKey, Arc<ClientConfig>>>,
> = OnceLock::new();
pub(crate) static BORING_CONNECTOR_CACHE: OnceLock<
    Mutex<BTreeMap<ResidentTlsClientConfigKey, Arc<SslConnector>>>,
> = OnceLock::new();

#[derive(Default)]
pub(crate) struct TlsRecordReader {
    pub(super) header: Vec<u8>,
    pub(super) body: Vec<u8>,
    pub(super) body_len: Option<usize>,
}
