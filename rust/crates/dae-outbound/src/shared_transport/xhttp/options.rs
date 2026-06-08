use crate::error::OutboundError;
use crate::shared_transport::ir;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XHttpXmuxOptions {
    pub max_connections: u32,
    pub c_max_reuse_times: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XHttpLifecycleOptions {
    pub host: String,
    pub path: String,
    pub mode: String,
    pub security: String,
    pub alpn: String,
    pub session_id: String,
    pub seq: u64,
    pub xmux: Option<XHttpXmuxOptions>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XHttpLifecycleReport {
    pub transport: &'static str,
    pub host: String,
    pub path: String,
    pub mode: String,
    pub alpn: String,
    pub use_h3: bool,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub lifecycle_harness: bool,
    pub full_h2_h3_stack: bool,
    pub default_go_path: bool,
}

impl XHttpLifecycleOptions {
    pub fn new(
        host: impl Into<String>,
        path: impl Into<String>,
        mode: impl Into<String>,
        security: impl Into<String>,
        alpn: impl Into<String>,
        session_id: impl Into<String>,
        seq: u64,
    ) -> Result<Self, OutboundError> {
        let security = security.into();
        let alpn = alpn.into();
        let mode = mode.into();
        let mode_result = ir::normalize_xhttp_mode(&mode, "https", &security, false);
        if !mode_result.ok {
            return Err(OutboundError::BadSharedTransport(
                mode_result.error_contains,
            ));
        }
        let alpn_result = ir::validate_xhttp_alpn(&security, &alpn);
        if !alpn_result.ok {
            return Err(OutboundError::BadSharedTransport(
                alpn_result.error_contains,
            ));
        }
        Ok(Self {
            host: host.into(),
            path: path.into(),
            mode: mode_result.normalized,
            security,
            alpn,
            session_id: session_id.into(),
            seq,
            xmux: None,
        })
    }

    pub fn with_xmux(mut self, xmux: XHttpXmuxOptions) -> Self {
        self.xmux = Some(xmux);
        self
    }
}

impl XHttpXmuxOptions {
    pub fn new(max_connections: u32, c_max_reuse_times: u32) -> Result<Self, OutboundError> {
        if max_connections == 0 {
            return Err(OutboundError::BadSharedTransport(
                "xhttp xmux maxConnections must be greater than zero".to_owned(),
            ));
        }
        if c_max_reuse_times == 0 {
            return Err(OutboundError::BadSharedTransport(
                "xhttp xmux cMaxReuseTimes must be greater than zero".to_owned(),
            ));
        }
        Ok(Self {
            max_connections,
            c_max_reuse_times,
        })
    }
}
