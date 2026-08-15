use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

const ENABLE_ENV: &str = "DAE_RUN_QUIC_OWNER_EXTERNAL_LIVE";
const PROTOCOL_ENV: &str = "DAE_QUIC_OWNER_EXTERNAL_PROTOCOL";
const LINK_ENV: &str = "DAE_QUIC_OWNER_EXTERNAL_LINK";
const UDP_TARGET_ENV: &str = "DAE_QUIC_OWNER_EXTERNAL_UDP_TARGET";
const SESSION_COUNT_ENV: &str = "DAE_QUIC_OWNER_EXTERNAL_SESSIONS";
const OPERATION_TIMEOUT_ENV: &str = "DAE_QUIC_OWNER_EXTERNAL_TIMEOUT_MS";
const CONTROL_DIR_ENV: &str = "DAE_QUIC_OWNER_EXTERNAL_CONTROL_DIR";

#[derive(Clone, Copy)]
pub(super) enum QuicOwnerProtocol {
    Hysteria2,
    Tuic,
    Juicity,
}

impl QuicOwnerProtocol {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Hysteria2 => "hysteria2",
            Self::Tuic => "tuic",
            Self::Juicity => "juicity",
        }
    }
}

pub(super) struct ExternalLiveConfig {
    pub(super) protocol: QuicOwnerProtocol,
    pub(super) link: String,
    pub(super) udp_target: SocketAddr,
    pub(super) session_count: usize,
    pub(super) operation_timeout: Duration,
    pub(super) control_dir: PathBuf,
}

impl ExternalLiveConfig {
    pub(super) fn load_if_enabled() -> Result<Option<Self>, String> {
        if std::env::var_os(ENABLE_ENV).is_none() {
            return Ok(None);
        }
        let protocol = match required(PROTOCOL_ENV)?.as_str() {
            "hysteria2" => QuicOwnerProtocol::Hysteria2,
            "tuic" => QuicOwnerProtocol::Tuic,
            "juicity" => QuicOwnerProtocol::Juicity,
            _ => {
                return Err(format!(
                    "{PROTOCOL_ENV} must be hysteria2, tuic, or juicity"
                ));
            }
        };
        let link = required(LINK_ENV)?;
        let udp_target = required(UDP_TARGET_ENV)?
            .parse()
            .map_err(|_| format!("{UDP_TARGET_ENV} must be a socket address"))?;
        let session_count = positive_usize(SESSION_COUNT_ENV)?;
        let timeout_ms = positive_u64(OPERATION_TIMEOUT_ENV)?;
        let control_dir = PathBuf::from(required(CONTROL_DIR_ENV)?);
        if !control_dir.is_dir() {
            return Err(format!("{CONTROL_DIR_ENV} must name an existing directory"));
        }
        Ok(Some(Self {
            protocol,
            link,
            udp_target,
            session_count,
            operation_timeout: Duration::from_millis(timeout_ms),
            control_dir,
        }))
    }
}

fn required(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is required when {ENABLE_ENV} is set"))
}

fn positive_usize(name: &str) -> Result<usize, String> {
    let value = required(name)?
        .parse::<usize>()
        .map_err(|_| format!("{name} must be a positive integer"))?;
    if value == 0 {
        return Err(format!("{name} must be greater than zero"));
    }
    Ok(value)
}

fn positive_u64(name: &str) -> Result<u64, String> {
    let value = required(name)?
        .parse::<u64>()
        .map_err(|_| format!("{name} must be a positive integer"))?;
    if value == 0 {
        return Err(format!("{name} must be greater than zero"));
    }
    Ok(value)
}
