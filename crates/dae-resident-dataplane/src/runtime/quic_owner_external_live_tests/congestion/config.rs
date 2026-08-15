use std::net::SocketAddr;
use std::time::Duration;

const ENABLE_ENV: &str = "DAE_RUN_HY2_CONGESTION_EXTERNAL";
const LINK_ENV: &str = "DAE_HY2_CONGESTION_LINK";
const TCP_TARGET_ENV: &str = "DAE_HY2_CONGESTION_TCP_TARGET";
const UDP_TARGET_ENV: &str = "DAE_HY2_CONGESTION_UDP_TARGET";
const UPLOAD_BYTES_ENV: &str = "DAE_HY2_CONGESTION_UPLOAD_BYTES";
const UDP_SAMPLES_ENV: &str = "DAE_HY2_CONGESTION_UDP_SAMPLES";
const UDP_PAYLOAD_BYTES_ENV: &str = "DAE_HY2_CONGESTION_UDP_PAYLOAD_BYTES";
const UDP_SAMPLE_TIMEOUT_MS_ENV: &str = "DAE_HY2_CONGESTION_UDP_SAMPLE_TIMEOUT_MS";
const OPERATION_TIMEOUT_MS_ENV: &str = "DAE_HY2_CONGESTION_OPERATION_TIMEOUT_MS";
const PROFILE_ENV: &str = "DAE_HY2_CONGESTION_PROFILE";
const MAX_UPLOAD_BYTES: usize = 512 * 1024 * 1024;
const MAX_UDP_SAMPLES: usize = 10_000;

pub(super) struct CongestionBenchmarkConfig {
    pub(super) link: String,
    pub(super) tcp_target: SocketAddr,
    pub(super) udp_target: SocketAddr,
    pub(super) upload_bytes: usize,
    pub(super) udp_samples: usize,
    pub(super) udp_payload_bytes: usize,
    pub(super) udp_sample_timeout: Duration,
    pub(super) operation_timeout: Duration,
    pub(super) profile: String,
}

impl CongestionBenchmarkConfig {
    pub(super) fn load_if_enabled() -> Result<Option<Self>, String> {
        if std::env::var_os(ENABLE_ENV).is_none() {
            return Ok(None);
        }
        let profile = required(PROFILE_ENV)?;
        if profile.is_empty()
            || profile.len() > 32
            || !profile
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(format!(
                "{PROFILE_ENV} must contain 1-32 ASCII letters, digits, dashes, or underscores"
            ));
        }
        let upload_bytes = bounded_usize(UPLOAD_BYTES_ENV, 1, MAX_UPLOAD_BYTES)?;
        let udp_samples = bounded_usize(UDP_SAMPLES_ENV, 1, MAX_UDP_SAMPLES)?;
        let udp_payload_bytes = bounded_usize(
            UDP_PAYLOAD_BYTES_ENV,
            std::mem::size_of::<u64>(),
            dae_outbound::hysteria2::HYSTERIA2_MAX_UDP_PAYLOAD_LENGTH,
        )?;
        Ok(Some(Self {
            link: required(LINK_ENV)?,
            tcp_target: socket_addr(TCP_TARGET_ENV)?,
            udp_target: socket_addr(UDP_TARGET_ENV)?,
            upload_bytes,
            udp_samples,
            udp_payload_bytes,
            udp_sample_timeout: Duration::from_millis(positive_u64(UDP_SAMPLE_TIMEOUT_MS_ENV)?),
            operation_timeout: Duration::from_millis(positive_u64(OPERATION_TIMEOUT_MS_ENV)?),
            profile,
        }))
    }
}

fn required(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is required when {ENABLE_ENV} is set"))
}

fn socket_addr(name: &str) -> Result<SocketAddr, String> {
    required(name)?
        .parse()
        .map_err(|_| format!("{name} must be a socket address"))
}

fn bounded_usize(name: &str, minimum: usize, maximum: usize) -> Result<usize, String> {
    let value = required(name)?
        .parse::<usize>()
        .map_err(|_| format!("{name} must be an integer"))?;
    if !(minimum..=maximum).contains(&value) {
        return Err(format!("{name} must be in {minimum}..={maximum}"));
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
