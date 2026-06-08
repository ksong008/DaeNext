use super::*;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoaderOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl LoaderOutput {
    pub(super) fn ok(stdout: String) -> Self {
        Self {
            stdout,
            stderr: String::new(),
            exit_code: 0,
        }
    }

    pub(super) fn usage(message: impl Into<String>) -> Self {
        Self {
            stdout: String::new(),
            stderr: format!("{}\n", message.into()),
            exit_code: 2,
        }
    }

    pub(super) fn error(message: impl Into<String>) -> Self {
        Self {
            stdout: String::new(),
            stderr: format!("{}\n", message.into()),
            exit_code: 1,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct BpfLoaderLoadPinOptions {
    pub(super) object: Option<PathBuf>,
    pub(super) object_source: Option<BpfObjectSource>,
    pub(super) pin_root: PathBuf,
    pub(super) tproxy_port: u16,
    pub(super) control_plane_pid: u32,
    pub(super) dae0_ifindex: u32,
    pub(super) dae_netns_id: u32,
    pub(super) dae0peer_mac: [u8; 6],
    pub(super) has_bpf_get_current_task: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BpfObjectSource {
    CAya,
    RustAyaSkeleton,
}

impl BpfObjectSource {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::CAya => "c-aya",
            Self::RustAyaSkeleton => "rust-aya-skeleton",
        }
    }

    pub(super) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "c-aya" => Ok(Self::CAya),
            "rust-aya-skeleton" => Ok(Self::RustAyaSkeleton),
            _ => Err(format!(
                "unsupported bpf-loader object source: {value}; want c-aya or rust-aya-skeleton"
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct MapStatsCountRequest {
    pub(super) name: String,
    pub(super) id: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TraceLoaderLoadPinOptions {
    pub(super) object: PathBuf,
    pub(super) pin_root: PathBuf,
    pub(super) ip_version: u8,
    pub(super) l4_proto: u16,
    pub(super) port: u16,
    pub(super) ringbuf_size: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TraceLoaderAttachSmokeTrigger {
    LoopbackUdp,
    OpenProcSelfStat,
}

impl TraceLoaderAttachSmokeTrigger {
    pub(super) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "loopback-udp" => Ok(Self::LoopbackUdp),
            "open-proc-self-stat" => Ok(Self::OpenProcSelfStat),
            _ => Err(format!(
                "bad trace attach smoke trigger: {value}; want loopback-udp or open-proc-self-stat"
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TraceLoaderAttachRingbufSmokeOptions {
    pub(super) object: PathBuf,
    pub(super) target: String,
    pub(super) program_name: String,
    pub(super) ip_version: u8,
    pub(super) l4_proto: u16,
    pub(super) port: u16,
    pub(super) ringbuf_size: u32,
    pub(super) trigger: TraceLoaderAttachSmokeTrigger,
    pub(super) trigger_count: u32,
    pub(super) poll_attempts: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ConnectivityMapUpdateOptions {
    pub(super) map_id: u32,
    pub(super) outbound: u8,
    pub(super) l4_proto: u8,
    pub(super) ip_version: u8,
    pub(super) alive: bool,
    pub(super) is_init: bool,
    pub(super) dryrun: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CgroupMonitorAttachPinOptions {
    pub(super) program_root: PathBuf,
    pub(super) link_root: PathBuf,
    pub(super) cgroup_path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TcAttachPinOptions {
    pub(super) program_root: PathBuf,
    pub(super) link_root: PathBuf,
    pub(super) program_name: String,
    pub(super) iface: String,
    pub(super) netns: Option<String>,
    pub(super) direction: dae_ebpf_support::TcAttachDirection,
    pub(super) priority: u16,
    pub(super) handle: u32,
    pub(super) backend: dae_ebpf_support::AttachBackend,
    pub(super) filter_name: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TproxyListenerOpenHandoffOptions {
    pub(super) map_id: u32,
    pub(super) port: u16,
    pub(super) handoff_fd: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TproxyListenerUpdateMapOptions {
    pub(super) map_id: u32,
    pub(super) tcp_fd: i32,
    pub(super) udp_fd: i32,
}
