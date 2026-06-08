#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoaderOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl LoaderOutput {
    fn ok(stdout: String) -> Self {
        Self {
            stdout,
            stderr: String::new(),
            exit_code: 0,
        }
    }

    fn usage(message: impl Into<String>) -> Self {
        Self {
            stdout: String::new(),
            stderr: format!("{}\n", message.into()),
            exit_code: 2,
        }
    }

    fn error(message: impl Into<String>) -> Self {
        Self {
            stdout: String::new(),
            stderr: format!("{}\n", message.into()),
            exit_code: 1,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BpfLoaderLoadPinOptions {
    object: Option<PathBuf>,
    object_source: Option<BpfObjectSource>,
    pin_root: PathBuf,
    tproxy_port: u16,
    control_plane_pid: u32,
    dae0_ifindex: u32,
    dae_netns_id: u32,
    dae0peer_mac: [u8; 6],
    has_bpf_get_current_task: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BpfObjectSource {
    CAya,
    RustAyaSkeleton,
}

impl BpfObjectSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CAya => "c-aya",
            Self::RustAyaSkeleton => "rust-aya-skeleton",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
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
struct MapStatsCountRequest {
    name: String,
    id: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TraceLoaderLoadPinOptions {
    object: PathBuf,
    pin_root: PathBuf,
    ip_version: u8,
    l4_proto: u16,
    port: u16,
    ringbuf_size: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TraceLoaderAttachSmokeTrigger {
    LoopbackUdp,
    OpenProcSelfStat,
}

impl TraceLoaderAttachSmokeTrigger {
    fn parse(value: &str) -> Result<Self, String> {
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
struct TraceLoaderAttachRingbufSmokeOptions {
    object: PathBuf,
    target: String,
    program_name: String,
    ip_version: u8,
    l4_proto: u16,
    port: u16,
    ringbuf_size: u32,
    trigger: TraceLoaderAttachSmokeTrigger,
    trigger_count: u32,
    poll_attempts: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConnectivityMapUpdateOptions {
    map_id: u32,
    outbound: u8,
    l4_proto: u8,
    ip_version: u8,
    alive: bool,
    is_init: bool,
    dryrun: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CgroupMonitorAttachPinOptions {
    program_root: PathBuf,
    link_root: PathBuf,
    cgroup_path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TcAttachPinOptions {
    program_root: PathBuf,
    link_root: PathBuf,
    program_name: String,
    iface: String,
    netns: Option<String>,
    direction: dae_ebpf_support::TcAttachDirection,
    priority: u16,
    handle: u32,
    backend: dae_ebpf_support::AttachBackend,
    filter_name: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TproxyListenerOpenHandoffOptions {
    map_id: u32,
    port: u16,
    handoff_fd: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TproxyListenerUpdateMapOptions {
    map_id: u32,
    tcp_fd: i32,
    udp_fd: i32,
}
