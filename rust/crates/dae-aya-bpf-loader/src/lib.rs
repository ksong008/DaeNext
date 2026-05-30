use std::io::{self, BufRead, Read, Write};
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use serde_json::{Value, json};

#[cfg(feature = "native-ebpf")]
const EMBEDDED_NATIVE_AYA_OBJECT: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/dae-native-bpf_bpfel.o"));

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

pub fn run_with_args(args: impl IntoIterator<Item = impl Into<String>>) -> LoaderOutput {
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("bpf-loader") => run_bpf_loader_command(&args[1..]),
        Some("cgroup-monitor") => run_cgroup_monitor_command(&args[1..]),
        Some("map-stats") => run_map_stats_command(&args[1..]),
        Some("connectivity-map") => run_connectivity_map_command(&args[1..]),
        Some("domain-routing-map") => run_domain_routing_map_command(&args[1..]),
        Some("routing-map") => run_routing_map_command(&args[1..]),
        Some("tc-attach") => run_tc_attach_command(&args[1..]),
        Some("tproxy-listener") => run_tproxy_listener_command(&args[1..]),
        Some("trace-loader") => run_trace_loader_command(&args[1..]),
        Some("contract") if args.len() == 1 => run_contract(),
        Some("load-pin") => run_load_pin_command(&args[1..]),
        Some(command) => {
            LoaderOutput::usage(format!("unsupported dae-aya-bpf-loader command: {command}"))
        }
        None => LoaderOutput::usage("missing dae-aya-bpf-loader command"),
    }
}

fn run_cgroup_monitor_command(args: &[String]) -> LoaderOutput {
    match args.first().map(String::as_str) {
        Some("contract") if args.len() == 1 => run_cgroup_monitor_contract(),
        Some("attach-pin") => match parse_cgroup_monitor_attach_pin_options(&args[1..]) {
            Ok(options) => run_cgroup_monitor_attach_pin(options),
            Err(err) => LoaderOutput::usage(err),
        },
        Some(subcommand) => LoaderOutput::usage(format!(
            "unsupported cgroup-monitor subcommand: {subcommand}"
        )),
        None => LoaderOutput::usage("missing cgroup-monitor subcommand"),
    }
}

fn run_connectivity_map_command(args: &[String]) -> LoaderOutput {
    match args.first().map(String::as_str) {
        Some("update") => match parse_connectivity_map_update_options(&args[1..]) {
            Ok(options) => run_connectivity_map_update(options),
            Err(err) => LoaderOutput::usage(err),
        },
        Some("serve") if args.len() == 1 => LoaderOutput::usage(
            "connectivity-map serve requires the dae-aya-bpf-loader stdio entrypoint",
        ),
        Some(subcommand) => LoaderOutput::usage(format!(
            "unsupported connectivity-map subcommand: {subcommand}"
        )),
        None => LoaderOutput::usage("missing connectivity-map subcommand"),
    }
}

fn run_domain_routing_map_command(args: &[String]) -> LoaderOutput {
    match args.first().map(String::as_str) {
        Some("apply") if args.len() == 1 => LoaderOutput::usage(
            "domain-routing-map apply requires the dae-aya-bpf-loader stdio entrypoint",
        ),
        Some("serve") if args.len() == 1 => LoaderOutput::usage(
            "domain-routing-map serve requires the dae-aya-bpf-loader stdio entrypoint",
        ),
        Some(subcommand) => LoaderOutput::usage(format!(
            "unsupported domain-routing-map subcommand: {subcommand}"
        )),
        None => LoaderOutput::usage("missing domain-routing-map subcommand"),
    }
}

fn run_routing_map_command(args: &[String]) -> LoaderOutput {
    match args.first().map(String::as_str) {
        Some("apply") if args.len() == 1 => LoaderOutput::usage(
            "routing-map apply requires the dae-aya-bpf-loader stdio entrypoint",
        ),
        Some(subcommand) => {
            LoaderOutput::usage(format!("unsupported routing-map subcommand: {subcommand}"))
        }
        None => LoaderOutput::usage("missing routing-map subcommand"),
    }
}

fn run_tc_attach_command(args: &[String]) -> LoaderOutput {
    match args.first().map(String::as_str) {
        Some("contract") if args.len() == 1 => run_tc_attach_contract(),
        Some("attach-pin") => match parse_tc_attach_pin_options(&args[1..]) {
            Ok(options) => run_tc_attach_pin(options),
            Err(err) => LoaderOutput::usage(err),
        },
        Some(subcommand) => {
            LoaderOutput::usage(format!("unsupported tc-attach subcommand: {subcommand}"))
        }
        None => LoaderOutput::usage("missing tc-attach subcommand"),
    }
}

fn run_tproxy_listener_command(args: &[String]) -> LoaderOutput {
    match args.first().map(String::as_str) {
        Some("contract") if args.len() == 1 => run_tproxy_listener_contract(),
        Some("open-handoff") => match parse_tproxy_listener_open_handoff_options(&args[1..]) {
            Ok(options) => run_tproxy_listener_open_handoff(options),
            Err(err) => LoaderOutput::usage(err),
        },
        Some("update-map") => match parse_tproxy_listener_update_map_options(&args[1..]) {
            Ok(options) => run_tproxy_listener_update_map(options),
            Err(err) => LoaderOutput::usage(err),
        },
        Some(subcommand) => LoaderOutput::usage(format!(
            "unsupported tproxy-listener subcommand: {subcommand}"
        )),
        None => LoaderOutput::usage("missing tproxy-listener subcommand"),
    }
}

pub fn run_bpf_loader_command(args: &[String]) -> LoaderOutput {
    match args.first().map(String::as_str) {
        Some("contract") if args.len() == 1 => run_contract(),
        Some("load-pin") => run_load_pin_command(&args[1..]),
        Some(subcommand) => {
            LoaderOutput::usage(format!("unsupported bpf-loader subcommand: {subcommand}"))
        }
        None => LoaderOutput::usage("missing bpf-loader subcommand"),
    }
}

fn run_map_stats_command(args: &[String]) -> LoaderOutput {
    match args.first().map(String::as_str) {
        Some("count") => match parse_map_stats_count_options(&args[1..]) {
            Ok(requests) => run_map_stats_count(requests),
            Err(err) => LoaderOutput::usage(err),
        },
        Some(subcommand) => {
            LoaderOutput::usage(format!("unsupported map-stats subcommand: {subcommand}"))
        }
        None => LoaderOutput::usage("missing map-stats subcommand"),
    }
}

fn run_trace_loader_command(args: &[String]) -> LoaderOutput {
    match args.first().map(String::as_str) {
        Some("contract") if args.len() == 1 => run_trace_loader_contract(),
        Some("load-pin") => match parse_trace_load_pin_options(&args[1..]) {
            Ok(options) => run_trace_load_pin(options),
            Err(err) => LoaderOutput::usage(err),
        },
        Some("attach-ringbuf-smoke") => {
            match parse_trace_attach_ringbuf_smoke_options(&args[1..]) {
                Ok(options) => run_trace_attach_ringbuf_smoke(options),
                Err(err) => LoaderOutput::usage(err),
            }
        }
        Some(subcommand) => {
            LoaderOutput::usage(format!("unsupported trace-loader subcommand: {subcommand}"))
        }
        None => LoaderOutput::usage("missing trace-loader subcommand"),
    }
}

fn run_contract() -> LoaderOutput {
    let tc_matrix =
        dae_ebpf_support::dae_tc_attach_matrix(dae_ebpf_support::DaeTcAttachMatrixInput {
            object: "runtime-pinned-program".to_owned(),
            lan_iface: "lan".to_owned(),
            wan_iface: "wan".to_owned(),
            host_iface: "dae0".to_owned(),
            peer_iface: "dae0peer".to_owned(),
            peer_netns: "daens".to_owned(),
            section_prefix: dae_ebpf_support::TcAttachSectionPrefix::Classifier,
            link_layer: dae_ebpf_support::TcAttachLayer::L2,
            flip: 0,
            is_reload: false,
        });
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "name": "rust-aya-bpf-loader-go-adoption-contract-v1",
            "binary": "dae-aya-bpf-loader",
            "compiled_native_ebpf": cfg!(feature = "native-ebpf"),
            "scope": "Rust/Aya loads a selected daemon eBPF object and pins all maps/programs for Go control-plane adoption",
            "go_userspace_outbound_remains_authoritative": true,
            "go_bpf_loader_removed_when_opted_in": true,
            "kernel_ebpf_program_rewrite": false,
            "rust_aya_skeleton_object_supported": true,
            "default_object_source": BpfObjectSource::CAya.as_str(),
            "supported_object_sources": [
                BpfObjectSource::CAya.as_str(),
                BpfObjectSource::RustAyaSkeleton.as_str(),
            ],
            "required_pins": {
                "maps": "pin_root/maps/<map_name>",
                "programs": "pin_root/programs/<program_name>"
            },
            "object_source": {
                "c-aya": "default embedded native Aya object built from control/kern/tproxy.c with DAE_AYA_EBPF_OBJECT, or explicit --object",
                "rust-aya-skeleton": "legacy option name for an explicit --object built from rust/crates/dae-ebpf-program; opt-in Rust/Aya native object candidate, not default without admission"
            },
            "param_source": {
                "tproxy_port": "host-order u16, converted to BPF big-endian PARAM",
                "control_plane_pid": "Go control-plane pid",
                "dae0_ifindex": "initialized dae0 ifindex",
                "dae_netns_id": "initialized dae netns id",
                "dae0peer_mac": "initialized dae0peer mac",
                "has_bpf_get_current_task": "Go feature probe result"
            },
            "maps": dae_ebpf_support::map_catalog().iter().map(|spec| json!({
                "name": spec.name,
                "type": spec.map_type,
                "key_size": spec.key_size,
                "value_size": spec.value_size,
                "max_entries": spec.max_entries,
                "flags": spec.flags,
                "pinning": spec.pinning,
                "role": format!("{:?}", spec.role()),
            })).collect::<Vec<_>>(),
            "tc_programs": tc_matrix.iter().map(|line| json!({
                "role": line.role.as_str(),
                "section": line.native.section,
                "program_name": line.native.program_name,
                "direction": line.native.target.direction.as_str(),
                "priority": line.native.priority,
                "handle": line.native.handle,
                "tcx_order": line.native.tcx_order.as_str(),
            })).collect::<Vec<_>>(),
            "cgroup_programs": dae_ebpf_support::dae_cgroup_attach_matrix().iter().map(|line| json!({
                "role": line.role.section_tail(),
                "section": line.section,
                "program_name": line.program_name,
                "bpf_attach_type": line.role.bpf_attach_type(),
                "aya_program_kind": line.aya_program_kind.as_str(),
            })).collect::<Vec<_>>(),
            "listener_smoke": "listen_socket_map key 0/1 remains updated by tproxy-listener helper; Rust skeleton only preserves map ABI",
            "routing_smoke": "routing-map/domain-routing-map helpers remain userspace-owned; Rust skeleton only preserves map ABI",
        })
    ))
}

fn run_cgroup_monitor_contract() -> LoaderOutput {
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "name": "rust-cgroup-pname-monitor-attach-contract-v1",
            "binary": "dae-aya-bpf-loader",
            "scope": "Rust attaches pinned cgroup pname monitor programs and pins bpf_link objects for Go control-plane lifetime ownership",
            "go_pname_routing_semantics_remain_authoritative": true,
            "kernel_ebpf_program_rewrite": false,
            "link_lifetime": "pinned under --link-root; Go control-plane removes the pin root on close/reload cleanup",
            "program_source": "--program-root/<program_name> from Rust/Aya-loaded pinned programs",
            "cgroup_source": "--cgroup-path, normally the first cgroup2 mount from /proc/mounts",
            "attach_matrix": dae_ebpf_support::dae_cgroup_attach_matrix().iter().map(|line| json!({
                "role": line.role.section_tail(),
                "section": line.section,
                "program_name": line.program_name,
                "go_attach_type": line.go_attach_type,
                "bpf_attach_type": line.role.bpf_attach_type(),
                "aya_program_kind": line.aya_program_kind.as_str(),
                "attach_mode": line.attach_mode,
            })).collect::<Vec<_>>(),
        })
    ))
}

fn run_tc_attach_contract() -> LoaderOutput {
    let matrix = dae_ebpf_support::dae_tc_attach_matrix(dae_ebpf_support::DaeTcAttachMatrixInput {
        object: "runtime-pinned-program".to_owned(),
        lan_iface: "lan".to_owned(),
        wan_iface: "wan".to_owned(),
        host_iface: "dae0".to_owned(),
        peer_iface: "dae0peer".to_owned(),
        peer_netns: "daens".to_owned(),
        section_prefix: dae_ebpf_support::TcAttachSectionPrefix::Tc,
        link_layer: dae_ebpf_support::TcAttachLayer::L2,
        flip: 0,
        is_reload: false,
    });
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "name": "rust-tc-tcx-attach-pin-contract-v1",
            "binary": "dae-aya-bpf-loader",
            "scope": "Rust/Aya attaches pinned TC sched classifier programs for LAN/WAN/dae0/dae0peer and pins TCX bpf_link lifetime for Go control-plane cleanup",
            "go_userspace_outbound_remains_authoritative": true,
            "go_routing_dns_sniff_group_remain_authoritative": true,
            "kernel_ebpf_program_rewrite": false,
            "backend": "auto attempts tcx first and falls back to tc_netlink; explicit tcx is strict; explicit tc/tc_netlink uses tc_netlink",
            "link_lifetime": {
                "tcx": "pinned under --link-root/link; Go control-plane removes link root on close/reload cleanup",
                "tc_netlink": "persistent kernel filter; Go control-plane deletes by priority/handle/name on close/reload cleanup"
            },
            "attach_matrix": matrix.iter().map(|line| json!({
                "role": line.role.as_str(),
                "filter_name": line.go_filter_name,
                "program_name": line.native.program_name,
                "direction": line.native.target.direction.as_str(),
                "priority": line.native.priority,
                "handle": line.native.handle,
                "tcx_order": line.native.tcx_order.as_str(),
                "netns": line.native.target.netns,
            })).collect::<Vec<_>>(),
        })
    ))
}

fn run_tproxy_listener_contract() -> LoaderOutput {
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "name": "rust-tproxy-listener-sockmap-handoff-contract-v1",
            "binary": "dae-aya-bpf-loader",
            "scope": "Rust opens TCP/UDP tproxy listeners in the caller netns, writes listen_socket_map key 0/1, and hands listener fds back to Go userspace handlers",
            "go_userspace_tcp_udp_handlers_remain_authoritative": true,
            "go_routing_dns_sniff_group_outbound_remain_authoritative": true,
            "kernel_ebpf_program_rewrite": false,
            "listen_socket_map": {
                "key_0": "tcp listener fd",
                "key_1": "udp socket fd",
                "map_type": "BPF_MAP_TYPE_SOCKMAP",
                "max_entries": 2
            },
            "socket_options": {
                "ip_transparent": true,
                "so_reuseaddr": true,
                "ip_recvorigdstaddr_or_ipv6_recvorigdstaddr": true
            },
            "handoff": "open-handoff sends TCP/UDP listener fds over SCM_RIGHTS; update-map accepts inherited fds for reload listener reuse",
            "fallback": "Go listener open and Go listen_socket_map update remain available when the helper fails",
        })
    ))
}

fn run_cgroup_monitor_attach_pin(options: CgroupMonitorAttachPinOptions) -> LoaderOutput {
    let reports = match dae_ebpf_support::attach_pin_cgroup_monitor(
        dae_ebpf_support::PinnedCgroupAttachOptions {
            program_root: &options.program_root,
            link_root: &options.link_root,
            cgroup_path: &options.cgroup_path,
        },
    ) {
        Ok(reports) => reports,
        Err(err) => return LoaderOutput::error(format!("cgroup monitor attach-pin failed: {err}")),
    };
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "status": "pass",
            "loader": "rust",
            "scope": "cgroup-pname-monitor-attach-pin",
            "program_root": options.program_root,
            "link_root": options.link_root,
            "cgroup_path": options.cgroup_path,
            "links": reports.iter().map(|report| json!({
                "role": report.role.section_tail(),
                "program_name": report.program_name,
                "program_path": report.program_path,
                "link_path": report.link_path,
                "section": report.section,
                "attach_type": report.attach_type,
                "attach_mode": report.attach_mode,
                "attached": report.attached,
                "pinned": report.pinned,
            })).collect::<Vec<_>>(),
        })
    ))
}

#[cfg(feature = "native-ebpf")]
fn run_tc_attach_pin(options: TcAttachPinOptions) -> LoaderOutput {
    let spec = dae_ebpf_support::TcNativeAttachSpec {
        target: dae_ebpf_support::TcAttachTarget {
            iface: options.iface.clone(),
            netns: options.netns.clone(),
            direction: options.direction,
        },
        object: "runtime-pinned-program".to_owned(),
        section: options.program_name.clone(),
        program_name: options.program_name.clone(),
        priority: options.priority,
        handle: options.handle,
        tcx_order: dae_ebpf_support::TcxAttachOrder::from_go_tc_priority(options.priority),
        protocol: dae_ebpf_support::ETH_P_ALL,
        direct_action: true,
        clsact_required: true,
        netns_enter_required: options.netns.is_some(),
        link_lifetime_owned_by_backend: true,
    };
    let report = match dae_ebpf_support::attach_pin_aya_sched_classifier(
        dae_ebpf_support::PinnedTcAttachOptions {
            program_root: &options.program_root,
            link_root: &options.link_root,
            spec: &spec,
            requested_backend: options.backend,
        },
    ) {
        Ok(report) => report,
        Err(err) => return LoaderOutput::error(format!("tc attach-pin failed: {err}")),
    };
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "status": "pass",
            "loader": "rust-aya",
            "scope": "tc-tcx-attach-pin",
            "program_root": options.program_root,
            "link_root": options.link_root,
            "filter_name": options.filter_name,
            "requested_backend": report.requested_backend.as_str(),
            "backend": report.backend.as_str(),
            "fallback_used": report.fallback_used,
            "fallback_error": report.fallback_error,
            "program_id": report.program_id,
            "program_name": report.program_name,
            "program_path": report.program_path,
            "iface": report.iface,
            "netns": report.netns,
            "netns_entered": report.netns_entered,
            "direction": report.direction.as_str(),
            "priority": report.priority,
            "handle": report.handle,
            "tcx_order": report.tcx_order.as_str(),
            "tcx_query_revision": report.tcx_query_revision,
            "tcx_order_verified": report.tcx_order_verified,
            "tcx_program_order": report.tcx_program_order.iter().map(|entry| json!({
                "id": entry.id,
                "name": entry.name,
                "tag": entry.tag,
            })).collect::<Vec<_>>(),
            "link_path": report.link_path,
            "tc_filter_persistent": report.tc_filter_persistent,
            "clsact_added_or_present": report.clsact_added_or_present,
        })
    ))
}

#[cfg(not(feature = "native-ebpf"))]
fn run_tc_attach_pin(_options: TcAttachPinOptions) -> LoaderOutput {
    LoaderOutput::error("tc-attach attach-pin requires dae-aya-bpf-loader feature native-ebpf")
}

fn run_tproxy_listener_open_handoff(options: TproxyListenerOpenHandoffOptions) -> LoaderOutput {
    let handoff = match dae_ebpf_support::open_tproxy_listener_set_and_update_sockmap_by_id(
        options.map_id,
        options.port,
    ) {
        Ok(handoff) => handoff,
        Err(err) => {
            return LoaderOutput::error(format!("tproxy listener open-handoff failed: {err}"));
        }
    };
    let payload = json!({
        "status": "pass",
        "loader": "rust",
        "scope": "tproxy-listener-open-handoff",
        "map_id": handoff.map.id,
        "map_name": handoff.map.name,
        "port": options.port,
        "keys_updated": handoff.keys_updated,
        "tcp_listener_fd": handoff.tcp_listener_fd,
        "udp_socket_fd": handoff.udp_socket_fd,
        "tcp_options": {
            "ip_transparent": handoff.tcp_options.ip_transparent,
            "so_reuseaddr": handoff.tcp_options.so_reuseaddr,
            "ip_recvorigdstaddr": handoff.tcp_options.ip_recvorigdstaddr,
            "ipv6_recvorigdstaddr": handoff.tcp_options.ipv6_recvorigdstaddr,
            "original_dst_capture_ready": handoff.tcp_options.original_dst_capture_ready,
        },
        "udp_options": {
            "ip_transparent": handoff.udp_options.ip_transparent,
            "so_reuseaddr": handoff.udp_options.so_reuseaddr,
            "ip_recvorigdstaddr": handoff.udp_options.ip_recvorigdstaddr,
            "ipv6_recvorigdstaddr": handoff.udp_options.ipv6_recvorigdstaddr,
            "original_dst_capture_ready": handoff.udp_options.original_dst_capture_ready,
        },
        "go_userspace_handlers_remain_authoritative": true,
    });
    let payload = format!("{payload}\n");
    if let Err(err) = send_fd_handoff(
        options.handoff_fd,
        payload.as_bytes(),
        &[
            handoff.listeners.tcp_listener.as_raw_fd(),
            handoff.listeners.udp_socket.as_raw_fd(),
        ],
    ) {
        return LoaderOutput::error(format!("send tproxy listener fd handoff failed: {err}"));
    }
    LoaderOutput::ok(payload)
}

fn run_tproxy_listener_update_map(options: TproxyListenerUpdateMapOptions) -> LoaderOutput {
    let map = match dae_ebpf_support::update_listen_socket_map_by_id(
        options.map_id,
        options.tcp_fd,
        options.udp_fd,
    ) {
        Ok(map) => map,
        Err(err) => {
            return LoaderOutput::error(format!("tproxy listener update-map failed: {err}"));
        }
    };
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "status": "pass",
            "loader": "rust",
            "scope": "tproxy-listener-update-map",
            "map_id": map.id,
            "map_name": map.name,
            "keys_updated": [0, 1],
            "tcp_fd": options.tcp_fd,
            "udp_fd": options.udp_fd,
            "go_userspace_handlers_remain_authoritative": true,
        })
    ))
}

fn run_load_pin_command(args: &[String]) -> LoaderOutput {
    match parse_load_pin_options(args) {
        Ok(options) => run_load_pin(options),
        Err(err) => LoaderOutput::usage(err),
    }
}

fn run_map_stats_count(requests: Vec<MapStatsCountRequest>) -> LoaderOutput {
    if requests.is_empty() {
        return LoaderOutput::usage("map-stats count requires at least one --map name:id");
    }
    let mut counts = Vec::with_capacity(requests.len());
    for request in requests {
        match dae_ebpf_support::count_map_entries_by_id(request.id) {
            Ok(entries) => counts.push(json!({
                "name": request.name,
                "id": request.id,
                "entries": entries,
            })),
            Err(err) => {
                return LoaderOutput::error(format!(
                    "count map {}:{} failed: {err}",
                    request.name, request.id
                ));
            }
        }
    }
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "status": "pass",
            "loader": "rust",
            "scope": "read-only-bpf-map-stats",
            "counts": counts,
        })
    ))
}

fn run_trace_loader_contract() -> LoaderOutput {
    let gate = dae_ebpf_support::trace_core_sideload_gate_report();
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "name": "rust-aya-trace-loader-contract-v1",
            "binary": "dae-aya-bpf-loader",
            "compiled_native_ebpf": cfg!(feature = "native-ebpf"),
            "scope": "Rust/Aya trace CO-RE side-load contract is retained for audit but temporarily disabled",
            "core_sideload_enabled": gate.enabled,
            "disabled_reason": gate.disabled_reason,
            "default_daemon_path": false,
            "kernel_ebpf_program_rewrite": false,
            "go_trace_adoption_ready": gate.go_trace_adoption_ready,
            "rust_core_relocation_required": gate.rust_core_relocation_required,
            "restore_gate": gate.restore_gate,
            "required_pins": {
                "maps": null,
                "programs": null
            },
            "non_default_smokes": {
                "attach_ringbuf": "disabled"
            },
            "config_source": {
                "port": "host-order u16, converted to BPF big-endian tracing_cfg.port",
                "l4_proto": "kernel protocol number",
                "ip_version": "4 or 6",
                "ringbuf_size": "events map max_entries override"
            }
        })
    ))
}

fn run_connectivity_map_update(options: ConnectivityMapUpdateOptions) -> LoaderOutput {
    let event = dae_ebpf_support::ConnectivityEvent {
        key: dae_ebpf_support::ConnectivityKey {
            outbound: options.outbound,
            l4proto: options.l4_proto,
            ipversion: options.ip_version,
        },
        alive: options.alive,
        is_init: options.is_init,
        dryrun: options.dryrun,
    };
    let plan = match dae_ebpf_support::update_connectivity_map_by_id(options.map_id, event) {
        Ok(plan) => plan,
        Err(err) => return LoaderOutput::error(format!("connectivity map update failed: {err}")),
    };
    LoaderOutput::ok(format!(
        "{}\n",
        connectivity_map_pass_response(options.map_id, plan, options.dryrun, options.is_init)
    ))
}

pub fn run_connectivity_map_serve<R, W>(reader: R, mut writer: W) -> io::Result<()>
where
    R: BufRead,
    W: Write,
{
    let mut cache = dae_ebpf_support::ConnectivityMapFdCache::default();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = handle_connectivity_map_serve_line(&mut cache, &line);
        writer.write_all(response.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    Ok(())
}

pub fn run_connectivity_map_serve_binary<R, W>(mut reader: R, mut writer: W) -> io::Result<()>
where
    R: Read,
    W: Write,
{
    let mut cache = dae_ebpf_support::ConnectivityMapFdCache::default();
    let mut request = [0_u8; 8];
    loop {
        match reader.read_exact(&mut request) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        }
        let response = handle_connectivity_map_serve_binary_request(&mut cache, request);
        writer.write_all(&response)?;
        writer.flush()?;
    }
}

fn handle_connectivity_map_serve_binary_request(
    cache: &mut dae_ebpf_support::ConnectivityMapFdCache,
    request: [u8; 8],
) -> [u8; 8] {
    let map_id = u32::from_le_bytes([request[0], request[1], request[2], request[3]]);
    let flags = request[7];
    let event = dae_ebpf_support::ConnectivityEvent {
        key: dae_ebpf_support::ConnectivityKey {
            outbound: request[4],
            l4proto: request[5],
            ipversion: request[6],
        },
        alive: flags & 0x01 != 0,
        is_init: flags & 0x02 != 0,
        dryrun: flags & 0x04 != 0,
    };
    let mut response = [0_u8; 8];
    response[4..8].copy_from_slice(&map_id.to_le_bytes());
    match cache.update_by_id(map_id, event) {
        Ok(plan) => {
            response[0] = 0;
            response[1] = u8::from(plan.written);
        }
        Err(_) => {
            response[0] = 1;
        }
    }
    response
}

fn handle_connectivity_map_serve_line(
    cache: &mut dae_ebpf_support::ConnectivityMapFdCache,
    line: &str,
) -> String {
    let options = match parse_connectivity_map_serve_request(line) {
        Ok(options) => options,
        Err(err) => return connectivity_map_error_response(err).to_string(),
    };
    let event = dae_ebpf_support::ConnectivityEvent {
        key: dae_ebpf_support::ConnectivityKey {
            outbound: options.outbound,
            l4proto: options.l4_proto,
            ipversion: options.ip_version,
        },
        alive: options.alive,
        is_init: options.is_init,
        dryrun: options.dryrun,
    };
    match cache.update_by_id(options.map_id, event) {
        Ok(plan) => {
            connectivity_map_pass_response(options.map_id, plan, options.dryrun, options.is_init)
                .to_string()
        }
        Err(err) => {
            connectivity_map_error_response(format!("connectivity map update failed: {err}"))
                .to_string()
        }
    }
}

fn connectivity_map_pass_response(
    map_id: u32,
    plan: dae_ebpf_support::ConnectivityWritePlan,
    dryrun: bool,
    is_init: bool,
) -> Value {
    json!({
        "status": "pass",
        "loader": "rust",
        "scope": "outbound-connectivity-map-update",
        "map_id": map_id,
        "written": plan.written,
        "key": {
            "outbound": plan.key.outbound,
            "l4proto": plan.key.l4proto,
            "ipversion": plan.key.ipversion,
        },
        "value": plan.value,
        "changed": plan.changed,
        "dryrun": dryrun,
        "is_init": is_init,
    })
}

fn connectivity_map_error_response(message: impl Into<String>) -> Value {
    json!({
        "status": "error",
        "loader": "rust",
        "scope": "outbound-connectivity-map-update",
        "error": message.into(),
    })
}

fn parse_connectivity_map_serve_request(
    line: &str,
) -> Result<ConnectivityMapUpdateOptions, String> {
    let value: Value =
        serde_json::from_str(line).map_err(|err| format!("bad connectivity-map request: {err}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "bad connectivity-map request: expected JSON object".to_owned())?;
    Ok(ConnectivityMapUpdateOptions {
        map_id: json_u32(object.get("map_id"), "map_id")?,
        outbound: json_u8(object.get("outbound"), "outbound")?,
        l4_proto: json_u8(
            object.get("l4_proto").or_else(|| object.get("l4proto")),
            "l4_proto",
        )?,
        ip_version: json_u8(
            object.get("ip_version").or_else(|| object.get("ipversion")),
            "ip_version",
        )?,
        alive: json_bool(object.get("alive"), "alive")?,
        is_init: json_bool(object.get("is_init"), "is_init")?,
        dryrun: json_bool(object.get("dryrun"), "dryrun")?,
    })
}

fn json_u32(value: Option<&Value>, name: &str) -> Result<u32, String> {
    let raw = value
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing or non-u32 connectivity-map field: {name}"))?;
    u32::try_from(raw).map_err(|_| format!("connectivity-map field out of u32 range: {name}"))
}

fn json_u8(value: Option<&Value>, name: &str) -> Result<u8, String> {
    let raw = json_u32(value, name)?;
    u8::try_from(raw).map_err(|_| format!("connectivity-map field out of u8 range: {name}"))
}

fn json_bool(value: Option<&Value>, name: &str) -> Result<bool, String> {
    value
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("missing or non-bool connectivity-map field: {name}"))
}

pub fn run_routing_map_apply_json(input: &str) -> LoaderOutput {
    let request = match parse_routing_map_apply_request(input) {
        Ok(request) => request,
        Err(err) => return LoaderOutput::usage(err),
    };
    match dae_ebpf_support::apply_routing_maps_with_lpm_build_by_id(
        request.routing_map_id,
        request.lpm_array_map_id,
        &request.routing_entries,
        &request.lpm_entries,
        &request.lpm_maps,
    ) {
        Ok(report) => LoaderOutput::ok(format!(
            "{}\n",
            json!({
                "status": "pass",
                "loader": "rust",
                "scope": "routing-map-apply",
                "routing_map_id": request.routing_map_id,
                "lpm_array_map_id": request.lpm_array_map_id,
                "routing_entries_updated": report.routing_entries_updated,
                "lpm_entries_updated": report.lpm_entries_updated,
                "lpm_maps_created": report.lpm_maps_created,
            })
        )),
        Err(err) => LoaderOutput::error(format!("routing map apply failed: {err}")),
    }
}

pub fn run_domain_routing_map_apply_json(input: &str) -> LoaderOutput {
    let request = match parse_domain_routing_map_apply_request(input) {
        Ok(request) => request,
        Err(err) => return LoaderOutput::usage(err),
    };
    match dae_ebpf_support::apply_domain_routing_map_by_id(
        request.map_id,
        &request.updates,
        &request.deletes,
    ) {
        Ok(report) => LoaderOutput::ok(format!(
            "{}\n",
            json!({
                "status": "pass",
                "loader": "rust",
                "scope": "domain-routing-map-apply",
                "map_id": request.map_id,
                "entries_updated": report.entries_updated,
                "entries_deleted": report.entries_deleted,
            })
        )),
        Err(err) => LoaderOutput::error(format!("domain routing map apply failed: {err}")),
    }
}

pub fn run_domain_routing_map_serve<R, W>(reader: R, mut writer: W) -> io::Result<()>
where
    R: BufRead,
    W: Write,
{
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = handle_domain_routing_map_serve_line(&line);
        writer.write_all(response.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    Ok(())
}

fn handle_domain_routing_map_serve_line(line: &str) -> String {
    let output = run_domain_routing_map_apply_json(line);
    if output.exit_code == 0 {
        return output.stdout.trim_end().to_owned();
    }
    json!({
        "status": "error",
        "loader": "rust",
        "scope": "domain-routing-map-apply",
        "error": output.stderr.trim(),
    })
    .to_string()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RoutingMapApplyRequest {
    routing_map_id: u32,
    lpm_array_map_id: u32,
    routing_entries: Vec<dae_ebpf_support::RoutingMapEntry>,
    lpm_entries: Vec<dae_ebpf_support::LpmArrayMapEntry>,
    lpm_maps: Vec<dae_ebpf_support::LpmMapBuildSpec>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DomainRoutingMapApplyRequest {
    map_id: u32,
    updates: Vec<dae_ebpf_support::DomainRoutingMapEntry>,
    deletes: Vec<[u32; 4]>,
}

fn parse_routing_map_apply_request(input: &str) -> Result<RoutingMapApplyRequest, String> {
    let value: Value =
        serde_json::from_str(input).map_err(|err| format!("bad routing-map request: {err}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "bad routing-map request: expected JSON object".to_owned())?;
    let routing_entries = json_array(object.get("routing_entries"), "routing_entries")?
        .iter()
        .map(parse_routing_map_entry)
        .collect::<Result<Vec<_>, _>>()?;
    let lpm_entries = json_array(object.get("lpm_entries"), "lpm_entries")?
        .iter()
        .map(parse_lpm_array_map_entry)
        .collect::<Result<Vec<_>, _>>()?;
    let lpm_maps = optional_json_array(object.get("lpm_maps"))?
        .iter()
        .map(parse_lpm_map_build_spec)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RoutingMapApplyRequest {
        routing_map_id: json_u32(object.get("routing_map_id"), "routing_map_id")?,
        lpm_array_map_id: json_u32(object.get("lpm_array_map_id"), "lpm_array_map_id")?,
        routing_entries,
        lpm_entries,
        lpm_maps,
    })
}

fn parse_domain_routing_map_apply_request(
    input: &str,
) -> Result<DomainRoutingMapApplyRequest, String> {
    let value: Value = serde_json::from_str(input)
        .map_err(|err| format!("bad domain-routing-map request: {err}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "bad domain-routing-map request: expected JSON object".to_owned())?;
    let updates = json_array(object.get("updates"), "updates")?
        .iter()
        .map(parse_domain_routing_map_entry)
        .collect::<Result<Vec<_>, _>>()?;
    let deletes = json_array(object.get("deletes"), "deletes")?
        .iter()
        .map(|value| json_u32_array_4(Some(value), "deletes[]"))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DomainRoutingMapApplyRequest {
        map_id: json_u32(object.get("map_id"), "map_id")?,
        updates,
        deletes,
    })
}

fn parse_routing_map_entry(value: &Value) -> Result<dae_ebpf_support::RoutingMapEntry, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "bad routing entry: expected JSON object".to_owned())?;
    Ok(dae_ebpf_support::RoutingMapEntry {
        index: json_u32(object.get("index"), "routing_entries[].index")?,
        value: parse_bpf_match_set(
            object
                .get("value")
                .ok_or_else(|| "missing routing_entries[].value".to_owned())?,
        )?,
    })
}

fn parse_lpm_array_map_entry(value: &Value) -> Result<dae_ebpf_support::LpmArrayMapEntry, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "bad lpm entry: expected JSON object".to_owned())?;
    Ok(dae_ebpf_support::LpmArrayMapEntry {
        index: json_u32(object.get("index"), "lpm_entries[].index")?,
        map_id: json_u32(object.get("map_id"), "lpm_entries[].map_id")?,
    })
}

fn parse_lpm_map_build_spec(value: &Value) -> Result<dae_ebpf_support::LpmMapBuildSpec, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "bad lpm map build spec: expected JSON object".to_owned())?;
    let entries = json_array(object.get("entries"), "lpm_maps[].entries")?
        .iter()
        .map(parse_lpm_map_entry)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(dae_ebpf_support::LpmMapBuildSpec {
        index: json_u32(object.get("index"), "lpm_maps[].index")?,
        flags: json_u32(object.get("flags"), "lpm_maps[].flags")?,
        max_entries: json_u32(object.get("max_entries"), "lpm_maps[].max_entries")?,
        key_size: json_u32(object.get("key_size"), "lpm_maps[].key_size")?,
        value_size: json_u32(object.get("value_size"), "lpm_maps[].value_size")?,
        entries,
    })
}

fn parse_lpm_map_entry(value: &Value) -> Result<dae_ebpf_support::LpmMapEntry, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "bad lpm map entry: expected JSON object".to_owned())?;
    let key = object
        .get("key")
        .and_then(Value::as_object)
        .ok_or_else(|| "bad lpm map entry key: expected JSON object".to_owned())?;
    Ok(dae_ebpf_support::LpmMapEntry {
        key: dae_ebpf_support::BpfLpmKey {
            prefix_len: json_u32(key.get("prefix_len"), "lpm_maps[].entries[].key.prefix_len")?,
            data: json_u32_array_4(key.get("data"), "lpm_maps[].entries[].key.data")?,
        },
        value: json_u32(object.get("value"), "lpm_maps[].entries[].value")?,
    })
}

fn parse_domain_routing_map_entry(
    value: &Value,
) -> Result<dae_ebpf_support::DomainRoutingMapEntry, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "bad domain routing entry: expected JSON object".to_owned())?;
    Ok(dae_ebpf_support::DomainRoutingMapEntry {
        key: json_u32_array_4(object.get("key"), "updates[].key")?,
        value: dae_ebpf_support::BpfDomainRouting {
            bitmap: json_u32_array_32(object.get("bitmap"), "updates[].bitmap")?,
        },
    })
}

fn parse_bpf_match_set(value: &Value) -> Result<dae_ebpf_support::BpfMatchSet, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "bad match set: expected JSON object".to_owned())?;
    Ok(dae_ebpf_support::BpfMatchSet {
        value: json_u8_array_16(object.get("value"), "match_set.value")?,
        not: u8::from(json_bool(object.get("not"), "match_set.not")?),
        kind: json_u8(
            object.get("type").or_else(|| object.get("kind")),
            "match_set.type",
        )?,
        outbound: json_u8(object.get("outbound"), "match_set.outbound")?,
        must: u8::from(json_bool(object.get("must"), "match_set.must")?),
        mark: json_u32(object.get("mark"), "match_set.mark")?,
    })
}

fn json_array<'a>(value: Option<&'a Value>, name: &str) -> Result<&'a Vec<Value>, String> {
    value
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing or non-array field: {name}"))
}

fn optional_json_array(value: Option<&Value>) -> Result<Vec<Value>, String> {
    match value {
        Some(value) => value
            .as_array()
            .cloned()
            .ok_or_else(|| "optional field is not an array".to_owned()),
        None => Ok(Vec::new()),
    }
}

fn json_u32_array_4(value: Option<&Value>, name: &str) -> Result<[u32; 4], String> {
    let values = json_array(value, name)?;
    if values.len() != 4 {
        return Err(format!("bad {name}: got {} values, want 4", values.len()));
    }
    let mut out = [0_u32; 4];
    for (index, value) in values.iter().enumerate() {
        out[index] = json_u32(Some(value), name)?;
    }
    Ok(out)
}

fn json_u32_array_32(value: Option<&Value>, name: &str) -> Result<[u32; 32], String> {
    let values = json_array(value, name)?;
    if values.len() != 32 {
        return Err(format!("bad {name}: got {} values, want 32", values.len()));
    }
    let mut out = [0_u32; 32];
    for (index, value) in values.iter().enumerate() {
        out[index] = json_u32(Some(value), name)?;
    }
    Ok(out)
}

fn json_u8_array_16(value: Option<&Value>, name: &str) -> Result<[u8; 16], String> {
    let values = json_array(value, name)?;
    if values.len() != 16 {
        return Err(format!("bad {name}: got {} values, want 16", values.len()));
    }
    let mut out = [0_u8; 16];
    for (index, value) in values.iter().enumerate() {
        out[index] = json_u8(Some(value), name)?;
    }
    Ok(out)
}

#[cfg(feature = "native-ebpf")]
fn run_trace_load_pin(options: TraceLoaderLoadPinOptions) -> LoaderOutput {
    use dae_ebpf_support::{AyaTraceLoaderOptions, load_pin_aya_trace_object};

    let report = match load_pin_aya_trace_object(AyaTraceLoaderOptions {
        object: &options.object,
        pin_root: &options.pin_root,
        port: options.port,
        l4_proto: options.l4_proto,
        ip_version: options.ip_version,
        ringbuf_size: options.ringbuf_size,
    }) {
        Ok(report) => report,
        Err(err) => return LoaderOutput::error(err),
    };
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "status": "pass",
            "loader": "rust-aya",
            "object": report.object,
            "pin_root": report.pin_root,
            "map_pin_root": report.map_pin_root,
            "program_pin_root": report.program_pin_root,
            "maps": report.maps.iter().map(|pin| json!({
                "name": pin.name,
                "path": pin.path,
            })).collect::<Vec<_>>(),
            "programs": report.programs.iter().map(|pin| json!({
                "name": pin.name,
                "path": pin.path,
            })).collect::<Vec<_>>(),
            "trace_config": {
                "port": report.port,
                "l4_proto": report.l4_proto,
                "ip_version": report.ip_version,
                "ringbuf_size": report.ringbuf_size,
            },
            "go_trace_adoption_ready": true,
        })
    ))
}

#[cfg(not(feature = "native-ebpf"))]
fn run_trace_load_pin(_options: TraceLoaderLoadPinOptions) -> LoaderOutput {
    LoaderOutput::error(dae_ebpf_support::trace_core_sideload_gate_report().disabled_reason)
}

#[cfg(feature = "native-ebpf")]
fn run_trace_attach_ringbuf_smoke(options: TraceLoaderAttachRingbufSmokeOptions) -> LoaderOutput {
    use dae_ebpf_support::{
        AyaTraceAttachRingbufSmokeOptions, AyaTraceAttachSmokeTrigger,
        attach_ringbuf_smoke_aya_trace_object,
    };

    let trigger = match options.trigger {
        TraceLoaderAttachSmokeTrigger::LoopbackUdp => AyaTraceAttachSmokeTrigger::LoopbackUdp,
        TraceLoaderAttachSmokeTrigger::OpenProcSelfStat => {
            AyaTraceAttachSmokeTrigger::OpenProcSelfStat
        }
    };
    let report = match attach_ringbuf_smoke_aya_trace_object(AyaTraceAttachRingbufSmokeOptions {
        object: &options.object,
        target: &options.target,
        program_name: &options.program_name,
        port: options.port,
        l4_proto: options.l4_proto,
        ip_version: options.ip_version,
        ringbuf_size: options.ringbuf_size,
        trigger,
        trigger_count: options.trigger_count,
        poll_attempts: options.poll_attempts,
    }) {
        Ok(report) => report,
        Err(err) => return LoaderOutput::error(err),
    };
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "status": "pass",
            "loader": "rust-aya",
            "scope": "trace-attach-ringbuf-smoke",
            "object": report.object,
            "target": report.target,
            "program_name": report.program_name,
            "trigger": report.trigger.as_str(),
            "trigger_count": report.trigger_count,
            "poll_attempts": report.poll_attempts,
            "events_seen": report.events_seen,
            "first_event_len": report.first_event_len,
            "first_event_pc_nonzero": report.first_event_pc_nonzero,
            "first_event_skb_nonzero": report.first_event_skb_nonzero,
            "sk_buff_core_semantics": false,
            "default_daemon_path": false,
        })
    ))
}

#[cfg(not(feature = "native-ebpf"))]
fn run_trace_attach_ringbuf_smoke(_options: TraceLoaderAttachRingbufSmokeOptions) -> LoaderOutput {
    LoaderOutput::error(dae_ebpf_support::trace_core_sideload_gate_report().disabled_reason)
}

#[cfg(feature = "native-ebpf")]
fn run_load_pin(options: BpfLoaderLoadPinOptions) -> LoaderOutput {
    use dae_ebpf_support::{
        AyaUserspaceLoaderOptions, DaeParamInput, build_dae_param, load_aya_userspace_object,
        pin_aya_loaded_object_for_go_adoption,
    };

    let requested_object_source = options.object_source;
    let (object, mut cleanup_object) = match options.object {
        Some(object) => (object, None),
        None => match write_embedded_native_aya_object() {
            Ok((object, cleanup)) => (object, Some(cleanup)),
            Err(err) => return LoaderOutput::error(err),
        },
    };
    let param = build_dae_param(DaeParamInput {
        tproxy_port: options.tproxy_port,
        control_plane_pid: options.control_plane_pid,
        dae0_ifindex: options.dae0_ifindex,
        dae_netns_id: options.dae_netns_id,
        dae0peer_mac: options.dae0peer_mac,
        has_bpf_get_current_task: options.has_bpf_get_current_task,
    });
    let map_pin_root = options.pin_root.join("maps");
    let mut loaded = match load_aya_userspace_object(AyaUserspaceLoaderOptions {
        object: &object,
        param: Some(param),
        map_pin_path: Some(&map_pin_root),
        allow_unsupported_maps: true,
        max_entries_overrides: &[],
        prepin_lpm_array_map: true,
    }) {
        Ok(loaded) => loaded,
        Err(err) => {
            if let Some(cleanup) = cleanup_object.take() {
                cleanup();
            }
            return LoaderOutput::error(err);
        }
    };
    let pin_report = match pin_aya_loaded_object_for_go_adoption(&mut loaded, &options.pin_root) {
        Ok(report) => report,
        Err(err) => {
            if let Some(cleanup) = cleanup_object.take() {
                cleanup();
            }
            return LoaderOutput::error(err);
        }
    };
    let object_source = requested_object_source
        .map(BpfObjectSource::as_str)
        .unwrap_or(if cleanup_object.is_some() {
            BpfObjectSource::CAya.as_str()
        } else {
            "explicit"
        });
    if let Some(cleanup) = cleanup_object.take() {
        cleanup();
    }
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "status": "pass",
            "loader": "rust-aya",
            "object": object,
            "object_source": object_source,
            "default_object_source": BpfObjectSource::CAya.as_str(),
            "rust_aya_skeleton_opt_in": object_source == BpfObjectSource::RustAyaSkeleton.as_str(),
            "pin_root": pin_report.adoption_pin_root,
            "map_pin_root": pin_report.map_pin_root,
            "program_pin_root": pin_report.program_pin_root,
            "maps": pin_report.maps.iter().map(|pin| json!({
                "name": pin.name,
                "path": pin.path,
            })).collect::<Vec<_>>(),
            "programs": pin_report.programs.iter().map(|pin| json!({
                "name": pin.name,
                "path": pin.path,
            })).collect::<Vec<_>>(),
            "param": {
                "tproxy_port": param.tproxy_port,
                "control_plane_pid": param.control_plane_pid,
                "dae0_ifindex": param.dae0_ifindex,
                "dae_netns_id": param.dae_netns_id,
                "dae0peer_mac": mac_string(param.dae0peer_mac),
                "has_bpf_get_current_task": param.has_bpf_get_current_task,
            },
            "go_adoption_ready": true,
        })
    ))
}

#[cfg(feature = "native-ebpf")]
fn write_embedded_native_aya_object() -> Result<(PathBuf, impl FnOnce()), String> {
    let path = std::env::temp_dir().join(format!(
        "dae-native-bpf-{}-{}.o",
        std::process::id(),
        fastrand::u64(..)
    ));
    std::fs::write(&path, EMBEDDED_NATIVE_AYA_OBJECT).map_err(|err| {
        format!(
            "write embedded native Aya object {} failed: {err}",
            path.display()
        )
    })?;
    let cleanup_path = path.clone();
    Ok((path, move || {
        let _ = std::fs::remove_file(cleanup_path);
    }))
}

#[cfg(not(feature = "native-ebpf"))]
fn run_load_pin(_options: BpfLoaderLoadPinOptions) -> LoaderOutput {
    LoaderOutput::error("bpf-loader load-pin requires dae-aya-bpf-loader feature native-ebpf")
}

fn parse_load_pin_options(args: &[String]) -> Result<BpfLoaderLoadPinOptions, String> {
    let mut object = None;
    let mut object_source = None;
    let mut pin_root = None;
    let mut tproxy_port = None;
    let mut control_plane_pid = None;
    let mut dae0_ifindex = None;
    let mut dae_netns_id = None;
    let mut dae0peer_mac = None;
    let mut has_bpf_get_current_task = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--object" => {
                object = Some(parse_next_path(&mut iter, "bpf-loader load-pin --object")?)
            }
            "--object-source" => {
                object_source = Some(BpfObjectSource::parse(next_value(
                    &mut iter,
                    "bpf-loader load-pin --object-source",
                )?)?)
            }
            "--pin-root" => {
                pin_root = Some(parse_next_path(
                    &mut iter,
                    "bpf-loader load-pin --pin-root",
                )?)
            }
            "--tproxy-port" => {
                tproxy_port = Some(parse_next::<u16>(
                    &mut iter,
                    "bpf-loader load-pin --tproxy-port",
                )?)
            }
            "--control-plane-pid" => {
                control_plane_pid = Some(parse_next::<u32>(
                    &mut iter,
                    "bpf-loader load-pin --control-plane-pid",
                )?)
            }
            "--dae0-ifindex" => {
                dae0_ifindex = Some(parse_next::<u32>(
                    &mut iter,
                    "bpf-loader load-pin --dae0-ifindex",
                )?)
            }
            "--dae-netns-id" => {
                dae_netns_id = Some(parse_next::<u32>(
                    &mut iter,
                    "bpf-loader load-pin --dae-netns-id",
                )?)
            }
            "--dae0peer-mac" => {
                dae0peer_mac = Some(parse_mac(next_value(
                    &mut iter,
                    "bpf-loader load-pin --dae0peer-mac",
                )?)?)
            }
            "--has-bpf-get-current-task" => {
                has_bpf_get_current_task = Some(parse_bool(next_value(
                    &mut iter,
                    "bpf-loader load-pin --has-bpf-get-current-task",
                )?)?)
            }
            _ if arg.starts_with("--object=") => object = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--object-source=") => {
                object_source = Some(BpfObjectSource::parse(split_value(arg)?)?)
            }
            _ if arg.starts_with("--pin-root=") => pin_root = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--tproxy-port=") => tproxy_port = Some(parse_value(arg)?),
            _ if arg.starts_with("--control-plane-pid=") => {
                control_plane_pid = Some(parse_value(arg)?)
            }
            _ if arg.starts_with("--dae0-ifindex=") => dae0_ifindex = Some(parse_value(arg)?),
            _ if arg.starts_with("--dae-netns-id=") => dae_netns_id = Some(parse_value(arg)?),
            _ if arg.starts_with("--dae0peer-mac=") => {
                dae0peer_mac = Some(parse_mac(split_value(arg)?)?)
            }
            _ if arg.starts_with("--has-bpf-get-current-task=") => {
                has_bpf_get_current_task = Some(parse_bool(split_value(arg)?)?)
            }
            _ => return Err(format!("unsupported bpf-loader load-pin argument: {arg}")),
        }
    }
    if object_source == Some(BpfObjectSource::RustAyaSkeleton) && object.is_none() {
        return Err(
            "bpf-loader load-pin --object-source=rust-aya-skeleton requires --object".to_owned(),
        );
    }
    Ok(BpfLoaderLoadPinOptions {
        object,
        object_source,
        pin_root: pin_root.ok_or_else(|| "missing bpf-loader load-pin --pin-root".to_owned())?,
        tproxy_port: tproxy_port
            .ok_or_else(|| "missing bpf-loader load-pin --tproxy-port".to_owned())?,
        control_plane_pid: control_plane_pid
            .ok_or_else(|| "missing bpf-loader load-pin --control-plane-pid".to_owned())?,
        dae0_ifindex: dae0_ifindex
            .ok_or_else(|| "missing bpf-loader load-pin --dae0-ifindex".to_owned())?,
        dae_netns_id: dae_netns_id
            .ok_or_else(|| "missing bpf-loader load-pin --dae-netns-id".to_owned())?,
        dae0peer_mac: dae0peer_mac
            .ok_or_else(|| "missing bpf-loader load-pin --dae0peer-mac".to_owned())?,
        has_bpf_get_current_task: has_bpf_get_current_task
            .ok_or_else(|| "missing bpf-loader load-pin --has-bpf-get-current-task".to_owned())?,
    })
}

fn parse_map_stats_count_options(args: &[String]) -> Result<Vec<MapStatsCountRequest>, String> {
    let mut maps = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--map" => maps.push(parse_map_count_request(next_value(
                &mut iter,
                "map-stats count --map",
            )?)?),
            _ if arg.starts_with("--map=") => {
                maps.push(parse_map_count_request(split_value(arg)?)?)
            }
            _ => return Err(format!("unsupported map-stats count argument: {arg}")),
        }
    }
    Ok(maps)
}

fn parse_trace_load_pin_options(args: &[String]) -> Result<TraceLoaderLoadPinOptions, String> {
    let mut object = None;
    let mut pin_root = None;
    let mut ip_version = None;
    let mut l4_proto = None;
    let mut port = None;
    let mut ringbuf_size = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--object" => object = Some(parse_next_path(&mut iter, "trace-loader --object")?),
            "--pin-root" => pin_root = Some(parse_next_path(&mut iter, "trace-loader --pin-root")?),
            "--ip-version" => {
                ip_version = Some(parse_next::<u8>(&mut iter, "trace-loader --ip-version")?)
            }
            "--l4-proto" => {
                l4_proto = Some(parse_next::<u16>(&mut iter, "trace-loader --l4-proto")?)
            }
            "--port" => port = Some(parse_next::<u16>(&mut iter, "trace-loader --port")?),
            "--ringbuf-size" => {
                ringbuf_size = Some(parse_next::<u32>(&mut iter, "trace-loader --ringbuf-size")?)
            }
            _ if arg.starts_with("--object=") => object = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--pin-root=") => pin_root = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--ip-version=") => ip_version = Some(parse_value(arg)?),
            _ if arg.starts_with("--l4-proto=") => l4_proto = Some(parse_value(arg)?),
            _ if arg.starts_with("--port=") => port = Some(parse_value(arg)?),
            _ if arg.starts_with("--ringbuf-size=") => ringbuf_size = Some(parse_value(arg)?),
            _ => return Err(format!("unsupported trace-loader load-pin argument: {arg}")),
        }
    }
    Ok(TraceLoaderLoadPinOptions {
        object: object.ok_or_else(|| "missing trace-loader load-pin --object".to_owned())?,
        pin_root: pin_root.ok_or_else(|| "missing trace-loader load-pin --pin-root".to_owned())?,
        ip_version: ip_version
            .ok_or_else(|| "missing trace-loader load-pin --ip-version".to_owned())?,
        l4_proto: l4_proto.ok_or_else(|| "missing trace-loader load-pin --l4-proto".to_owned())?,
        port: port.ok_or_else(|| "missing trace-loader load-pin --port".to_owned())?,
        ringbuf_size: ringbuf_size
            .ok_or_else(|| "missing trace-loader load-pin --ringbuf-size".to_owned())?,
    })
}

fn parse_trace_attach_ringbuf_smoke_options(
    args: &[String],
) -> Result<TraceLoaderAttachRingbufSmokeOptions, String> {
    let mut object = None;
    let mut target = None;
    let mut program_name = Some("kprobe_skb_1".to_owned());
    let mut ip_version = Some(4_u8);
    let mut l4_proto = Some(6_u16);
    let mut port = Some(443_u16);
    let mut ringbuf_size = Some(65_536_u32);
    let mut trigger = Some(TraceLoaderAttachSmokeTrigger::LoopbackUdp);
    let mut trigger_count = Some(4_u32);
    let mut poll_attempts = Some(50_u32);
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--object" => {
                object = Some(parse_next_path(
                    &mut iter,
                    "trace-loader attach-ringbuf-smoke --object",
                )?)
            }
            "--target" => {
                target = Some(
                    next_value(&mut iter, "trace-loader attach-ringbuf-smoke --target")?.to_owned(),
                )
            }
            "--program-name" => {
                program_name = Some(
                    next_value(
                        &mut iter,
                        "trace-loader attach-ringbuf-smoke --program-name",
                    )?
                    .to_owned(),
                )
            }
            "--ip-version" => {
                ip_version = Some(parse_next::<u8>(
                    &mut iter,
                    "trace-loader attach-ringbuf-smoke --ip-version",
                )?)
            }
            "--l4-proto" => {
                l4_proto = Some(parse_next::<u16>(
                    &mut iter,
                    "trace-loader attach-ringbuf-smoke --l4-proto",
                )?)
            }
            "--port" => {
                port = Some(parse_next::<u16>(
                    &mut iter,
                    "trace-loader attach-ringbuf-smoke --port",
                )?)
            }
            "--ringbuf-size" => {
                ringbuf_size = Some(parse_next::<u32>(
                    &mut iter,
                    "trace-loader attach-ringbuf-smoke --ringbuf-size",
                )?)
            }
            "--trigger" => {
                trigger = Some(TraceLoaderAttachSmokeTrigger::parse(next_value(
                    &mut iter,
                    "trace-loader attach-ringbuf-smoke --trigger",
                )?)?)
            }
            "--trigger-count" => {
                trigger_count = Some(parse_next::<u32>(
                    &mut iter,
                    "trace-loader attach-ringbuf-smoke --trigger-count",
                )?)
            }
            "--poll-attempts" => {
                poll_attempts = Some(parse_next::<u32>(
                    &mut iter,
                    "trace-loader attach-ringbuf-smoke --poll-attempts",
                )?)
            }
            _ if arg.starts_with("--object=") => object = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--target=") => target = Some(split_value(arg)?.to_owned()),
            _ if arg.starts_with("--program-name=") => {
                program_name = Some(split_value(arg)?.to_owned())
            }
            _ if arg.starts_with("--ip-version=") => ip_version = Some(parse_value(arg)?),
            _ if arg.starts_with("--l4-proto=") => l4_proto = Some(parse_value(arg)?),
            _ if arg.starts_with("--port=") => port = Some(parse_value(arg)?),
            _ if arg.starts_with("--ringbuf-size=") => ringbuf_size = Some(parse_value(arg)?),
            _ if arg.starts_with("--trigger=") => {
                trigger = Some(TraceLoaderAttachSmokeTrigger::parse(split_value(arg)?)?)
            }
            _ if arg.starts_with("--trigger-count=") => trigger_count = Some(parse_value(arg)?),
            _ if arg.starts_with("--poll-attempts=") => poll_attempts = Some(parse_value(arg)?),
            _ => {
                return Err(format!(
                    "unsupported trace-loader attach-ringbuf-smoke argument: {arg}"
                ));
            }
        }
    }
    Ok(TraceLoaderAttachRingbufSmokeOptions {
        object: object
            .ok_or_else(|| "missing trace-loader attach-ringbuf-smoke --object".to_owned())?,
        target: target
            .ok_or_else(|| "missing trace-loader attach-ringbuf-smoke --target".to_owned())?,
        program_name: program_name
            .ok_or_else(|| "missing trace-loader attach-ringbuf-smoke --program-name".to_owned())?,
        ip_version: ip_version
            .ok_or_else(|| "missing trace-loader attach-ringbuf-smoke --ip-version".to_owned())?,
        l4_proto: l4_proto
            .ok_or_else(|| "missing trace-loader attach-ringbuf-smoke --l4-proto".to_owned())?,
        port: port.ok_or_else(|| "missing trace-loader attach-ringbuf-smoke --port".to_owned())?,
        ringbuf_size: ringbuf_size
            .ok_or_else(|| "missing trace-loader attach-ringbuf-smoke --ringbuf-size".to_owned())?,
        trigger: trigger
            .ok_or_else(|| "missing trace-loader attach-ringbuf-smoke --trigger".to_owned())?,
        trigger_count: trigger_count.ok_or_else(|| {
            "missing trace-loader attach-ringbuf-smoke --trigger-count".to_owned()
        })?,
        poll_attempts: poll_attempts.ok_or_else(|| {
            "missing trace-loader attach-ringbuf-smoke --poll-attempts".to_owned()
        })?,
    })
}

fn parse_cgroup_monitor_attach_pin_options(
    args: &[String],
) -> Result<CgroupMonitorAttachPinOptions, String> {
    let mut program_root = None;
    let mut link_root = None;
    let mut cgroup_path = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--program-root" => {
                program_root = Some(parse_next_path(
                    &mut iter,
                    "cgroup-monitor attach-pin --program-root",
                )?)
            }
            "--link-root" => {
                link_root = Some(parse_next_path(
                    &mut iter,
                    "cgroup-monitor attach-pin --link-root",
                )?)
            }
            "--cgroup-path" => {
                cgroup_path = Some(parse_next_path(
                    &mut iter,
                    "cgroup-monitor attach-pin --cgroup-path",
                )?)
            }
            _ if arg.starts_with("--program-root=") => program_root = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--link-root=") => link_root = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--cgroup-path=") => cgroup_path = Some(parse_path_value(arg)?),
            _ => {
                return Err(format!(
                    "unsupported cgroup-monitor attach-pin argument: {arg}"
                ));
            }
        }
    }
    Ok(CgroupMonitorAttachPinOptions {
        program_root: program_root
            .ok_or_else(|| "missing cgroup-monitor attach-pin --program-root".to_owned())?,
        link_root: link_root
            .ok_or_else(|| "missing cgroup-monitor attach-pin --link-root".to_owned())?,
        cgroup_path: cgroup_path
            .ok_or_else(|| "missing cgroup-monitor attach-pin --cgroup-path".to_owned())?,
    })
}

fn parse_tc_attach_pin_options(args: &[String]) -> Result<TcAttachPinOptions, String> {
    let mut program_root = None;
    let mut link_root = None;
    let mut program_name = None;
    let mut iface = None;
    let mut netns = None;
    let mut direction = None;
    let mut priority = None;
    let mut handle = None;
    let mut backend = None;
    let mut filter_name = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--program-root" => {
                program_root = Some(parse_next_path(
                    &mut iter,
                    "tc-attach attach-pin --program-root",
                )?)
            }
            "--link-root" => {
                link_root = Some(parse_next_path(
                    &mut iter,
                    "tc-attach attach-pin --link-root",
                )?)
            }
            "--program-name" => {
                program_name =
                    Some(next_value(&mut iter, "tc-attach attach-pin --program-name")?.to_owned())
            }
            "--iface" => {
                iface = Some(next_value(&mut iter, "tc-attach attach-pin --iface")?.to_owned())
            }
            "--netns" => {
                netns = Some(next_value(&mut iter, "tc-attach attach-pin --netns")?.to_owned())
            }
            "--direction" => {
                direction = Some(parse_tc_attach_direction(next_value(
                    &mut iter,
                    "tc-attach attach-pin --direction",
                )?)?)
            }
            "--priority" => {
                priority = Some(parse_next::<u16>(
                    &mut iter,
                    "tc-attach attach-pin --priority",
                )?)
            }
            "--handle" => {
                handle = Some(parse_next::<u32>(
                    &mut iter,
                    "tc-attach attach-pin --handle",
                )?)
            }
            "--backend" => {
                backend = Some(parse_attach_backend(next_value(
                    &mut iter,
                    "tc-attach attach-pin --backend",
                )?)?)
            }
            "--filter-name" => {
                filter_name =
                    Some(next_value(&mut iter, "tc-attach attach-pin --filter-name")?.to_owned())
            }
            _ if arg.starts_with("--program-root=") => program_root = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--link-root=") => link_root = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--program-name=") => {
                program_name = Some(split_value(arg)?.to_owned())
            }
            _ if arg.starts_with("--iface=") => iface = Some(split_value(arg)?.to_owned()),
            _ if arg.starts_with("--netns=") => netns = Some(split_value(arg)?.to_owned()),
            _ if arg.starts_with("--direction=") => {
                direction = Some(parse_tc_attach_direction(split_value(arg)?)?)
            }
            _ if arg.starts_with("--priority=") => priority = Some(parse_value(arg)?),
            _ if arg.starts_with("--handle=") => handle = Some(parse_value(arg)?),
            _ if arg.starts_with("--backend=") => {
                backend = Some(parse_attach_backend(split_value(arg)?)?)
            }
            _ if arg.starts_with("--filter-name=") => {
                filter_name = Some(split_value(arg)?.to_owned())
            }
            _ => return Err(format!("unsupported tc-attach attach-pin argument: {arg}")),
        }
    }
    Ok(TcAttachPinOptions {
        program_root: program_root
            .ok_or_else(|| "missing tc-attach attach-pin --program-root".to_owned())?,
        link_root: link_root
            .ok_or_else(|| "missing tc-attach attach-pin --link-root".to_owned())?,
        program_name: program_name
            .ok_or_else(|| "missing tc-attach attach-pin --program-name".to_owned())?,
        iface: iface.ok_or_else(|| "missing tc-attach attach-pin --iface".to_owned())?,
        netns,
        direction: direction
            .ok_or_else(|| "missing tc-attach attach-pin --direction".to_owned())?,
        priority: priority.ok_or_else(|| "missing tc-attach attach-pin --priority".to_owned())?,
        handle: handle.ok_or_else(|| "missing tc-attach attach-pin --handle".to_owned())?,
        backend: backend.ok_or_else(|| "missing tc-attach attach-pin --backend".to_owned())?,
        filter_name,
    })
}

fn parse_tproxy_listener_open_handoff_options(
    args: &[String],
) -> Result<TproxyListenerOpenHandoffOptions, String> {
    let mut map_id = None;
    let mut port = None;
    let mut handoff_fd = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--map-id" => {
                map_id = Some(parse_next::<u32>(
                    &mut iter,
                    "tproxy-listener open-handoff --map-id",
                )?)
            }
            "--port" => {
                port = Some(parse_next::<u16>(
                    &mut iter,
                    "tproxy-listener open-handoff --port",
                )?)
            }
            "--handoff-fd" => {
                handoff_fd = Some(parse_next::<i32>(
                    &mut iter,
                    "tproxy-listener open-handoff --handoff-fd",
                )?)
            }
            _ if arg.starts_with("--map-id=") => map_id = Some(parse_value(arg)?),
            _ if arg.starts_with("--port=") => port = Some(parse_value(arg)?),
            _ if arg.starts_with("--handoff-fd=") => handoff_fd = Some(parse_value(arg)?),
            _ => {
                return Err(format!(
                    "unsupported tproxy-listener open-handoff argument: {arg}"
                ));
            }
        }
    }
    Ok(TproxyListenerOpenHandoffOptions {
        map_id: map_id.ok_or_else(|| "missing tproxy-listener open-handoff --map-id".to_owned())?,
        port: port.ok_or_else(|| "missing tproxy-listener open-handoff --port".to_owned())?,
        handoff_fd: handoff_fd
            .ok_or_else(|| "missing tproxy-listener open-handoff --handoff-fd".to_owned())?,
    })
}

fn parse_tproxy_listener_update_map_options(
    args: &[String],
) -> Result<TproxyListenerUpdateMapOptions, String> {
    let mut map_id = None;
    let mut tcp_fd = None;
    let mut udp_fd = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--map-id" => {
                map_id = Some(parse_next::<u32>(
                    &mut iter,
                    "tproxy-listener update-map --map-id",
                )?)
            }
            "--tcp-fd" => {
                tcp_fd = Some(parse_next::<i32>(
                    &mut iter,
                    "tproxy-listener update-map --tcp-fd",
                )?)
            }
            "--udp-fd" => {
                udp_fd = Some(parse_next::<i32>(
                    &mut iter,
                    "tproxy-listener update-map --udp-fd",
                )?)
            }
            _ if arg.starts_with("--map-id=") => map_id = Some(parse_value(arg)?),
            _ if arg.starts_with("--tcp-fd=") => tcp_fd = Some(parse_value(arg)?),
            _ if arg.starts_with("--udp-fd=") => udp_fd = Some(parse_value(arg)?),
            _ => {
                return Err(format!(
                    "unsupported tproxy-listener update-map argument: {arg}"
                ));
            }
        }
    }
    Ok(TproxyListenerUpdateMapOptions {
        map_id: map_id.ok_or_else(|| "missing tproxy-listener update-map --map-id".to_owned())?,
        tcp_fd: tcp_fd.ok_or_else(|| "missing tproxy-listener update-map --tcp-fd".to_owned())?,
        udp_fd: udp_fd.ok_or_else(|| "missing tproxy-listener update-map --udp-fd".to_owned())?,
    })
}

fn parse_connectivity_map_update_options(
    args: &[String],
) -> Result<ConnectivityMapUpdateOptions, String> {
    let mut map_id = None;
    let mut outbound = None;
    let mut l4_proto = None;
    let mut ip_version = None;
    let mut alive = None;
    let mut is_init = None;
    let mut dryrun = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--map-id" => {
                map_id = Some(parse_next::<u32>(
                    &mut iter,
                    "connectivity-map update --map-id",
                )?)
            }
            "--outbound" => {
                outbound = Some(parse_next::<u8>(
                    &mut iter,
                    "connectivity-map update --outbound",
                )?)
            }
            "--l4-proto" => {
                l4_proto = Some(parse_next::<u8>(
                    &mut iter,
                    "connectivity-map update --l4-proto",
                )?)
            }
            "--ip-version" => {
                ip_version = Some(parse_next::<u8>(
                    &mut iter,
                    "connectivity-map update --ip-version",
                )?)
            }
            "--alive" => {
                alive = Some(parse_bool(next_value(
                    &mut iter,
                    "connectivity-map update --alive",
                )?)?)
            }
            "--is-init" => {
                is_init = Some(parse_bool(next_value(
                    &mut iter,
                    "connectivity-map update --is-init",
                )?)?)
            }
            "--dryrun" => {
                dryrun = Some(parse_bool(next_value(
                    &mut iter,
                    "connectivity-map update --dryrun",
                )?)?)
            }
            _ if arg.starts_with("--map-id=") => map_id = Some(parse_value(arg)?),
            _ if arg.starts_with("--outbound=") => outbound = Some(parse_value(arg)?),
            _ if arg.starts_with("--l4-proto=") => l4_proto = Some(parse_value(arg)?),
            _ if arg.starts_with("--ip-version=") => ip_version = Some(parse_value(arg)?),
            _ if arg.starts_with("--alive=") => alive = Some(parse_bool(split_value(arg)?)?),
            _ if arg.starts_with("--is-init=") => is_init = Some(parse_bool(split_value(arg)?)?),
            _ if arg.starts_with("--dryrun=") => dryrun = Some(parse_bool(split_value(arg)?)?),
            _ => {
                return Err(format!(
                    "unsupported connectivity-map update argument: {arg}"
                ));
            }
        }
    }
    Ok(ConnectivityMapUpdateOptions {
        map_id: map_id.ok_or_else(|| "missing connectivity-map update --map-id".to_owned())?,
        outbound: outbound
            .ok_or_else(|| "missing connectivity-map update --outbound".to_owned())?,
        l4_proto: l4_proto
            .ok_or_else(|| "missing connectivity-map update --l4-proto".to_owned())?,
        ip_version: ip_version
            .ok_or_else(|| "missing connectivity-map update --ip-version".to_owned())?,
        alive: alive.ok_or_else(|| "missing connectivity-map update --alive".to_owned())?,
        is_init: is_init.ok_or_else(|| "missing connectivity-map update --is-init".to_owned())?,
        dryrun: dryrun.ok_or_else(|| "missing connectivity-map update --dryrun".to_owned())?,
    })
}

fn parse_map_count_request(value: &str) -> Result<MapStatsCountRequest, String> {
    let (name, id) = value
        .split_once(':')
        .ok_or_else(|| format!("bad map-stats count --map {value:?}; want name:id"))?;
    if name.trim().is_empty() {
        return Err(format!("bad map-stats count --map {value:?}; empty name"));
    }
    let id = id
        .parse::<u32>()
        .map_err(|err| format!("bad map id in --map {value:?}: {err}"))?;
    Ok(MapStatsCountRequest {
        name: name.to_owned(),
        id,
    })
}

fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    name: &str,
) -> Result<&'a str, String> {
    iter.next()
        .map(String::as_str)
        .ok_or_else(|| format!("missing {name}"))
}

fn parse_next<'a, T: std::str::FromStr>(
    iter: &mut impl Iterator<Item = &'a String>,
    name: &str,
) -> Result<T, String>
where
    T::Err: std::fmt::Display,
{
    next_value(iter, name)?
        .parse()
        .map_err(|err| format!("bad {name}: {err}"))
}

fn parse_next_path<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    name: &str,
) -> Result<PathBuf, String> {
    Ok(PathBuf::from(next_value(iter, name)?))
}

fn parse_value<T: std::str::FromStr>(arg: &str) -> Result<T, String>
where
    T::Err: std::fmt::Display,
{
    split_value(arg)?
        .parse()
        .map_err(|err| format!("bad {arg}: {err}"))
}

fn parse_path_value(arg: &str) -> Result<PathBuf, String> {
    Ok(PathBuf::from(split_value(arg)?))
}

fn split_value(arg: &str) -> Result<&str, String> {
    arg.split_once('=')
        .map(|(_, value)| value)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing value for {arg}"))
}

fn parse_bool(value: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("bad bool value: {value}")),
    }
}

fn parse_tc_attach_direction(value: &str) -> Result<dae_ebpf_support::TcAttachDirection, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "ingress" => Ok(dae_ebpf_support::TcAttachDirection::Ingress),
        "egress" => Ok(dae_ebpf_support::TcAttachDirection::Egress),
        _ => Err(format!("bad tc attach direction: {value}")),
    }
}

fn parse_attach_backend(value: &str) -> Result<dae_ebpf_support::AttachBackend, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "auto" => Ok(dae_ebpf_support::AttachBackend::Auto),
        "tcx" => Ok(dae_ebpf_support::AttachBackend::Tcx),
        "tc" | "tc-netlink" | "tc_netlink" => Ok(dae_ebpf_support::AttachBackend::TcNetlink),
        _ => Err(format!("bad tc attach backend: {value}")),
    }
}

fn parse_mac(value: &str) -> Result<[u8; 6], String> {
    let mut mac = [0_u8; 6];
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != mac.len() {
        return Err(format!("bad mac address: {value}"));
    }
    for (index, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return Err(format!("bad mac address: {value}"));
        }
        mac[index] =
            u8::from_str_radix(part, 16).map_err(|err| format!("bad mac address: {err}"))?;
    }
    Ok(mac)
}

fn send_fd_handoff(socket_fd: i32, payload: &[u8], fds: &[i32]) -> Result<(), String> {
    if payload.is_empty() {
        return Err("fd handoff payload must not be empty".to_owned());
    }
    if fds.is_empty() {
        return Err("fd handoff requires at least one fd".to_owned());
    }

    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let rights_len = std::mem::size_of_val(fds);
    let mut control = vec![0_u8; unsafe { libc::CMSG_SPACE(rights_len as u32) as usize }];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = control.len();

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err("failed to allocate SCM_RIGHTS control message".to_owned());
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(rights_len as u32) as usize;
        std::ptr::copy_nonoverlapping(
            fds.as_ptr().cast::<u8>(),
            libc::CMSG_DATA(cmsg).cast::<u8>(),
            rights_len,
        );
        let sent = libc::sendmsg(socket_fd, &msg, 0);
        if sent < 0 {
            return Err(format!(
                "sendmsg failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if sent as usize != payload.len() {
            return Err(format!(
                "sendmsg wrote {sent} bytes, expected {}",
                payload.len()
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "native-ebpf")]
fn mac_string(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::Value;

    use super::*;

    #[test]
    fn contract_declares_loader_only_scope() {
        let output = run_with_args(["bpf-loader", "contract"]);
        assert_eq!(output.exit_code, 0, "{}", output.stderr);
        let json: Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(
            json["name"].as_str().unwrap(),
            "rust-aya-bpf-loader-go-adoption-contract-v1"
        );
        assert_eq!(json["binary"].as_str().unwrap(), "dae-aya-bpf-loader");
        assert!(
            json["go_userspace_outbound_remains_authoritative"]
                .as_bool()
                .unwrap()
        );
        assert!(!json["kernel_ebpf_program_rewrite"].as_bool().unwrap());
        assert_eq!(json["default_object_source"].as_str().unwrap(), "c-aya");
        assert!(
            json["rust_aya_skeleton_object_supported"]
                .as_bool()
                .unwrap()
        );
        assert_eq!(json["maps"].as_array().unwrap().len(), 13);
        assert_eq!(json["tc_programs"].as_array().unwrap().len(), 6);
        assert_eq!(json["cgroup_programs"].as_array().unwrap().len(), 6);
        assert_eq!(
            json["supported_object_sources"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["c-aya", "rust-aya-skeleton"]
        );
    }

    #[test]
    fn load_pin_requires_full_param_set() {
        let output = run_with_args(["bpf-loader", "load-pin", "--pin-root", "/tmp/dae"]);
        assert_eq!(output.exit_code, 2);
        assert!(output.stderr.contains("--tproxy-port"));
    }

    #[test]
    fn load_pin_accepts_explicit_rust_skeleton_source() {
        let options = parse_load_pin_options(&[
            "--object-source=rust-aya-skeleton".to_owned(),
            "--object=/tmp/dae-ebpf-program".to_owned(),
            "--pin-root=/tmp/dae".to_owned(),
            "--tproxy-port=12345".to_owned(),
            "--control-plane-pid=7".to_owned(),
            "--dae0-ifindex=8".to_owned(),
            "--dae-netns-id=9".to_owned(),
            "--dae0peer-mac=02:00:00:00:00:01".to_owned(),
            "--has-bpf-get-current-task=true".to_owned(),
        ])
        .unwrap();
        assert_eq!(
            options.object_source,
            Some(BpfObjectSource::RustAyaSkeleton)
        );
        assert_eq!(options.object, Some(PathBuf::from("/tmp/dae-ebpf-program")));

        let err = parse_load_pin_options(&[
            "--object-source=rust-aya-skeleton".to_owned(),
            "--pin-root=/tmp/dae".to_owned(),
            "--tproxy-port=12345".to_owned(),
            "--control-plane-pid=7".to_owned(),
            "--dae0-ifindex=8".to_owned(),
            "--dae-netns-id=9".to_owned(),
            "--dae0peer-mac=02:00:00:00:00:01".to_owned(),
            "--has-bpf-get-current-task=true".to_owned(),
        ])
        .unwrap_err();
        assert!(err.contains("rust-aya-skeleton requires --object"));
    }

    #[test]
    fn trace_loader_contract_declares_non_default_scope() {
        let output = run_with_args(["trace-loader", "contract"]);
        assert_eq!(output.exit_code, 0, "{}", output.stderr);
        let json: Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(
            json["name"].as_str().unwrap(),
            "rust-aya-trace-loader-contract-v1"
        );
        assert!(!json["core_sideload_enabled"].as_bool().unwrap());
        assert!(!json["go_trace_adoption_ready"].as_bool().unwrap());
        assert!(!json["default_daemon_path"].as_bool().unwrap());
        assert!(!json["kernel_ebpf_program_rewrite"].as_bool().unwrap());
        assert_eq!(
            json["non_default_smokes"]["attach_ringbuf"]
                .as_str()
                .unwrap(),
            "disabled"
        );
        assert!(
            json["disabled_reason"]
                .as_str()
                .unwrap()
                .contains("temporarily disabled")
        );
    }

    #[test]
    fn trace_loader_core_sideload_commands_are_disabled() {
        let output = run_with_args([
            "trace-loader",
            "load-pin",
            "--object",
            "/tmp/trace.o",
            "--pin-root",
            "/sys/fs/bpf/trace",
            "--ip-version",
            "4",
            "--l4-proto",
            "6",
            "--port",
            "443",
            "--ringbuf-size",
            "65536",
        ]);
        assert_eq!(output.exit_code, 1);
        assert!(output.stderr.contains("temporarily disabled"));

        let output = run_with_args([
            "trace-loader",
            "attach-ringbuf-smoke",
            "--object",
            "/tmp/trace.o",
            "--target",
            "ip_rcv_core",
        ]);
        assert_eq!(output.exit_code, 1);
        assert!(output.stderr.contains("temporarily disabled"));
    }

    #[test]
    fn trace_attach_ringbuf_smoke_options_parse_explicit_target_and_defaults() {
        let options = parse_trace_attach_ringbuf_smoke_options(&[
            "--object=/tmp/trace.o".to_owned(),
            "--target=ip_rcv_core".to_owned(),
        ])
        .unwrap();
        assert_eq!(options.object, PathBuf::from("/tmp/trace.o"));
        assert_eq!(options.target, "ip_rcv_core");
        assert_eq!(options.program_name, "kprobe_skb_1");
        assert_eq!(options.ip_version, 4);
        assert_eq!(options.l4_proto, 6);
        assert_eq!(options.port, 443);
        assert_eq!(options.ringbuf_size, 65_536);
        assert_eq!(options.trigger, TraceLoaderAttachSmokeTrigger::LoopbackUdp);
        assert_eq!(options.trigger_count, 4);
        assert_eq!(options.poll_attempts, 50);

        let explicit = parse_trace_attach_ringbuf_smoke_options(&[
            "--object".to_owned(),
            "/tmp/trace.o".to_owned(),
            "--target".to_owned(),
            "security_file_open".to_owned(),
            "--program-name".to_owned(),
            "kprobe_skb_1".to_owned(),
            "--trigger".to_owned(),
            "open-proc-self-stat".to_owned(),
            "--trigger-count".to_owned(),
            "2".to_owned(),
            "--poll-attempts".to_owned(),
            "3".to_owned(),
        ])
        .unwrap();
        assert_eq!(explicit.target, "security_file_open");
        assert_eq!(
            explicit.trigger,
            TraceLoaderAttachSmokeTrigger::OpenProcSelfStat
        );
        assert_eq!(explicit.trigger_count, 2);
        assert_eq!(explicit.poll_attempts, 3);

        let err = parse_trace_attach_ringbuf_smoke_options(&[
            "--object=/tmp/trace.o".to_owned(),
            "--trigger=bad".to_owned(),
        ])
        .unwrap_err();
        assert!(err.contains("bad trace attach smoke trigger"));
    }

    #[test]
    fn cgroup_monitor_contract_declares_pinned_link_lifetime() {
        let output = run_with_args(["cgroup-monitor", "contract"]);
        assert_eq!(output.exit_code, 0, "{}", output.stderr);
        let json: Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(
            json["name"].as_str().unwrap(),
            "rust-cgroup-pname-monitor-attach-contract-v1"
        );
        assert!(
            json["go_pname_routing_semantics_remain_authoritative"]
                .as_bool()
                .unwrap()
        );
        assert_eq!(json["attach_matrix"].as_array().unwrap().len(), 6);
    }

    #[test]
    fn map_stats_count_requires_map_specs() {
        let output = run_with_args(["map-stats", "count"]);
        assert_eq!(output.exit_code, 2);
        assert!(output.stderr.contains("--map name:id"));
        assert_eq!(
            parse_map_count_request("routing_tuples_map:7").unwrap(),
            MapStatsCountRequest {
                name: "routing_tuples_map".to_owned(),
                id: 7,
            }
        );
    }

    #[test]
    fn cgroup_monitor_attach_pin_requires_paths() {
        let output = run_with_args(["cgroup-monitor", "attach-pin", "--program-root", "/bpffs/p"]);
        assert_eq!(output.exit_code, 2);
        assert!(output.stderr.contains("--link-root"));
        let options = parse_cgroup_monitor_attach_pin_options(&[
            "--program-root=/bpffs/programs".to_owned(),
            "--link-root=/bpffs/links".to_owned(),
            "--cgroup-path=/sys/fs/cgroup".to_owned(),
        ])
        .unwrap();
        assert_eq!(
            options,
            CgroupMonitorAttachPinOptions {
                program_root: PathBuf::from("/bpffs/programs"),
                link_root: PathBuf::from("/bpffs/links"),
                cgroup_path: PathBuf::from("/sys/fs/cgroup"),
            }
        );
    }

    #[test]
    fn tc_attach_contract_declares_pinned_lifetime_and_matrix() {
        let output = run_with_args(["tc-attach", "contract"]);
        assert_eq!(output.exit_code, 0, "{}", output.stderr);
        let json: Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(
            json["name"].as_str().unwrap(),
            "rust-tc-tcx-attach-pin-contract-v1"
        );
        assert!(
            json["go_routing_dns_sniff_group_remain_authoritative"]
                .as_bool()
                .unwrap()
        );
        assert_eq!(json["attach_matrix"].as_array().unwrap().len(), 6);
    }

    #[test]
    fn tc_attach_pin_requires_full_spec() {
        let output = run_with_args(["tc-attach", "attach-pin", "--program-root", "/bpffs/p"]);
        assert_eq!(output.exit_code, 2);
        assert!(output.stderr.contains("--link-root"));
        let options = parse_tc_attach_pin_options(&[
            "--program-root=/bpffs/programs".to_owned(),
            "--link-root=/bpffs/tc-links/one".to_owned(),
            "--program-name=tproxy_lan_ingress_l2".to_owned(),
            "--iface=eth0".to_owned(),
            "--direction=ingress".to_owned(),
            "--priority=2".to_owned(),
            "--handle=539164676".to_owned(),
            "--backend=tc-netlink".to_owned(),
            "--filter-name=dae_lan_ingress_l2".to_owned(),
        ])
        .unwrap();
        assert_eq!(
            options,
            TcAttachPinOptions {
                program_root: PathBuf::from("/bpffs/programs"),
                link_root: PathBuf::from("/bpffs/tc-links/one"),
                program_name: "tproxy_lan_ingress_l2".to_owned(),
                iface: "eth0".to_owned(),
                netns: None,
                direction: dae_ebpf_support::TcAttachDirection::Ingress,
                priority: 2,
                handle: 539164676,
                backend: dae_ebpf_support::AttachBackend::TcNetlink,
                filter_name: Some("dae_lan_ingress_l2".to_owned()),
            }
        );
    }

    #[test]
    fn tproxy_listener_contract_keeps_go_handlers_authoritative() {
        let output = run_with_args(["tproxy-listener", "contract"]);
        assert_eq!(output.exit_code, 0, "{}", output.stderr);
        let json: Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(
            json["name"].as_str().unwrap(),
            "rust-tproxy-listener-sockmap-handoff-contract-v1"
        );
        assert!(
            json["go_userspace_tcp_udp_handlers_remain_authoritative"]
                .as_bool()
                .unwrap()
        );
        assert_eq!(
            json["listen_socket_map"]["key_0"].as_str().unwrap(),
            "tcp listener fd"
        );
        assert_eq!(
            json["listen_socket_map"]["key_1"].as_str().unwrap(),
            "udp socket fd"
        );
    }

    #[test]
    fn tproxy_listener_commands_require_handoff_and_socket_fds() {
        let output = run_with_args(["tproxy-listener", "open-handoff", "--map-id", "7"]);
        assert_eq!(output.exit_code, 2);
        assert!(output.stderr.contains("--port"));
        let open = parse_tproxy_listener_open_handoff_options(&[
            "--map-id=7".to_owned(),
            "--port=12345".to_owned(),
            "--handoff-fd=3".to_owned(),
        ])
        .unwrap();
        assert_eq!(
            open,
            TproxyListenerOpenHandoffOptions {
                map_id: 7,
                port: 12345,
                handoff_fd: 3,
            }
        );

        let output = run_with_args(["tproxy-listener", "update-map", "--map-id", "7"]);
        assert_eq!(output.exit_code, 2);
        assert!(output.stderr.contains("--tcp-fd"));
        let update = parse_tproxy_listener_update_map_options(&[
            "--map-id=7".to_owned(),
            "--tcp-fd=3".to_owned(),
            "--udp-fd=4".to_owned(),
        ])
        .unwrap();
        assert_eq!(
            update,
            TproxyListenerUpdateMapOptions {
                map_id: 7,
                tcp_fd: 3,
                udp_fd: 4,
            }
        );
    }

    #[test]
    fn connectivity_map_update_requires_full_key() {
        let output = run_with_args(["connectivity-map", "update", "--map-id", "1"]);
        assert_eq!(output.exit_code, 2);
        assert!(output.stderr.contains("--outbound"));
        let output = run_with_args(["connectivity-map", "serve"]);
        assert_eq!(output.exit_code, 2);
        assert!(output.stderr.contains("stdio entrypoint"));
        let options = parse_connectivity_map_update_options(&[
            "--map-id=7".to_owned(),
            "--outbound=2".to_owned(),
            "--l4-proto=6".to_owned(),
            "--ip-version=4".to_owned(),
            "--alive=true".to_owned(),
            "--is-init=true".to_owned(),
            "--dryrun=false".to_owned(),
        ])
        .unwrap();
        assert_eq!(
            options,
            ConnectivityMapUpdateOptions {
                map_id: 7,
                outbound: 2,
                l4_proto: 6,
                ip_version: 4,
                alive: true,
                is_init: true,
                dryrun: false,
            }
        );
    }

    #[test]
    fn routing_map_apply_parser_preserves_match_set_shape() {
        let request = parse_routing_map_apply_request(
            r#"{
              "routing_map_id": 7,
              "lpm_array_map_id": 8,
              "lpm_entries": [{"index": 3, "map_id": 9}],
              "lpm_maps": [{
                "index": 4,
                "flags": 1,
                "max_entries": 2048,
                "key_size": 20,
                "value_size": 4,
                "entries": [{
                  "key": {"prefix_len": 128, "data": [0,0,65535,1]},
                  "value": 1
                }]
              }],
              "routing_entries": [{
                "index": 0,
                "value": {
                  "value": [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                  "not": false,
                  "type": 10,
                  "outbound": 2,
                  "must": true,
                  "mark": 134217728
                }
              }]
            }"#,
        )
        .unwrap();
        assert_eq!(request.routing_map_id, 7);
        assert_eq!(request.lpm_array_map_id, 8);
        assert_eq!(request.lpm_entries[0].map_id, 9);
        assert_eq!(request.lpm_maps[0].index, 4);
        assert_eq!(request.lpm_maps[0].entries[0].key.prefix_len, 128);
        assert_eq!(request.lpm_maps[0].entries[0].value, 1);
        assert_eq!(request.routing_entries[0].value.value[0], 1);
        assert_eq!(request.routing_entries[0].value.kind, 10);
        assert_eq!(request.routing_entries[0].value.must, 1);

        let output = run_with_args(["routing-map", "apply"]);
        assert_eq!(output.exit_code, 2);
        assert!(output.stderr.contains("stdio entrypoint"));
    }

    #[test]
    fn domain_routing_map_apply_parser_preserves_bitmap_shape() {
        let bitmap = vec![1_u32; 32];
        let payload = json!({
            "map_id": 7,
            "updates": [{
                "key": [0, 0, 65535, 1],
                "bitmap": bitmap,
            }],
            "deletes": [[0, 0, 65535, 2]],
        })
        .to_string();
        let request = parse_domain_routing_map_apply_request(&payload).unwrap();
        assert_eq!(request.map_id, 7);
        assert_eq!(request.updates[0].key, [0, 0, 65535, 1]);
        assert_eq!(request.updates[0].value.bitmap[31], 1);
        assert_eq!(request.deletes[0], [0, 0, 65535, 2]);

        let output = run_with_args(["domain-routing-map", "apply"]);
        assert_eq!(output.exit_code, 2);
        assert!(output.stderr.contains("stdio entrypoint"));
        let output = run_with_args(["domain-routing-map", "serve"]);
        assert_eq!(output.exit_code, 2);
        assert!(output.stderr.contains("stdio entrypoint"));
    }

    #[test]
    fn connectivity_map_serve_dryrun_skip_does_not_open_map() {
        let mut cache = dae_ebpf_support::ConnectivityMapFdCache::default();
        let response = handle_connectivity_map_serve_line(
            &mut cache,
            r#"{"map_id":0,"outbound":2,"l4_proto":6,"ip_version":4,"alive":true,"is_init":false,"dryrun":true}"#,
        );
        let json: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["status"].as_str().unwrap(), "pass");
        assert!(!json["written"].as_bool().unwrap());
        assert_eq!(json["key"]["outbound"].as_u64().unwrap(), 2);
        assert!(cache.is_empty());
    }

    #[test]
    fn connectivity_map_serve_binary_dryrun_skip_does_not_open_map() {
        let mut cache = dae_ebpf_support::ConnectivityMapFdCache::default();
        let response = handle_connectivity_map_serve_binary_request(
            &mut cache,
            [
                0,
                0,
                0,
                0, // map id
                2,
                6,
                4,           // outbound, l4 proto, ip version
                0x01 | 0x04, // alive + dryrun, no is-init
            ],
        );
        assert_eq!(response[0], 0);
        assert_eq!(response[1], 0);
        assert_eq!(
            u32::from_le_bytes([response[4], response[5], response[6], response[7]]),
            0
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn connectivity_map_serve_reports_malformed_requests() {
        let mut cache = dae_ebpf_support::ConnectivityMapFdCache::default();
        let response = handle_connectivity_map_serve_line(&mut cache, "{bad-json");
        let json: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["status"].as_str().unwrap(), "error");
        assert!(
            json["error"]
                .as_str()
                .unwrap()
                .contains("bad connectivity-map request")
        );
    }

    #[test]
    fn domain_routing_map_serve_reports_malformed_requests() {
        let response = handle_domain_routing_map_serve_line("{bad-json");
        let json: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["status"].as_str().unwrap(), "error");
        assert!(
            json["error"]
                .as_str()
                .unwrap()
                .contains("bad domain-routing-map request")
        );
    }

    #[test]
    fn parses_mac_and_bool_values() {
        assert_eq!(
            parse_mac("aa:bb:cc:dd:ee:ff").unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
        assert!(parse_bool("on").unwrap());
        assert!(!parse_bool("off").unwrap());
    }
}
