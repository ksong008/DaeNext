use std::os::fd::AsRawFd;
use std::path::PathBuf;

use serde_json::json;

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
    pin_root: PathBuf,
    tproxy_port: u16,
    control_plane_pid: u32,
    dae0_ifindex: u32,
    dae_netns_id: u32,
    dae0peer_mac: [u8; 6],
    has_bpf_get_current_task: bool,
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
        Some(subcommand) => LoaderOutput::usage(format!(
            "unsupported connectivity-map subcommand: {subcommand}"
        )),
        None => LoaderOutput::usage("missing connectivity-map subcommand"),
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
        Some(subcommand) => {
            LoaderOutput::usage(format!("unsupported trace-loader subcommand: {subcommand}"))
        }
        None => LoaderOutput::usage("missing trace-loader subcommand"),
    }
}

fn run_contract() -> LoaderOutput {
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "name": "rust-aya-bpf-loader-go-adoption-contract-v1",
            "binary": "dae-aya-bpf-loader",
            "compiled_native_ebpf": cfg!(feature = "native-ebpf"),
            "scope": "Rust/Aya loads the existing C eBPF object and pins all maps/programs for Go control-plane adoption",
            "go_userspace_outbound_remains_authoritative": true,
            "go_bpf_loader_removed_when_opted_in": true,
            "kernel_ebpf_program_rewrite": false,
            "required_pins": {
                "maps": "pin_root/maps/<map_name>",
                "programs": "pin_root/programs/<program_name>"
            },
            "object_source": "optional --object path or embedded native Aya object built from control/kern/tproxy.c with DAE_AYA_EBPF_OBJECT",
            "param_source": {
                "tproxy_port": "host-order u16, converted to BPF big-endian PARAM",
                "control_plane_pid": "Go control-plane pid",
                "dae0_ifindex": "initialized dae0 ifindex",
                "dae_netns_id": "initialized dae netns id",
                "dae0peer_mac": "initialized dae0peer mac",
                "has_bpf_get_current_task": "Go feature probe result"
            }
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
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "name": "rust-aya-trace-loader-contract-v1",
            "binary": "dae-aya-bpf-loader",
            "compiled_native_ebpf": cfg!(feature = "native-ebpf"),
            "scope": "Rust/Aya loads the existing trace C eBPF object and pins maps/programs for Go trace attach and ringbuf adoption",
            "default_daemon_path": false,
            "kernel_ebpf_program_rewrite": false,
            "required_pins": {
                "maps": "pin_root/maps/{events,skb_addresses}",
                "programs": "pin_root/programs/kprobe_skb_*"
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
        json!({
            "status": "pass",
            "loader": "rust",
            "scope": "outbound-connectivity-map-update",
            "map_id": options.map_id,
            "written": plan.written,
            "key": {
                "outbound": plan.key.outbound,
                "l4proto": plan.key.l4proto,
                "ipversion": plan.key.ipversion,
            },
            "value": plan.value,
            "dryrun": options.dryrun,
            "is_init": options.is_init,
        })
    ))
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
    LoaderOutput::error("trace-loader load-pin requires dae-aya-bpf-loader feature native-ebpf")
}

#[cfg(feature = "native-ebpf")]
fn run_load_pin(options: BpfLoaderLoadPinOptions) -> LoaderOutput {
    use dae_ebpf_support::{
        AyaUserspaceLoaderOptions, DaeParamInput, build_dae_param, load_aya_userspace_object,
        pin_aya_loaded_object_for_go_adoption,
    };

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
    let object_source = if cleanup_object.is_some() {
        "embedded-native-aya"
    } else {
        "explicit"
    };
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
    Ok(BpfLoaderLoadPinOptions {
        object,
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
    }

    #[test]
    fn load_pin_requires_full_param_set() {
        let output = run_with_args(["bpf-loader", "load-pin", "--pin-root", "/tmp/dae"]);
        assert_eq!(output.exit_code, 2);
        assert!(output.stderr.contains("--tproxy-port"));
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
        assert!(!json["default_daemon_path"].as_bool().unwrap());
        assert!(!json["kernel_ebpf_program_rewrite"].as_bool().unwrap());
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
    fn parses_mac_and_bool_values() {
        assert_eq!(
            parse_mac("aa:bb:cc:dd:ee:ff").unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
        assert!(parse_bool("on").unwrap());
        assert!(!parse_bool("off").unwrap());
    }
}
