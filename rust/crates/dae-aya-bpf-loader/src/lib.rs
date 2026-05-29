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

pub fn run_with_args(args: impl IntoIterator<Item = impl Into<String>>) -> LoaderOutput {
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("bpf-loader") => run_bpf_loader_command(&args[1..]),
        Some("map-stats") => run_map_stats_command(&args[1..]),
        Some("connectivity-map") => run_connectivity_map_command(&args[1..]),
        Some("trace-loader") => run_trace_loader_command(&args[1..]),
        Some("contract") if args.len() == 1 => run_contract(),
        Some("load-pin") => run_load_pin_command(&args[1..]),
        Some(command) => {
            LoaderOutput::usage(format!("unsupported dae-aya-bpf-loader command: {command}"))
        }
        None => LoaderOutput::usage("missing dae-aya-bpf-loader command"),
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

#[cfg(feature = "native-ebpf")]
fn mac_string(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
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
