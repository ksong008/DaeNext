use super::*;
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

pub(super) fn run_cgroup_monitor_command(args: &[String]) -> LoaderOutput {
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

pub(super) fn run_connectivity_map_command(args: &[String]) -> LoaderOutput {
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

pub(super) fn run_domain_routing_map_command(args: &[String]) -> LoaderOutput {
    match args.first().map(String::as_str) {
        Some("apply") if args.len() == 1 => LoaderOutput::usage(
            "domain-routing-map apply requires the dae-aya-bpf-loader stdio entrypoint",
        ),
        Some("serve") if args.len() == 1 => LoaderOutput::usage(
            "domain-routing-map serve requires the dae-aya-bpf-loader stdio entrypoint",
        ),
        Some("serve-owner") if args.len() == 1 => LoaderOutput::usage(
            "domain-routing-map serve-owner requires the dae-aya-bpf-loader stdio entrypoint",
        ),
        Some(subcommand) => LoaderOutput::usage(format!(
            "unsupported domain-routing-map subcommand: {subcommand}"
        )),
        None => LoaderOutput::usage("missing domain-routing-map subcommand"),
    }
}

pub(super) fn run_routing_map_command(args: &[String]) -> LoaderOutput {
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

pub(super) fn run_tc_attach_command(args: &[String]) -> LoaderOutput {
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

pub(super) fn run_tproxy_listener_command(args: &[String]) -> LoaderOutput {
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

pub(super) fn run_map_stats_command(args: &[String]) -> LoaderOutput {
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

pub(super) fn run_trace_loader_command(args: &[String]) -> LoaderOutput {
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
