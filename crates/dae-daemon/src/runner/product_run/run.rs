use super::*;
pub(crate) fn run_product_run_command(args: &[String], version: &str) -> DaemonOutput {
    let ProductRunParsedArgs {
        root,
        root_explicit,
        config,
        logfile,
        service_pid_file,
        service_progress_file,
        service_abort_file,
        service_ready_file,
        disable_timestamp,
        disable_pidfile,
        disable_sudo,
        listener_smoke,
        reload_smoke,
        production_runtime_owner,
        production_runtime_active_tcp,
        production_dataplane_smoke,
        ack_root_gate,
        production_runtime_tproxy_port,
        production_runtime_dae_netns_id,
        production_runtime_netns_link_mode,
        production_runtime_object,
        production_runtime_native_ebpf_requested,
        production_runtime_native_ebpf_backend,
        production_runtime_native_ebpf_local_admission,
        production_runtime_active_tcp_target_ip,
        production_runtime_active_tcp_client_ip,
        production_runtime_active_tcp_target_port,
        production_runtime_active_tcp_so_mark,
        production_runtime_active_tcp_mptcp,
        production_runtime_active_tcp_relay,
        production_runtime_active_tcp_upstream_mptcp,
        production_runtime_active_tcp_benchmark_iters,
        production_runtime_active_udp,
        production_runtime_active_udp_target_ip,
        production_runtime_active_udp_target_port,
        production_runtime_active_udp_benchmark_iters,
        production_runtime_active_dns,
        production_runtime_active_dns_target_ip,
        production_runtime_active_dns_target_port,
        production_runtime_active_dns_upstream_ip,
        production_runtime_active_dns_upstream_port,
        production_runtime_active_dns_qname,
        production_runtime_active_dns_benchmark_iters,
        production_runtime_reload_parity,
        dataplane_benchmark_iters,
        exit_after_ready,
    } = match parse_product_run_args(args) {
        Ok(parsed) => parsed,
        Err(output) => return output,
    };
    let Some(config) = config else {
        return DaemonOutput::usage("run requires -c/--config");
    };
    let bounded_report_requested = root_explicit
        || exit_after_ready
        || !listener_smoke
        || !reload_smoke
        || production_runtime_owner
        || production_runtime_active_tcp
        || production_runtime_active_tcp_relay
        || production_runtime_active_udp
        || production_runtime_active_dns
        || production_runtime_reload_parity
        || production_dataplane_smoke
        || exit_after_ready;
    if !bounded_report_requested {
        let mut options = ResidentRunOptions::for_config(config);
        options.logfile = logfile;
        options.disable_timestamp = disable_timestamp;
        options.disable_pidfile = disable_pidfile;
        options.disable_sudo = disable_sudo;
        if let Some(path) = service_pid_file {
            options.pid_file = path;
        }
        if let Some(path) = service_progress_file {
            options.progress_file = path;
        }
        if let Some(path) = service_abort_file {
            options.abort_file = path;
        }
        options.ready_record_file = service_ready_file;
        return match run_resident_service(&options) {
            Ok(()) => DaemonOutput::ok(String::new()),
            Err(err) => DaemonOutput::error(err),
        };
    }
    let mut options = RunOptions::under_root(root, config);
    if let Some(logfile) = logfile {
        options.logfile = logfile;
    }
    options.disable_timestamp = disable_timestamp;
    options.disable_pidfile = disable_pidfile;
    options.disable_sudo = disable_sudo;
    options.listener_smoke = listener_smoke;
    options.reload_smoke = reload_smoke;
    options.production_runtime_owner.execute = production_runtime_owner;
    options.production_runtime_owner.ack_root_gate = ack_root_gate;
    options.production_runtime_owner.tproxy_port = production_runtime_tproxy_port;
    options.production_runtime_owner.dae_netns_id = production_runtime_dae_netns_id;
    options.production_runtime_owner.netns_link_mode = production_runtime_netns_link_mode;
    options.production_runtime_owner.execute_active_tcp = production_runtime_active_tcp;
    options.production_runtime_owner.execute_active_tcp_relay = production_runtime_active_tcp_relay;
    options.production_runtime_owner.execute_active_udp = production_runtime_active_udp;
    options.production_runtime_owner.execute_active_dns = production_runtime_active_dns;
    options
        .production_runtime_owner
        .execute_reload_runtime_parity = production_runtime_reload_parity;
    options.production_runtime_owner.native_ebpf_requested =
        production_runtime_native_ebpf_requested;
    options.production_runtime_owner.native_ebpf_embedded_object =
        production_runtime_native_ebpf_requested && cfg!(feature = "native-ebpf");
    options.production_runtime_owner.native_ebpf_backend = production_runtime_native_ebpf_backend;
    options.production_runtime_owner.native_ebpf_local_admission =
        production_runtime_native_ebpf_local_admission;
    if let Some(source_object) = production_runtime_object {
        options.production_runtime_owner.source_object = source_object;
    }
    if let Some(target_ip) = production_runtime_active_tcp_target_ip {
        options.production_runtime_owner.active_tcp_target_ip = target_ip;
    }
    if let Some(client_ip) = production_runtime_active_tcp_client_ip {
        options.production_runtime_owner.active_tcp_client_ip = client_ip;
    }
    if let Some(target_port) = production_runtime_active_tcp_target_port {
        options.production_runtime_owner.active_tcp_target_port = target_port;
    }
    if let Some(so_mark) = production_runtime_active_tcp_so_mark {
        options.production_runtime_owner.active_tcp_so_mark = so_mark;
    }
    if let Some(mptcp) = production_runtime_active_tcp_mptcp {
        options.production_runtime_owner.active_tcp_mptcp = mptcp;
    }
    if let Some(upstream_mptcp) = production_runtime_active_tcp_upstream_mptcp {
        options.production_runtime_owner.active_tcp_upstream_mptcp = upstream_mptcp;
    }
    if let Some(iterations) = production_runtime_active_tcp_benchmark_iters {
        options.production_runtime_owner.active_tcp_benchmark_iters = iterations;
    }
    if let Some(target_ip) = production_runtime_active_udp_target_ip {
        options.production_runtime_owner.active_udp_target_ip = target_ip;
    }
    if let Some(target_port) = production_runtime_active_udp_target_port {
        options.production_runtime_owner.active_udp_target_port = target_port;
    }
    if let Some(iterations) = production_runtime_active_udp_benchmark_iters {
        options.production_runtime_owner.active_udp_benchmark_iters = iterations;
    }
    if let Some(target_ip) = production_runtime_active_dns_target_ip {
        options.production_runtime_owner.active_dns_target_ip = target_ip;
    }
    if let Some(target_port) = production_runtime_active_dns_target_port {
        options.production_runtime_owner.active_dns_target_port = target_port;
    }
    if let Some(upstream_ip) = production_runtime_active_dns_upstream_ip {
        options.production_runtime_owner.active_dns_upstream_ip = upstream_ip;
    }
    if let Some(upstream_port) = production_runtime_active_dns_upstream_port {
        options.production_runtime_owner.active_dns_upstream_port = upstream_port;
    }
    if let Some(qname) = production_runtime_active_dns_qname {
        options.production_runtime_owner.active_dns_qname = qname;
    }
    if let Some(iterations) = production_runtime_active_dns_benchmark_iters {
        options.production_runtime_owner.active_dns_benchmark_iters = iterations;
    }
    options.production_dataplane_harness.execute = production_dataplane_smoke;
    options.production_dataplane_harness.ack_root_gate = ack_root_gate;
    options.production_dataplane_harness.benchmark_iters = dataplane_benchmark_iters;

    match run_product_run_report(&options, version) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}
