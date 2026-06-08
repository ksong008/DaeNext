fn run_default_optin_command(args: &[String], version: &str) -> DaemonOutput {
    let DefaultOptinParsedArgs {
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
        production_runtime_native_ebpf_opt_in,
        production_runtime_native_ebpf_backend,
        production_runtime_native_ebpf_completed_a3_admission,
        production_runtime_fallback_retirement_product_chain_recertified,
        production_runtime_fallback_retirement_explicit_user_approval,
        production_runtime_native_ebpf_object,
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
        matched_default_benchmark,
        matched_benchmark_iterations,
        matched_ready_timeout_ms,
        go_tool,
        go_work,
        go_binary,
        rust_binary,
        source_dir,
        product_chain_recertification,
        product_chain_dae_repo,
        product_chain_dae_wing_repo,
        product_chain_daed_repo,
        product_chain_outbound_repo,
        product_chain_quic_go_repo,
        product_chain_service_file,
        product_chain_go_mod_file,
        product_chain_admission_evidence,
        request_default_path_mutation,
        plan_production_run_command_replacement,
        execute_production_run_command_replacement,
        plan_production_run_command_apply,
        allow_host_default_path_mutation,
        plan_local_validation_fresh_install,
        product_chain_fresh_install_binary_source,
        mut product_chain_resident_default_daemon_binary_source,
        exit_after_ready,
    } = match parse_default_optin_args(args) {
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
        || matched_default_benchmark
        || product_chain_recertification
        || request_default_path_mutation
        || plan_production_run_command_replacement
        || execute_production_run_command_replacement
        || plan_production_run_command_apply
        || allow_host_default_path_mutation
        || plan_local_validation_fresh_install
        || product_chain_resident_default_daemon_binary_source.is_some();
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
    options.production_runtime_owner.native_ebpf_opt_in = production_runtime_native_ebpf_opt_in;
    options.production_runtime_owner.native_ebpf_backend = production_runtime_native_ebpf_backend;
    options
        .production_runtime_owner
        .native_ebpf_completed_a3_admission = production_runtime_native_ebpf_completed_a3_admission;
    options
        .production_runtime_owner
        .fallback_retirement_product_chain_recertified =
        production_runtime_fallback_retirement_product_chain_recertified;
    options
        .production_runtime_owner
        .fallback_retirement_explicit_user_approval =
        production_runtime_fallback_retirement_explicit_user_approval;
    options.production_runtime_owner.native_ebpf_object = production_runtime_native_ebpf_object;
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
    options.matched_default_benchmark.execute = matched_default_benchmark;
    options.matched_default_benchmark.ack_root_gate = ack_root_gate;
    options.matched_default_benchmark.iterations = matched_benchmark_iterations;
    options.matched_default_benchmark.ready_timeout_ms = matched_ready_timeout_ms;
    if let Some(go_tool) = go_tool {
        options.matched_default_benchmark.go_tool = go_tool;
    }
    options.matched_default_benchmark.go_work = go_work;
    options.matched_default_benchmark.go_binary = go_binary;
    options.matched_default_benchmark.rust_binary = rust_binary;
    if let Some(source_dir) = source_dir {
        options.matched_default_benchmark.source_dir = source_dir;
    }
    options.product_chain_recertification.execute = product_chain_recertification;
    options
        .product_chain_recertification
        .default_path_mutation_requested = request_default_path_mutation;
    options
        .product_chain_recertification
        .production_run_command_replacement_dry_run_requested =
        plan_production_run_command_replacement;
    options
        .product_chain_recertification
        .production_run_command_replacement_execute_requested =
        execute_production_run_command_replacement;
    options
        .product_chain_recertification
        .production_run_command_replacement_apply_plan_requested =
        plan_production_run_command_apply;
    options
        .product_chain_recertification
        .host_default_path_mutation_allow_requested = allow_host_default_path_mutation;
    options
        .product_chain_recertification
        .local_validation_fresh_install_plan_requested = plan_local_validation_fresh_install;
    if plan_local_validation_fresh_install {
        options
            .product_chain_recertification
            .local_validation_config_source = Some(options.config.clone());
        options
            .product_chain_recertification
            .local_validation_binary_source = product_chain_fresh_install_binary_source.clone();
        if product_chain_resident_default_daemon_binary_source.is_none() {
            product_chain_resident_default_daemon_binary_source =
                product_chain_fresh_install_binary_source;
        }
    }
    if let Some(path) = product_chain_resident_default_daemon_binary_source {
        options
            .product_chain_recertification
            .resident_default_daemon_binary_source = Some(path);
    }
    if let Some(path) = product_chain_dae_repo {
        options.product_chain_recertification.dae_repo = path;
    }
    if let Some(path) = product_chain_dae_wing_repo {
        options.product_chain_recertification.dae_wing_repo = path;
    }
    if let Some(path) = product_chain_daed_repo {
        options.product_chain_recertification.daed_repo = path;
    }
    if let Some(path) = product_chain_outbound_repo {
        options.product_chain_recertification.outbound_repo = path;
    }
    if let Some(path) = product_chain_quic_go_repo {
        options.product_chain_recertification.quic_go_repo = path;
    }
    if let Some(path) = product_chain_service_file {
        options.product_chain_recertification.service_file = path;
    }
    if let Some(path) = product_chain_go_mod_file {
        options.product_chain_recertification.go_mod_file = path;
    }
    if let Some(path) = product_chain_admission_evidence {
        match product_chain_admission_from_run_report(&path) {
            Ok(admission) => {
                options.product_chain_admission_override = Some(admission);
                options.product_chain_admission_source = Some(path);
            }
            Err(err) => return DaemonOutput::error(err),
        }
    }

    match run_default_optin_report(&options, version) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}
