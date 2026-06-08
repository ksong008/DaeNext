fn parse_default_optin_args(args: &[String]) -> Result<DefaultOptinParsedArgs, DaemonOutput> {
    macro_rules! usage {
        ($($arg:tt)*) => {
            return Err(DaemonOutput::usage($($arg)*))
        };
    }
    let mut root = default_run_root();
    let mut root_explicit = false;
    let mut config: Option<PathBuf> = None;
    let mut logfile: Option<PathBuf> = None;
    let mut service_pid_file: Option<PathBuf> = None;
    let mut service_progress_file: Option<PathBuf> = None;
    let mut service_abort_file: Option<PathBuf> = None;
    let mut service_ready_file: Option<PathBuf> = None;
    let mut disable_timestamp = false;
    let mut disable_pidfile = false;
    let mut disable_sudo = false;
    let mut listener_smoke = true;
    let mut reload_smoke = true;
    let mut production_runtime_owner = false;
    let mut production_runtime_active_tcp = false;
    let mut production_dataplane_smoke = false;
    let mut ack_root_gate = false;
    let mut production_runtime_tproxy_port = 12345_u16;
    let mut production_runtime_dae_netns_id = 49_u32;
    let mut production_runtime_netns_link_mode = NetnsLinkMode::Auto;
    let mut production_runtime_object: Option<PathBuf> = None;
    let mut production_runtime_native_ebpf_opt_in = false;
    let mut production_runtime_native_ebpf_backend = AttachBackend::Auto;
    let mut production_runtime_native_ebpf_completed_a3_admission = false;
    let mut production_runtime_fallback_retirement_product_chain_recertified = false;
    let mut production_runtime_fallback_retirement_explicit_user_approval = false;
    let mut production_runtime_native_ebpf_object: Option<PathBuf> = None;
    let mut production_runtime_active_tcp_target_ip: Option<String> = None;
    let mut production_runtime_active_tcp_client_ip: Option<String> = None;
    let mut production_runtime_active_tcp_target_port: Option<u16> = None;
    let mut production_runtime_active_tcp_so_mark: Option<u32> = None;
    let mut production_runtime_active_tcp_mptcp: Option<bool> = None;
    let mut production_runtime_active_tcp_relay = false;
    let mut production_runtime_active_tcp_upstream_mptcp: Option<bool> = None;
    let mut production_runtime_active_tcp_benchmark_iters: Option<u32> = None;
    let mut production_runtime_active_udp = false;
    let mut production_runtime_active_udp_target_ip: Option<String> = None;
    let mut production_runtime_active_udp_target_port: Option<u16> = None;
    let mut production_runtime_active_udp_benchmark_iters: Option<u32> = None;
    let mut production_runtime_active_dns = false;
    let mut production_runtime_active_dns_target_ip: Option<String> = None;
    let mut production_runtime_active_dns_target_port: Option<u16> = None;
    let mut production_runtime_active_dns_upstream_ip: Option<String> = None;
    let mut production_runtime_active_dns_upstream_port: Option<u16> = None;
    let mut production_runtime_active_dns_qname: Option<String> = None;
    let mut production_runtime_active_dns_benchmark_iters: Option<u32> = None;
    let mut production_runtime_reload_parity = false;
    let mut dataplane_benchmark_iters = 5_u32;
    let mut matched_default_benchmark = false;
    let mut matched_benchmark_iterations = 3_u32;
    let mut matched_ready_timeout_ms = 15_000_u64;
    let mut go_tool: Option<PathBuf> = None;
    let mut go_work: Option<PathBuf> = None;
    let mut go_binary: Option<PathBuf> = None;
    let mut rust_binary: Option<PathBuf> = None;
    let mut source_dir: Option<PathBuf> = None;
    let mut product_chain_recertification = false;
    let mut product_chain_dae_repo: Option<PathBuf> = None;
    let mut product_chain_dae_wing_repo: Option<PathBuf> = None;
    let mut product_chain_daed_repo: Option<PathBuf> = None;
    let mut product_chain_outbound_repo: Option<PathBuf> = None;
    let mut product_chain_quic_go_repo: Option<PathBuf> = None;
    let mut product_chain_service_file: Option<PathBuf> = None;
    let mut product_chain_go_mod_file: Option<PathBuf> = None;
    let mut product_chain_admission_evidence: Option<PathBuf> = None;
    let mut request_default_path_mutation = false;
    let mut plan_production_run_command_replacement = false;
    let mut execute_production_run_command_replacement = false;
    let mut plan_production_run_command_apply = false;
    let mut allow_host_default_path_mutation = false;
    let mut plan_local_validation_fresh_install = false;
    let mut product_chain_fresh_install_binary_source: Option<PathBuf> = None;
    let mut product_chain_resident_default_daemon_binary_source: Option<PathBuf> = None;
    let mut exit_after_ready = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                let Some(value) = iter.next() else {
                    usage!("missing run --config value");
                };
                config = Some(value.into());
            }
            _ if arg.starts_with("--config=") => {
                config = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--root" => {
                let Some(value) = iter.next() else {
                    usage!("missing run --root value");
                };
                root = value.into();
                root_explicit = true;
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
                root_explicit = true;
            }
            "--logfile" => {
                let Some(value) = iter.next() else {
                    usage!("missing run --logfile value");
                };
                logfile = Some(value.into());
            }
            _ if arg.starts_with("--logfile=") => {
                logfile = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--service-pid-file" => {
                let Some(value) = iter.next() else {
                    usage!("missing run --service-pid-file value");
                };
                service_pid_file = Some(value.into());
            }
            _ if arg.starts_with("--service-pid-file=") => {
                service_pid_file = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--service-progress-file" => {
                let Some(value) = iter.next() else {
                    usage!("missing run --service-progress-file value");
                };
                service_progress_file = Some(value.into());
            }
            _ if arg.starts_with("--service-progress-file=") => {
                service_progress_file = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--service-abort-file" => {
                let Some(value) = iter.next() else {
                    usage!("missing run --service-abort-file value");
                };
                service_abort_file = Some(value.into());
            }
            _ if arg.starts_with("--service-abort-file=") => {
                service_abort_file = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--service-ready-file" => {
                let Some(value) = iter.next() else {
                    usage!("missing run --service-ready-file value");
                };
                service_ready_file = Some(value.into());
            }
            _ if arg.starts_with("--service-ready-file=") => {
                service_ready_file = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--disable-timestamp" => disable_timestamp = true,
            "--disable-pidfile" => disable_pidfile = true,
            "--disable-sudo" => disable_sudo = true,
            "--no-listener-smoke" => listener_smoke = false,
            "--no-reload-smoke" => reload_smoke = false,
            "--execute-production-runtime-owner" => production_runtime_owner = true,
            "--execute-production-runtime-active-tcp" => production_runtime_active_tcp = true,
            "--execute-production-dataplane-smoke" => production_dataplane_smoke = true,
            "--ack-root-gate" => ack_root_gate = true,
            "--production-runtime-tproxy-port" => {
                let Some(value) = iter.next() else {
                    usage!(
                        "missing run --production-runtime-tproxy-port value",
                    );
                };
                production_runtime_tproxy_port = match value.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        usage!(
                            "invalid run --production-runtime-tproxy-port value",
                        );
                    }
                };
            }
            _ if arg.starts_with("--production-runtime-tproxy-port=") => {
                production_runtime_tproxy_port = match arg.split_once('=').unwrap().1.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        usage!(
                            "invalid run --production-runtime-tproxy-port value",
                        );
                    }
                };
            }
            "--production-runtime-dae-netns-id" => {
                let Some(value) = iter.next() else {
                    usage!(
                        "missing run --production-runtime-dae-netns-id value",
                    );
                };
                production_runtime_dae_netns_id = match value.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        usage!(
                            "invalid run --production-runtime-dae-netns-id value",
                        );
                    }
                };
            }
            _ if arg.starts_with("--production-runtime-dae-netns-id=") => {
                production_runtime_dae_netns_id = match arg.split_once('=').unwrap().1.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        usage!(
                            "invalid run --production-runtime-dae-netns-id value",
                        );
                    }
                };
            }
            "--production-runtime-netns-link" => {
                let Some(value) = iter.next() else {
                    usage!(
                        "missing run --production-runtime-netns-link value",
                    );
                };
                production_runtime_netns_link_mode = match parse_netns_link_mode(value) {
                    Ok(value) => value,
                    Err(_) => {
                        usage!(
                            "invalid run --production-runtime-netns-link value",
                        );
                    }
                };
            }
            _ if arg.starts_with("--production-runtime-netns-link=") => {
                production_runtime_netns_link_mode =
                    match parse_netns_link_mode(arg.split_once('=').unwrap().1) {
                        Ok(value) => value,
                        Err(_) => {
                            usage!(
                                "invalid run --production-runtime-netns-link value",
                            );
                        }
                    };
            }
            "--production-runtime-object" => {
                let Some(value) = iter.next() else {
                    usage!("missing run --production-runtime-object value");
                };
                production_runtime_object = Some(value.into());
            }
            _ if arg.starts_with("--production-runtime-object=") => {
                production_runtime_object = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--production-runtime-native-ebpf-object" => {
                let Some(value) = iter.next() else {
                    usage!(
                        "missing run --production-runtime-native-ebpf-object value",
                    );
                };
                production_runtime_native_ebpf_object = Some(value.into());
            }
            _ if arg.starts_with("--production-runtime-native-ebpf-object=") => {
                production_runtime_native_ebpf_object =
                    arg.split_once('=').map(|(_, value)| value.into());
            }
            "--production-runtime-native-ebpf" => {
                production_runtime_native_ebpf_opt_in = true;
            }
            "--production-runtime-native-ebpf-backend" => {
                let Some(value) = iter.next() else {
                    usage!(
                        "missing run --production-runtime-native-ebpf-backend value",
                    );
                };
                production_runtime_native_ebpf_backend = match parse_attach_backend(value) {
                    Some(value) => value,
                    None => {
                        usage!(
                            "invalid run --production-runtime-native-ebpf-backend value",
                        );
                    }
                };
            }
            _ if arg.starts_with("--production-runtime-native-ebpf-backend=") => {
                production_runtime_native_ebpf_backend =
                    match parse_attach_backend(arg.split_once('=').unwrap().1) {
                        Some(value) => value,
                        None => {
                            usage!(
                                "invalid run --production-runtime-native-ebpf-backend value",
                            );
                        }
                    };
            }
            "--production-runtime-native-ebpf-completed-a3-local" => {
                production_runtime_native_ebpf_completed_a3_admission = true;
            }
            "--production-runtime-fallback-retirement-product-chain-recertified" => {
                production_runtime_fallback_retirement_product_chain_recertified = true;
            }
            "--production-runtime-fallback-retirement-explicit-approval" => {
                production_runtime_fallback_retirement_explicit_user_approval = true;
            }
            "--production-runtime-active-tcp-target-ip" => {
                let Some(value) = iter.next() else {
                    usage!(
                        "missing run --production-runtime-active-tcp-target-ip value",
                    );
                };
                production_runtime_active_tcp_target_ip = Some(value.to_owned());
            }
            _ if arg.starts_with("--production-runtime-active-tcp-target-ip=") => {
                production_runtime_active_tcp_target_ip =
                    arg.split_once('=').map(|(_, value)| value.to_owned());
            }
            "--production-runtime-active-tcp-client-ip" => {
                let Some(value) = iter.next() else {
                    usage!(
                        "missing run --production-runtime-active-tcp-client-ip value",
                    );
                };
                production_runtime_active_tcp_client_ip = Some(value.to_owned());
            }
            _ if arg.starts_with("--production-runtime-active-tcp-client-ip=") => {
                production_runtime_active_tcp_client_ip =
                    arg.split_once('=').map(|(_, value)| value.to_owned());
            }
            "--production-runtime-active-tcp-target-port" => {
                let Some(value) = iter.next() else {
                    usage!(
                        "missing run --production-runtime-active-tcp-target-port value",
                    );
                };
                production_runtime_active_tcp_target_port = match value.parse() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        usage!(
                            "invalid run --production-runtime-active-tcp-target-port value",
                        );
                    }
                };
            }
            _ if arg.starts_with("--production-runtime-active-tcp-target-port=") => {
                production_runtime_active_tcp_target_port =
                    match arg.split_once('=').unwrap().1.parse() {
                        Ok(value) => Some(value),
                        Err(_) => {
                            usage!(
                                "invalid run --production-runtime-active-tcp-target-port value",
                            );
                        }
                    };
            }
            "--production-runtime-active-tcp-so-mark" => {
                let Some(value) = iter.next() else {
                    usage!(
                        "missing run --production-runtime-active-tcp-so-mark value",
                    );
                };
                production_runtime_active_tcp_so_mark = match value.parse() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        usage!(
                            "invalid run --production-runtime-active-tcp-so-mark value",
                        );
                    }
                };
            }
            _ if arg.starts_with("--production-runtime-active-tcp-so-mark=") => {
                production_runtime_active_tcp_so_mark = match arg.split_once('=').unwrap().1.parse()
                {
                    Ok(value) => Some(value),
                    Err(_) => {
                        usage!(
                            "invalid run --production-runtime-active-tcp-so-mark value",
                        );
                    }
                };
            }
            "--production-runtime-active-tcp-mptcp" => {
                production_runtime_active_tcp_mptcp = Some(true);
            }
            "--production-runtime-active-tcp-no-mptcp"
            | "--no-production-runtime-active-tcp-mptcp" => {
                production_runtime_active_tcp_mptcp = Some(false);
            }
            "--execute-production-runtime-active-tcp-relay" => {
                production_runtime_active_tcp_relay = true;
            }
            "--execute-production-runtime-active-udp" => {
                production_runtime_active_udp = true;
            }
            "--production-runtime-active-udp-target-ip" => {
                let Some(value) = iter.next() else {
                    usage!(
                        "missing run --production-runtime-active-udp-target-ip value",
                    );
                };
                production_runtime_active_udp_target_ip = Some(value.to_owned());
            }
            _ if arg.starts_with("--production-runtime-active-udp-target-ip=") => {
                production_runtime_active_udp_target_ip =
                    arg.split_once('=').map(|(_, value)| value.to_owned());
            }
            "--production-runtime-active-udp-target-port" => {
                let Some(value) = iter.next() else {
                    usage!(
                        "missing run --production-runtime-active-udp-target-port value",
                    );
                };
                production_runtime_active_udp_target_port = match value.parse() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        usage!(
                            "invalid run --production-runtime-active-udp-target-port value",
                        );
                    }
                };
            }
            _ if arg.starts_with("--production-runtime-active-udp-target-port=") => {
                production_runtime_active_udp_target_port =
                    match arg.split_once('=').unwrap().1.parse() {
                        Ok(value) => Some(value),
                        Err(_) => {
                            usage!(
                                "invalid run --production-runtime-active-udp-target-port value",
                            );
                        }
                    };
            }
            "--production-runtime-active-udp-benchmark-iters" => {
                let Some(value) = iter.next() else {
                    usage!(
                        "missing run --production-runtime-active-udp-benchmark-iters value",
                    );
                };
                production_runtime_active_udp_benchmark_iters = match value.parse() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        usage!(
                            "invalid run --production-runtime-active-udp-benchmark-iters value",
                        );
                    }
                };
            }
            _ if arg.starts_with("--production-runtime-active-udp-benchmark-iters=") => {
                production_runtime_active_udp_benchmark_iters =
                    match arg.split_once('=').unwrap().1.parse() {
                        Ok(value) => Some(value),
                        Err(_) => {
                            usage!(
                                "invalid run --production-runtime-active-udp-benchmark-iters value",
                            );
                        }
                    };
            }
            "--execute-production-runtime-active-dns" => {
                production_runtime_active_dns = true;
            }
            "--production-runtime-active-dns-target-ip" => {
                let Some(value) = iter.next() else {
                    usage!(
                        "missing run --production-runtime-active-dns-target-ip value",
                    );
                };
                production_runtime_active_dns_target_ip = Some(value.to_owned());
            }
            _ if arg.starts_with("--production-runtime-active-dns-target-ip=") => {
                production_runtime_active_dns_target_ip =
                    arg.split_once('=').map(|(_, value)| value.to_owned());
            }
            "--production-runtime-active-dns-target-port" => {
                let Some(value) = iter.next() else {
                    usage!(
                        "missing run --production-runtime-active-dns-target-port value",
                    );
                };
                production_runtime_active_dns_target_port = match value.parse() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        usage!(
                            "invalid run --production-runtime-active-dns-target-port value",
                        );
                    }
                };
            }
            _ if arg.starts_with("--production-runtime-active-dns-target-port=") => {
                production_runtime_active_dns_target_port =
                    match arg.split_once('=').unwrap().1.parse() {
                        Ok(value) => Some(value),
                        Err(_) => {
                            usage!(
                                "invalid run --production-runtime-active-dns-target-port value",
                            );
                        }
                    };
            }
            "--production-runtime-active-dns-upstream-ip" => {
                let Some(value) = iter.next() else {
                    usage!(
                        "missing run --production-runtime-active-dns-upstream-ip value",
                    );
                };
                production_runtime_active_dns_upstream_ip = Some(value.to_owned());
            }
            _ if arg.starts_with("--production-runtime-active-dns-upstream-ip=") => {
                production_runtime_active_dns_upstream_ip =
                    arg.split_once('=').map(|(_, value)| value.to_owned());
            }
            "--production-runtime-active-dns-upstream-port" => {
                let Some(value) = iter.next() else {
                    usage!(
                        "missing run --production-runtime-active-dns-upstream-port value",
                    );
                };
                production_runtime_active_dns_upstream_port = match value.parse() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        usage!(
                            "invalid run --production-runtime-active-dns-upstream-port value",
                        );
                    }
                };
            }
            _ if arg.starts_with("--production-runtime-active-dns-upstream-port=") => {
                production_runtime_active_dns_upstream_port =
                    match arg.split_once('=').unwrap().1.parse() {
                        Ok(value) => Some(value),
                        Err(_) => {
                            usage!(
                                "invalid run --production-runtime-active-dns-upstream-port value",
                            );
                        }
                    };
            }
            "--production-runtime-active-dns-qname" => {
                let Some(value) = iter.next() else {
                    usage!(
                        "missing run --production-runtime-active-dns-qname value",
                    );
                };
                production_runtime_active_dns_qname = Some(value.to_owned());
            }
            _ if arg.starts_with("--production-runtime-active-dns-qname=") => {
                production_runtime_active_dns_qname =
                    arg.split_once('=').map(|(_, value)| value.to_owned());
            }
            "--production-runtime-active-dns-benchmark-iters" => {
                let Some(value) = iter.next() else {
                    usage!(
                        "missing run --production-runtime-active-dns-benchmark-iters value",
                    );
                };
                production_runtime_active_dns_benchmark_iters = match value.parse() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        usage!(
                            "invalid run --production-runtime-active-dns-benchmark-iters value",
                        );
                    }
                };
            }
            _ if arg.starts_with("--production-runtime-active-dns-benchmark-iters=") => {
                production_runtime_active_dns_benchmark_iters =
                    match arg.split_once('=').unwrap().1.parse() {
                        Ok(value) => Some(value),
                        Err(_) => {
                            usage!(
                                "invalid run --production-runtime-active-dns-benchmark-iters value",
                            );
                        }
                    };
            }
            "--execute-production-runtime-reload-parity" => {
                production_runtime_reload_parity = true;
            }
            "--production-runtime-active-tcp-upstream-mptcp" => {
                production_runtime_active_tcp_upstream_mptcp = Some(true);
            }
            "--production-runtime-active-tcp-upstream-plain-tcp" => {
                production_runtime_active_tcp_upstream_mptcp = Some(false);
            }
            "--production-runtime-active-tcp-benchmark-iters" => {
                let Some(value) = iter.next() else {
                    usage!(
                        "missing run --production-runtime-active-tcp-benchmark-iters value",
                    );
                };
                production_runtime_active_tcp_benchmark_iters = match value.parse() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        usage!(
                            "invalid run --production-runtime-active-tcp-benchmark-iters value",
                        );
                    }
                };
            }
            _ if arg.starts_with("--production-runtime-active-tcp-benchmark-iters=") => {
                production_runtime_active_tcp_benchmark_iters =
                    match arg.split_once('=').unwrap().1.parse() {
                        Ok(value) => Some(value),
                        Err(_) => {
                            usage!(
                                "invalid run --production-runtime-active-tcp-benchmark-iters value",
                            );
                        }
                    };
            }
            "--dataplane-benchmark-iters" => {
                let Some(value) = iter.next() else {
                    usage!("missing run --dataplane-benchmark-iters value");
                };
                dataplane_benchmark_iters = match value.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        usage!(
                            "invalid run --dataplane-benchmark-iters value",
                        );
                    }
                };
            }
            _ if arg.starts_with("--dataplane-benchmark-iters=") => {
                dataplane_benchmark_iters = match arg.split_once('=').unwrap().1.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        usage!(
                            "invalid run --dataplane-benchmark-iters value",
                        );
                    }
                };
            }
            "--execute-matched-default-benchmark" => matched_default_benchmark = true,
            "--matched-benchmark-iterations" => {
                let Some(value) = iter.next() else {
                    usage!("missing run --matched-benchmark-iterations value");
                };
                matched_benchmark_iterations = match value.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        usage!(
                            "invalid run --matched-benchmark-iterations value",
                        );
                    }
                };
            }
            _ if arg.starts_with("--matched-benchmark-iterations=") => {
                matched_benchmark_iterations = match arg.split_once('=').unwrap().1.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        usage!(
                            "invalid run --matched-benchmark-iterations value",
                        );
                    }
                };
            }
            "--matched-ready-timeout-ms" => {
                let Some(value) = iter.next() else {
                    usage!("missing run --matched-ready-timeout-ms value");
                };
                matched_ready_timeout_ms = match value.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        usage!("invalid run --matched-ready-timeout-ms value");
                    }
                };
            }
            _ if arg.starts_with("--matched-ready-timeout-ms=") => {
                matched_ready_timeout_ms = match arg.split_once('=').unwrap().1.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        usage!("invalid run --matched-ready-timeout-ms value");
                    }
                };
            }
            "--go-tool" => {
                let Some(value) = iter.next() else {
                    usage!("missing run --go-tool value");
                };
                go_tool = Some(value.into());
            }
            _ if arg.starts_with("--go-tool=") => {
                go_tool = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--go-work" => {
                let Some(value) = iter.next() else {
                    usage!("missing run --go-work value");
                };
                go_work = Some(value.into());
            }
            _ if arg.starts_with("--go-work=") => {
                go_work = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--go-binary" => {
                let Some(value) = iter.next() else {
                    usage!("missing run --go-binary value");
                };
                go_binary = Some(value.into());
            }
            _ if arg.starts_with("--go-binary=") => {
                go_binary = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--rust-binary" => {
                let Some(value) = iter.next() else {
                    usage!("missing run --rust-binary value");
                };
                rust_binary = Some(value.into());
            }
            _ if arg.starts_with("--rust-binary=") => {
                rust_binary = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--source-dir" => {
                let Some(value) = iter.next() else {
                    usage!("missing run --source-dir value");
                };
                source_dir = Some(value.into());
            }
            _ if arg.starts_with("--source-dir=") => {
                source_dir = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--execute-product-chain-recertification" => {
                product_chain_recertification = true;
            }
            "--product-chain-admission-evidence" => {
                let Some(value) = iter.next() else {
                    usage!(
                        "missing run --product-chain-admission-evidence value",
                    );
                };
                product_chain_admission_evidence = Some(value.into());
            }
            _ if arg.starts_with("--product-chain-admission-evidence=") => {
                product_chain_admission_evidence =
                    arg.split_once('=').map(|(_, value)| value.into());
            }
            "--request-default-path-mutation" => {
                request_default_path_mutation = true;
            }
            "--plan-production-run-command-replacement" => {
                plan_production_run_command_replacement = true;
            }
            "--execute-production-run-command-replacement" => {
                execute_production_run_command_replacement = true;
            }
            "--plan-production-run-command-apply" => {
                plan_production_run_command_apply = true;
            }
            "--allow-host-default-path-mutation" => {
                allow_host_default_path_mutation = true;
            }
            "--plan-local-validation-fresh-install" => {
                plan_local_validation_fresh_install = true;
            }
            "--product-chain-fresh-install-binary-source" => {
                let Some(value) = iter.next() else {
                    usage!(
                        "missing run --product-chain-fresh-install-binary-source value",
                    );
                };
                product_chain_fresh_install_binary_source = Some(value.into());
            }
            _ if arg.starts_with("--product-chain-fresh-install-binary-source=") => {
                product_chain_fresh_install_binary_source =
                    arg.split_once('=').map(|(_, value)| value.into());
            }
            "--product-chain-resident-default-daemon-binary-source" => {
                let Some(value) = iter.next() else {
                    usage!(
                        "missing run --product-chain-resident-default-daemon-binary-source value",
                    );
                };
                product_chain_resident_default_daemon_binary_source = Some(value.into());
            }
            _ if arg.starts_with("--product-chain-resident-default-daemon-binary-source=") => {
                product_chain_resident_default_daemon_binary_source =
                    arg.split_once('=').map(|(_, value)| value.into());
            }
            "--product-chain-dae-repo" => {
                let Some(value) = iter.next() else {
                    usage!("missing run --product-chain-dae-repo value");
                };
                product_chain_dae_repo = Some(value.into());
            }
            _ if arg.starts_with("--product-chain-dae-repo=") => {
                product_chain_dae_repo = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--product-chain-dae-wing-repo" => {
                let Some(value) = iter.next() else {
                    usage!("missing run --product-chain-dae-wing-repo value");
                };
                product_chain_dae_wing_repo = Some(value.into());
            }
            _ if arg.starts_with("--product-chain-dae-wing-repo=") => {
                product_chain_dae_wing_repo = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--product-chain-daed-repo" => {
                let Some(value) = iter.next() else {
                    usage!("missing run --product-chain-daed-repo value");
                };
                product_chain_daed_repo = Some(value.into());
            }
            _ if arg.starts_with("--product-chain-daed-repo=") => {
                product_chain_daed_repo = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--product-chain-outbound-repo" => {
                let Some(value) = iter.next() else {
                    usage!("missing run --product-chain-outbound-repo value");
                };
                product_chain_outbound_repo = Some(value.into());
            }
            _ if arg.starts_with("--product-chain-outbound-repo=") => {
                product_chain_outbound_repo = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--product-chain-quic-go-repo" => {
                let Some(value) = iter.next() else {
                    usage!("missing run --product-chain-quic-go-repo value");
                };
                product_chain_quic_go_repo = Some(value.into());
            }
            _ if arg.starts_with("--product-chain-quic-go-repo=") => {
                product_chain_quic_go_repo = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--product-chain-service-file" => {
                let Some(value) = iter.next() else {
                    usage!("missing run --product-chain-service-file value");
                };
                product_chain_service_file = Some(value.into());
            }
            _ if arg.starts_with("--product-chain-service-file=") => {
                product_chain_service_file = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--product-chain-go-mod-file" => {
                let Some(value) = iter.next() else {
                    usage!("missing run --product-chain-go-mod-file value");
                };
                product_chain_go_mod_file = Some(value.into());
            }
            _ if arg.starts_with("--product-chain-go-mod-file=") => {
                product_chain_go_mod_file = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--exit-after-ready" | "--once" => exit_after_ready = true,
            _ => usage!(format!("unsupported run argument: {arg}")),
        }
    }
    Ok(DefaultOptinParsedArgs {
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
        product_chain_resident_default_daemon_binary_source,
        exit_after_ready,
    })
}
