use crate::bpf_loader::run_bpf_loader_command;
use crate::config_validate::validate_config_file;
use crate::identity::daemon_identity;
use crate::lifecycle::{default_lifecycle_smoke_root, lifecycle_smoke_report};
use crate::preflight::identity_preflight_report;
use crate::production_runtime_owner::{NetnsLinkMode, parse_netns_link_mode};
use crate::{
    DefaultRunIdentityAdmissionOptions, default_run_identity_admission_report,
    default_run_identity_admission_root,
};
use crate::{
    ReloadOptions, ResidentRunOptions, reload_resident_service, run_resident_service,
    service_contract_capabilities,
};
use crate::{
    RunOptions, default_run_root, product_chain_admission_from_run_report, run_default_optin_report,
};
use crate::{
    control_plane_entrypoint_admission_report, default_control_plane_entrypoint_admission_root,
};
use crate::{control_plane_owner_preflight_report, default_control_plane_owner_preflight_root};
use crate::{default_listener_ebpf_preflight_root, listener_ebpf_preflight_report};
use crate::{default_reload_owner_benchmark_root, reload_owner_benchmark_report};
use crate::{default_reload_owner_handoff_root, reload_owner_handoff_smoke_report};
use crate::{default_run_entrypoint_preflight_root, run_entrypoint_preflight_report};
use crate::{default_signal_control_plane_smoke_root, signal_control_plane_smoke_report};
use dae_ebpf_support::AttachBackend;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl DaemonOutput {
    pub(crate) fn ok(stdout: String) -> Self {
        Self {
            stdout,
            stderr: String::new(),
            exit_code: 0,
        }
    }

    pub(crate) fn usage(message: impl Into<String>) -> Self {
        Self {
            stdout: String::new(),
            stderr: format!("{}\n", message.into()),
            exit_code: 2,
        }
    }

    pub(crate) fn error(message: impl Into<String>) -> Self {
        Self {
            stdout: String::new(),
            stderr: format!("{}\n", message.into()),
            exit_code: 1,
        }
    }
}

pub fn run_with_args_and_version(
    args: impl IntoIterator<Item = impl Into<String>>,
    version: &str,
) -> DaemonOutput {
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("identity") if args.len() == 1 => {
            DaemonOutput::ok(format!("{}\n", daemon_identity(version)))
        }
        Some("validate") => run_validate_command(&args[1..]),
        Some("run") => run_default_optin_command(&args[1..], version),
        Some("reload") => run_reload_command(&args[1..]),
        Some("service-contract") if args.len() == 1 => {
            DaemonOutput::ok(format!("{}\n", service_contract_capabilities(version)))
        }
        Some("identity-preflight") if args.len() == 1 => {
            DaemonOutput::ok(format!("{}\n", identity_preflight_report(version)))
        }
        Some("lifecycle-smoke") => run_lifecycle_smoke_command(&args[1..]),
        Some("control-plane-owner-preflight") => {
            run_control_plane_owner_preflight_command(&args[1..])
        }
        Some("signal-control-plane-smoke") => run_signal_control_plane_smoke_command(&args[1..]),
        Some("run-entrypoint-preflight") => run_run_entrypoint_preflight_command(&args[1..]),
        Some("default-run-identity-admission") => {
            run_default_run_identity_admission_command(&args[1..])
        }
        Some("control-plane-entrypoint-admission") => {
            run_control_plane_entrypoint_admission_command(&args[1..])
        }
        Some("listener-ebpf-preflight") => run_listener_ebpf_preflight_command(&args[1..]),
        Some("reload-owner-handoff-smoke") => run_reload_owner_handoff_smoke_command(&args[1..]),
        Some("reload-owner-benchmark") => run_reload_owner_benchmark_command(&args[1..]),
        Some("bpf-loader") => run_bpf_loader_command(&args[1..]),
        Some("identity") | Some("service-contract") | Some("identity-preflight") => {
            DaemonOutput::usage("unsupported dae-daemon-optin argument")
        }
        Some(command) => {
            DaemonOutput::usage(format!("unsupported dae-daemon-optin command: {command}"))
        }
        None => DaemonOutput::usage("missing dae-daemon-optin command"),
    }
}

fn run_validate_command(args: &[String]) -> DaemonOutput {
    let mut config: Option<PathBuf> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing validate --config value");
                };
                config = Some(value.into());
            }
            _ if arg.starts_with("--config=") => {
                config = arg.split_once('=').map(|(_, value)| value.into());
            }
            _ => return DaemonOutput::usage(format!("unsupported validate argument: {arg}")),
        }
    }
    let Some(config) = config else {
        return DaemonOutput::usage("validate requires -c/--config");
    };
    match validate_config_file(&config) {
        Ok(_) => DaemonOutput::ok(String::new()),
        Err(err) => DaemonOutput::error(format!("validate config failed: {err}")),
    }
}

fn run_reload_command(args: &[String]) -> DaemonOutput {
    let mut options = ReloadOptions::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-a" | "--abort" => options.abort_connections = true,
            "--service-pid-file" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing reload --service-pid-file value");
                };
                options.pid_file = value.into();
            }
            _ if arg.starts_with("--service-pid-file=") => {
                options.pid_file = arg.split_once('=').unwrap().1.into();
            }
            "--service-progress-file" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing reload --service-progress-file value");
                };
                options.progress_file = value.into();
            }
            _ if arg.starts_with("--service-progress-file=") => {
                options.progress_file = arg.split_once('=').unwrap().1.into();
            }
            "--service-abort-file" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing reload --service-abort-file value");
                };
                options.abort_file = value.into();
            }
            _ if arg.starts_with("--service-abort-file=") => {
                options.abort_file = arg.split_once('=').unwrap().1.into();
            }
            "--timeout-ms" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing reload --timeout-ms value");
                };
                options.timeout = match value.parse::<u64>() {
                    Ok(value) => Some(Duration::from_millis(value)),
                    Err(_) => return DaemonOutput::usage("invalid reload --timeout-ms value"),
                };
            }
            _ if arg.starts_with("--timeout-ms=") => {
                options.timeout = match arg.split_once('=').unwrap().1.parse::<u64>() {
                    Ok(value) => Some(Duration::from_millis(value)),
                    Err(_) => return DaemonOutput::usage("invalid reload --timeout-ms value"),
                };
            }
            _ if arg.starts_with('-') => {
                return DaemonOutput::usage(format!("unsupported reload argument: {arg}"));
            }
            _ if options.pid.is_none() => {
                options.pid = match arg.parse::<i32>() {
                    Ok(value) => Some(value),
                    Err(_) => return DaemonOutput::usage("invalid reload pid value"),
                };
            }
            _ => return DaemonOutput::usage("reload accepts at most one pid value"),
        }
    }
    match reload_resident_service(&options) {
        Ok(stdout) => DaemonOutput::ok(stdout),
        Err(err) => DaemonOutput::error(err),
    }
}

fn run_default_optin_command(args: &[String], version: &str) -> DaemonOutput {
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
                    return DaemonOutput::usage("missing run --config value");
                };
                config = Some(value.into());
            }
            _ if arg.starts_with("--config=") => {
                config = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --root value");
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
                    return DaemonOutput::usage("missing run --logfile value");
                };
                logfile = Some(value.into());
            }
            _ if arg.starts_with("--logfile=") => {
                logfile = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--service-pid-file" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --service-pid-file value");
                };
                service_pid_file = Some(value.into());
            }
            _ if arg.starts_with("--service-pid-file=") => {
                service_pid_file = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--service-progress-file" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --service-progress-file value");
                };
                service_progress_file = Some(value.into());
            }
            _ if arg.starts_with("--service-progress-file=") => {
                service_progress_file = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--service-abort-file" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --service-abort-file value");
                };
                service_abort_file = Some(value.into());
            }
            _ if arg.starts_with("--service-abort-file=") => {
                service_abort_file = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--service-ready-file" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --service-ready-file value");
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
                    return DaemonOutput::usage(
                        "missing run --production-runtime-tproxy-port value",
                    );
                };
                production_runtime_tproxy_port = match value.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        return DaemonOutput::usage(
                            "invalid run --production-runtime-tproxy-port value",
                        );
                    }
                };
            }
            _ if arg.starts_with("--production-runtime-tproxy-port=") => {
                production_runtime_tproxy_port = match arg.split_once('=').unwrap().1.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        return DaemonOutput::usage(
                            "invalid run --production-runtime-tproxy-port value",
                        );
                    }
                };
            }
            "--production-runtime-dae-netns-id" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage(
                        "missing run --production-runtime-dae-netns-id value",
                    );
                };
                production_runtime_dae_netns_id = match value.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        return DaemonOutput::usage(
                            "invalid run --production-runtime-dae-netns-id value",
                        );
                    }
                };
            }
            _ if arg.starts_with("--production-runtime-dae-netns-id=") => {
                production_runtime_dae_netns_id = match arg.split_once('=').unwrap().1.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        return DaemonOutput::usage(
                            "invalid run --production-runtime-dae-netns-id value",
                        );
                    }
                };
            }
            "--production-runtime-netns-link" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage(
                        "missing run --production-runtime-netns-link value",
                    );
                };
                production_runtime_netns_link_mode = match parse_netns_link_mode(value) {
                    Ok(value) => value,
                    Err(_) => {
                        return DaemonOutput::usage(
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
                            return DaemonOutput::usage(
                                "invalid run --production-runtime-netns-link value",
                            );
                        }
                    };
            }
            "--production-runtime-object" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --production-runtime-object value");
                };
                production_runtime_object = Some(value.into());
            }
            _ if arg.starts_with("--production-runtime-object=") => {
                production_runtime_object = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--production-runtime-native-ebpf-object" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage(
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
                    return DaemonOutput::usage(
                        "missing run --production-runtime-native-ebpf-backend value",
                    );
                };
                production_runtime_native_ebpf_backend = match parse_attach_backend(value) {
                    Some(value) => value,
                    None => {
                        return DaemonOutput::usage(
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
                            return DaemonOutput::usage(
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
                    return DaemonOutput::usage(
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
                    return DaemonOutput::usage(
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
                    return DaemonOutput::usage(
                        "missing run --production-runtime-active-tcp-target-port value",
                    );
                };
                production_runtime_active_tcp_target_port = match value.parse() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        return DaemonOutput::usage(
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
                            return DaemonOutput::usage(
                                "invalid run --production-runtime-active-tcp-target-port value",
                            );
                        }
                    };
            }
            "--production-runtime-active-tcp-so-mark" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage(
                        "missing run --production-runtime-active-tcp-so-mark value",
                    );
                };
                production_runtime_active_tcp_so_mark = match value.parse() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        return DaemonOutput::usage(
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
                        return DaemonOutput::usage(
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
                    return DaemonOutput::usage(
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
                    return DaemonOutput::usage(
                        "missing run --production-runtime-active-udp-target-port value",
                    );
                };
                production_runtime_active_udp_target_port = match value.parse() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        return DaemonOutput::usage(
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
                            return DaemonOutput::usage(
                                "invalid run --production-runtime-active-udp-target-port value",
                            );
                        }
                    };
            }
            "--production-runtime-active-udp-benchmark-iters" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage(
                        "missing run --production-runtime-active-udp-benchmark-iters value",
                    );
                };
                production_runtime_active_udp_benchmark_iters = match value.parse() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        return DaemonOutput::usage(
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
                            return DaemonOutput::usage(
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
                    return DaemonOutput::usage(
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
                    return DaemonOutput::usage(
                        "missing run --production-runtime-active-dns-target-port value",
                    );
                };
                production_runtime_active_dns_target_port = match value.parse() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        return DaemonOutput::usage(
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
                            return DaemonOutput::usage(
                                "invalid run --production-runtime-active-dns-target-port value",
                            );
                        }
                    };
            }
            "--production-runtime-active-dns-upstream-ip" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage(
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
                    return DaemonOutput::usage(
                        "missing run --production-runtime-active-dns-upstream-port value",
                    );
                };
                production_runtime_active_dns_upstream_port = match value.parse() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        return DaemonOutput::usage(
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
                            return DaemonOutput::usage(
                                "invalid run --production-runtime-active-dns-upstream-port value",
                            );
                        }
                    };
            }
            "--production-runtime-active-dns-qname" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage(
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
                    return DaemonOutput::usage(
                        "missing run --production-runtime-active-dns-benchmark-iters value",
                    );
                };
                production_runtime_active_dns_benchmark_iters = match value.parse() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        return DaemonOutput::usage(
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
                            return DaemonOutput::usage(
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
                    return DaemonOutput::usage(
                        "missing run --production-runtime-active-tcp-benchmark-iters value",
                    );
                };
                production_runtime_active_tcp_benchmark_iters = match value.parse() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        return DaemonOutput::usage(
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
                            return DaemonOutput::usage(
                                "invalid run --production-runtime-active-tcp-benchmark-iters value",
                            );
                        }
                    };
            }
            "--dataplane-benchmark-iters" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --dataplane-benchmark-iters value");
                };
                dataplane_benchmark_iters = match value.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        return DaemonOutput::usage(
                            "invalid run --dataplane-benchmark-iters value",
                        );
                    }
                };
            }
            _ if arg.starts_with("--dataplane-benchmark-iters=") => {
                dataplane_benchmark_iters = match arg.split_once('=').unwrap().1.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        return DaemonOutput::usage(
                            "invalid run --dataplane-benchmark-iters value",
                        );
                    }
                };
            }
            "--execute-matched-default-benchmark" => matched_default_benchmark = true,
            "--matched-benchmark-iterations" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --matched-benchmark-iterations value");
                };
                matched_benchmark_iterations = match value.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        return DaemonOutput::usage(
                            "invalid run --matched-benchmark-iterations value",
                        );
                    }
                };
            }
            _ if arg.starts_with("--matched-benchmark-iterations=") => {
                matched_benchmark_iterations = match arg.split_once('=').unwrap().1.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        return DaemonOutput::usage(
                            "invalid run --matched-benchmark-iterations value",
                        );
                    }
                };
            }
            "--matched-ready-timeout-ms" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --matched-ready-timeout-ms value");
                };
                matched_ready_timeout_ms = match value.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        return DaemonOutput::usage("invalid run --matched-ready-timeout-ms value");
                    }
                };
            }
            _ if arg.starts_with("--matched-ready-timeout-ms=") => {
                matched_ready_timeout_ms = match arg.split_once('=').unwrap().1.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        return DaemonOutput::usage("invalid run --matched-ready-timeout-ms value");
                    }
                };
            }
            "--go-tool" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --go-tool value");
                };
                go_tool = Some(value.into());
            }
            _ if arg.starts_with("--go-tool=") => {
                go_tool = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--go-work" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --go-work value");
                };
                go_work = Some(value.into());
            }
            _ if arg.starts_with("--go-work=") => {
                go_work = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--go-binary" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --go-binary value");
                };
                go_binary = Some(value.into());
            }
            _ if arg.starts_with("--go-binary=") => {
                go_binary = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--rust-binary" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --rust-binary value");
                };
                rust_binary = Some(value.into());
            }
            _ if arg.starts_with("--rust-binary=") => {
                rust_binary = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--source-dir" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --source-dir value");
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
                    return DaemonOutput::usage(
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
                    return DaemonOutput::usage(
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
                    return DaemonOutput::usage(
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
                    return DaemonOutput::usage("missing run --product-chain-dae-repo value");
                };
                product_chain_dae_repo = Some(value.into());
            }
            _ if arg.starts_with("--product-chain-dae-repo=") => {
                product_chain_dae_repo = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--product-chain-dae-wing-repo" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --product-chain-dae-wing-repo value");
                };
                product_chain_dae_wing_repo = Some(value.into());
            }
            _ if arg.starts_with("--product-chain-dae-wing-repo=") => {
                product_chain_dae_wing_repo = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--product-chain-daed-repo" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --product-chain-daed-repo value");
                };
                product_chain_daed_repo = Some(value.into());
            }
            _ if arg.starts_with("--product-chain-daed-repo=") => {
                product_chain_daed_repo = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--product-chain-outbound-repo" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --product-chain-outbound-repo value");
                };
                product_chain_outbound_repo = Some(value.into());
            }
            _ if arg.starts_with("--product-chain-outbound-repo=") => {
                product_chain_outbound_repo = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--product-chain-quic-go-repo" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --product-chain-quic-go-repo value");
                };
                product_chain_quic_go_repo = Some(value.into());
            }
            _ if arg.starts_with("--product-chain-quic-go-repo=") => {
                product_chain_quic_go_repo = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--product-chain-service-file" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --product-chain-service-file value");
                };
                product_chain_service_file = Some(value.into());
            }
            _ if arg.starts_with("--product-chain-service-file=") => {
                product_chain_service_file = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--product-chain-go-mod-file" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --product-chain-go-mod-file value");
                };
                product_chain_go_mod_file = Some(value.into());
            }
            _ if arg.starts_with("--product-chain-go-mod-file=") => {
                product_chain_go_mod_file = arg.split_once('=').map(|(_, value)| value.into());
            }
            "--exit-after-ready" | "--once" => exit_after_ready = true,
            _ => return DaemonOutput::usage(format!("unsupported run argument: {arg}")),
        }
    }
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

fn parse_attach_backend(value: &str) -> Option<AttachBackend> {
    match value {
        "auto" => Some(AttachBackend::Auto),
        "tcx" => Some(AttachBackend::Tcx),
        "tc-netlink" | "tc_netlink" => Some(AttachBackend::TcNetlink),
        "tc-command-fallback" | "tc_command_fallback" => Some(AttachBackend::TcCommandFallback),
        _ => None,
    }
}

fn run_reload_owner_benchmark_command(args: &[String]) -> DaemonOutput {
    let mut root = default_reload_owner_benchmark_root();
    let mut iterations = 3_u32;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing reload-owner-benchmark --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            "--iterations" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage(
                        "missing reload-owner-benchmark --iterations value",
                    );
                };
                iterations = match value.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        return DaemonOutput::usage(
                            "invalid reload-owner-benchmark --iterations value",
                        );
                    }
                };
            }
            _ if arg.starts_with("--iterations=") => {
                iterations = match arg.split_once('=').unwrap().1.parse() {
                    Ok(value) => value,
                    Err(_) => {
                        return DaemonOutput::usage(
                            "invalid reload-owner-benchmark --iterations value",
                        );
                    }
                };
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported reload-owner-benchmark argument: {arg}"
                ));
            }
        }
    }
    match reload_owner_benchmark_report(&root, iterations) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_reload_owner_handoff_smoke_command(args: &[String]) -> DaemonOutput {
    let mut root = default_reload_owner_handoff_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing reload-owner-handoff-smoke --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported reload-owner-handoff-smoke argument: {arg}"
                ));
            }
        }
    }
    match reload_owner_handoff_smoke_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_listener_ebpf_preflight_command(args: &[String]) -> DaemonOutput {
    let mut root = default_listener_ebpf_preflight_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing listener-ebpf-preflight --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported listener-ebpf-preflight argument: {arg}"
                ));
            }
        }
    }
    match listener_ebpf_preflight_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_control_plane_entrypoint_admission_command(args: &[String]) -> DaemonOutput {
    let mut root = default_control_plane_entrypoint_admission_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage(
                        "missing control-plane-entrypoint-admission --root value",
                    );
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported control-plane-entrypoint-admission argument: {arg}"
                ));
            }
        }
    }
    match control_plane_entrypoint_admission_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_default_run_identity_admission_command(args: &[String]) -> DaemonOutput {
    let mut opts =
        DefaultRunIdentityAdmissionOptions::under_root(default_run_identity_admission_root());
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage(
                        "missing default-run-identity-admission --root value",
                    );
                };
                opts = DefaultRunIdentityAdmissionOptions::under_root(value);
            }
            _ if arg.starts_with("--root=") => {
                opts =
                    DefaultRunIdentityAdmissionOptions::under_root(arg.split_once('=').unwrap().1);
            }
            "-c" | "--config" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage(
                        "missing default-run-identity-admission --config value",
                    );
                };
                opts.config = value.into();
            }
            _ if arg.starts_with("--config=") => {
                opts.config = arg.split_once('=').unwrap().1.into();
            }
            "--logfile" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage(
                        "missing default-run-identity-admission --logfile value",
                    );
                };
                opts.logfile = value.into();
            }
            _ if arg.starts_with("--logfile=") => {
                opts.logfile = arg.split_once('=').unwrap().1.into();
            }
            "--disable-timestamp" => opts.disable_timestamp = true,
            "--disable-pidfile" => opts.disable_pidfile = true,
            "--disable-sudo" => opts.disable_sudo = true,
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported default-run-identity-admission argument: {arg}"
                ));
            }
        }
    }
    match default_run_identity_admission_report(&opts) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_run_entrypoint_preflight_command(args: &[String]) -> DaemonOutput {
    let mut root = default_run_entrypoint_preflight_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run-entrypoint-preflight --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported run-entrypoint-preflight argument: {arg}"
                ));
            }
        }
    }
    match run_entrypoint_preflight_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_signal_control_plane_smoke_command(args: &[String]) -> DaemonOutput {
    let mut root = default_signal_control_plane_smoke_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing signal-control-plane-smoke --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported signal-control-plane-smoke argument: {arg}"
                ));
            }
        }
    }
    match signal_control_plane_smoke_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_lifecycle_smoke_command(args: &[String]) -> DaemonOutput {
    let mut root = default_lifecycle_smoke_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing lifecycle-smoke --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!("unsupported lifecycle-smoke argument: {arg}"));
            }
        }
    }
    match lifecycle_smoke_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_control_plane_owner_preflight_command(args: &[String]) -> DaemonOutput {
    let mut root = default_control_plane_owner_preflight_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage(
                        "missing control-plane-owner-preflight --root value",
                    );
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported control-plane-owner-preflight argument: {arg}"
                ));
            }
        }
    }
    match control_plane_owner_preflight_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}
