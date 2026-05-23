use crate::identity::daemon_identity;
use crate::lifecycle::{default_stage150_root, stage150_lifecycle_smoke_report};
use crate::preflight::stage149_identity_preflight_report;
use crate::{RunOptions, default_run_root, run_default_optin_report};
use crate::{
    Stage156DefaultRunIdentityOptions, default_stage156_root,
    stage156_default_run_identity_admission_report,
};
use crate::{default_stage151_root, stage151_control_plane_owner_preflight_report};
use crate::{default_stage152_root, stage152_signal_control_plane_smoke_report};
use crate::{default_stage153_root, stage153_run_entrypoint_preflight_report};
use crate::{default_stage157_root, stage157_control_plane_entrypoint_admission_report};
use crate::{default_stage160_root, stage160_listener_ebpf_preflight_harness_report};
use crate::{default_stage165_root, stage165_reload_owner_handoff_smoke_report};
use crate::{default_stage167_root, stage167_reload_owner_benchmark_report};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl DaemonOutput {
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
        Some("run") => run_default_optin_command(&args[1..], version),
        Some("stage149-identity-preflight") if args.len() == 1 => {
            DaemonOutput::ok(format!("{}\n", stage149_identity_preflight_report(version)))
        }
        Some("stage150-lifecycle-smoke") => run_stage150_lifecycle_smoke_command(&args[1..]),
        Some("stage151-control-plane-owner-preflight") => {
            run_stage151_control_plane_owner_preflight_command(&args[1..])
        }
        Some("stage152-signal-control-plane-smoke") => {
            run_stage152_signal_control_plane_smoke_command(&args[1..])
        }
        Some("stage153-run-entrypoint-preflight") => {
            run_stage153_run_entrypoint_preflight_command(&args[1..])
        }
        Some("stage156-default-run-identity-admission") => {
            run_stage156_default_run_identity_admission_command(&args[1..])
        }
        Some("stage157-control-plane-entrypoint-admission") => {
            run_stage157_control_plane_entrypoint_admission_command(&args[1..])
        }
        Some("stage160-listener-ebpf-preflight-harness") => {
            run_stage160_listener_ebpf_preflight_harness_command(&args[1..])
        }
        Some("stage165-reload-owner-handoff-smoke") => {
            run_stage165_reload_owner_handoff_smoke_command(&args[1..])
        }
        Some("stage167-reload-owner-benchmark") => {
            run_stage167_reload_owner_benchmark_command(&args[1..])
        }
        Some("identity") | Some("stage149-identity-preflight") => {
            DaemonOutput::usage("unsupported dae-daemon-optin argument")
        }
        Some(command) => {
            DaemonOutput::usage(format!("unsupported dae-daemon-optin command: {command}"))
        }
        None => DaemonOutput::usage("missing dae-daemon-optin command"),
    }
}

fn run_default_optin_command(args: &[String], version: &str) -> DaemonOutput {
    let mut root = default_run_root();
    let mut config: Option<PathBuf> = None;
    let mut logfile: Option<PathBuf> = None;
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
    let mut production_runtime_object: Option<PathBuf> = None;
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
    let mut cargo_manifest: Option<PathBuf> = None;
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
    let mut request_default_path_mutation = false;
    let mut plan_production_run_command_replacement = false;
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
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
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
            "--production-runtime-object" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --production-runtime-object value");
                };
                production_runtime_object = Some(value.into());
            }
            _ if arg.starts_with("--production-runtime-object=") => {
                production_runtime_object = arg.split_once('=').map(|(_, value)| value.into());
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
            "--cargo-manifest" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing run --cargo-manifest value");
                };
                cargo_manifest = Some(value.into());
            }
            _ if arg.starts_with("--cargo-manifest=") => {
                cargo_manifest = arg.split_once('=').map(|(_, value)| value.into());
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
            "--request-default-path-mutation" => {
                request_default_path_mutation = true;
            }
            "--plan-production-run-command-replacement" => {
                plan_production_run_command_replacement = true;
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
            "--exit-after-ready" | "--once" => {}
            _ => return DaemonOutput::usage(format!("unsupported run argument: {arg}")),
        }
    }
    let Some(config) = config else {
        return DaemonOutput::usage("run requires -c/--config");
    };
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
    options.production_runtime_owner.execute_active_tcp = production_runtime_active_tcp;
    options.production_runtime_owner.execute_active_tcp_relay = production_runtime_active_tcp_relay;
    options.production_runtime_owner.execute_active_udp = production_runtime_active_udp;
    options.production_runtime_owner.execute_active_dns = production_runtime_active_dns;
    options
        .production_runtime_owner
        .execute_reload_runtime_parity = production_runtime_reload_parity;
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
    if let Some(cargo_manifest) = cargo_manifest {
        options.production_dataplane_harness.cargo_manifest = cargo_manifest;
    }
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

    match run_default_optin_report(&options, version) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_stage167_reload_owner_benchmark_command(args: &[String]) -> DaemonOutput {
    let mut root = default_stage167_root();
    let mut iterations = 3_u32;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing stage167 --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            "--iterations" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing stage167 --iterations value");
                };
                iterations = match value.parse() {
                    Ok(value) => value,
                    Err(_) => return DaemonOutput::usage("invalid stage167 --iterations value"),
                };
            }
            _ if arg.starts_with("--iterations=") => {
                iterations = match arg.split_once('=').unwrap().1.parse() {
                    Ok(value) => value,
                    Err(_) => return DaemonOutput::usage("invalid stage167 --iterations value"),
                };
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported stage167 reload owner benchmark argument: {arg}"
                ));
            }
        }
    }
    match stage167_reload_owner_benchmark_report(&root, iterations) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_stage165_reload_owner_handoff_smoke_command(args: &[String]) -> DaemonOutput {
    let mut root = default_stage165_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing stage165 --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported stage165 reload owner handoff argument: {arg}"
                ));
            }
        }
    }
    match stage165_reload_owner_handoff_smoke_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_stage160_listener_ebpf_preflight_harness_command(args: &[String]) -> DaemonOutput {
    let mut root = default_stage160_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing stage160 --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported stage160 listener/eBPF preflight argument: {arg}"
                ));
            }
        }
    }
    match stage160_listener_ebpf_preflight_harness_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_stage157_control_plane_entrypoint_admission_command(args: &[String]) -> DaemonOutput {
    let mut root = default_stage157_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing stage157 --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported stage157 control-plane entrypoint argument: {arg}"
                ));
            }
        }
    }
    match stage157_control_plane_entrypoint_admission_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_stage156_default_run_identity_admission_command(args: &[String]) -> DaemonOutput {
    let mut opts = Stage156DefaultRunIdentityOptions::under_root(default_stage156_root());
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing stage156 --root value");
                };
                opts = Stage156DefaultRunIdentityOptions::under_root(value);
            }
            _ if arg.starts_with("--root=") => {
                opts =
                    Stage156DefaultRunIdentityOptions::under_root(arg.split_once('=').unwrap().1);
            }
            "-c" | "--config" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing stage156 --config value");
                };
                opts.config = value.into();
            }
            _ if arg.starts_with("--config=") => {
                opts.config = arg.split_once('=').unwrap().1.into();
            }
            "--logfile" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing stage156 --logfile value");
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
                    "unsupported stage156 default run identity argument: {arg}"
                ));
            }
        }
    }
    match stage156_default_run_identity_admission_report(&opts) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_stage153_run_entrypoint_preflight_command(args: &[String]) -> DaemonOutput {
    let mut root = default_stage153_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing stage153 --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported stage153 run entrypoint argument: {arg}"
                ));
            }
        }
    }
    match stage153_run_entrypoint_preflight_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_stage152_signal_control_plane_smoke_command(args: &[String]) -> DaemonOutput {
    let mut root = default_stage152_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing stage152 --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported stage152 signal control-plane argument: {arg}"
                ));
            }
        }
    }
    match stage152_signal_control_plane_smoke_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_stage150_lifecycle_smoke_command(args: &[String]) -> DaemonOutput {
    let mut root = default_stage150_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing stage150 --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported stage150 lifecycle argument: {arg}"
                ));
            }
        }
    }
    match stage150_lifecycle_smoke_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}

fn run_stage151_control_plane_owner_preflight_command(args: &[String]) -> DaemonOutput {
    let mut root = default_stage151_root();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                let Some(value) = iter.next() else {
                    return DaemonOutput::usage("missing stage151 --root value");
                };
                root = value.into();
            }
            _ if arg.starts_with("--root=") => {
                root = arg.split_once('=').unwrap().1.into();
            }
            _ => {
                return DaemonOutput::usage(format!(
                    "unsupported stage151 control-plane owner argument: {arg}"
                ));
            }
        }
    }
    match stage151_control_plane_owner_preflight_report(&root) {
        Ok(report) => DaemonOutput::ok(format!("{report}\n")),
        Err(err) => DaemonOutput {
            stdout: String::new(),
            stderr: format!("{err}\n"),
            exit_code: 1,
        },
    }
}
