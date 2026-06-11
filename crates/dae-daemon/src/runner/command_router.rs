use super::*;
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
        Some("run") => run_product_run_command(&args[1..], version),
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
        Some("product-run-identity-admission") => {
            run_product_run_identity_admission_command(&args[1..])
        }
        Some("control-plane-entrypoint-admission") => {
            run_control_plane_entrypoint_admission_command(&args[1..])
        }
        Some("listener-ebpf-preflight") => run_listener_ebpf_preflight_command(&args[1..]),
        Some("reload-owner-handoff-smoke") => run_reload_owner_handoff_smoke_command(&args[1..]),
        Some("reload-owner-benchmark") => run_reload_owner_benchmark_command(&args[1..]),
        Some("bpf-loader") => run_bpf_loader_command(&args[1..]),
        Some("identity") | Some("service-contract") | Some("identity-preflight") => {
            DaemonOutput::usage("unsupported daed argument")
        }
        Some(command) => DaemonOutput::usage(format!("unsupported daed command: {command}")),
        None => DaemonOutput::usage("missing daed command"),
    }
}
