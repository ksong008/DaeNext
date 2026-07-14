use super::*;
pub fn run_daed_product_with_args_and_version(
    args: impl IntoIterator<Item = impl Into<String>>,
    version: &str,
) -> DaedProductOutput {
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("version") | Some("--version") | Some("-V") => {
            run_version_command(&args[1..], version)
        }
        Some("service-contract") => run_service_contract_command(&args[1..], version),
        Some("package-info") => run_package_info_command(&args[1..], version),
        Some("validate") => run_validate_command(&args[1..]),
        Some("resident-adapter-matrix") => run_resident_adapter_matrix_command(&args[1..]),
        Some("resident-adapter-udp-live") => run_resident_adapter_udp_live_command(&args[1..]),
        Some("state") => run_state_command(&args[1..]),
        Some("run") => run_product_server_command(&args[1..], version),
        Some("reload") => run_local_control_reload_command(&args[1..]),
        Some("wait-ready") => run_local_control_wait_ready_command(&args[1..]),
        Some("export") => run_export_command(&args[1..]),
        Some("resetpass") => run_resetpass_command(&args[1..]),
        Some("latency-probe-helper") => run_latency_probe_helper_command(&args[1..]),
        Some("help") | Some("--help") | Some("-h") => DaedProductOutput::ok(help_text()),
        Some(command) => DaedProductOutput::usage(format!("unsupported daed command: {command}")),
        None => DaedProductOutput::usage("missing daed command"),
    }
}

pub(super) fn run_version_command(args: &[String], version: &str) -> DaedProductOutput {
    if !args.is_empty() {
        return DaedProductOutput::usage("version accepts no arguments");
    }
    DaedProductOutput::ok(format!("{version}\n"))
}

pub(super) fn run_service_contract_command(args: &[String], version: &str) -> DaedProductOutput {
    if !args.is_empty() && args != ["--json"] {
        return DaedProductOutput::usage("service-contract accepts only optional --json");
    }
    DaedProductOutput::ok(format!("{}\n", daed_service_contract(version)))
}

pub(super) fn run_package_info_command(args: &[String], version: &str) -> DaedProductOutput {
    if !args.is_empty() && args != ["--json"] {
        return DaedProductOutput::usage("package-info accepts only optional --json");
    }
    DaedProductOutput::ok(format!("{}\n", daed_package_info(version)))
}
