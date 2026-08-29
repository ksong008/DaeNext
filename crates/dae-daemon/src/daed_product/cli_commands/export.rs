use super::*;
pub(crate) fn run_export_command(args: &[String]) -> DaedProductOutput {
    match args.first().map(String::as_str) {
        Some("openapi") if args.len() == 1 => DaedProductOutput::ok(format!(
            "{}\n",
            product_openapi_skeleton(&crate::version::version_from_env())
        )),
        Some("flatdesc") if args.len() == 1 => {
            DaedProductOutput::ok(format!("{}\n", product_package_context().flatdesc()))
        }
        Some("outline") if args.len() == 1 => {
            DaedProductOutput::ok(format!("{}\n", product_package_context().outline()))
        }
        Some("package-manifest") if args.len() == 1 => DaedProductOutput::ok(format!(
            "{}\n",
            product_package_context().package_manifest()
        )),
        Some("admission-report") if args.len() == 1 => DaedProductOutput::ok(format!(
            "{}\n",
            product_package_context().admission_report(&webui_route_audit_report())
        )),
        Some("webui-route-audit") if args.len() == 1 => {
            DaedProductOutput::ok(format!("{}\n", webui_route_audit_report()))
        }
        Some("systemd-unit") if args.len() == 1 => DaedProductOutput::ok(systemd_unit_text()),
        Some("docker-entrypoint") if args.len() == 1 => {
            DaedProductOutput::ok(docker_entrypoint_text())
        }
        Some(command) => DaedProductOutput::usage(format!("unsupported export command: {command}")),
        None => DaedProductOutput::usage(
            "export requires openapi, flatdesc, outline, package-manifest, admission-report, webui-route-audit, systemd-unit, or docker-entrypoint",
        ),
    }
}
