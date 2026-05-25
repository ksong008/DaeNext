use super::*;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

mod baseline;
mod default_switch;
mod dependency_boundary;
mod local_validation;
mod readiness_host_write;
mod repo_status;
mod run_command_replacement;
mod runtime_control_contract;

fn write_fixture_file(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn write_candidate_service_contract(path: &Path, resident_dataplane_ready: bool) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
            path,
            format!(
                "#!/bin/sh\n\
                 if [ \"$1\" = \"validate\" ]; then exit 0; fi\n\
                 if [ \"$1\" = \"service-contract\" ]; then\n\
                   printf '%s\\n' '{{\"resident_run_service_contract_ready\":true,\"reload_command_service_contract_ready\":true,\"resident_production_dataplane_ready\":{resident_dataplane_ready},\"resident_default_daemon_switch_ready\":{resident_dataplane_ready}}}'\n\
                   exit 0\n\
                 fi\n\
                 exit 2\n"
            ),
        )
        .unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn init_fixture_repo(path: &Path, branch: &str) {
    std::fs::create_dir_all(path).unwrap();
    assert!(
        Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(path)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args(["checkout", "--quiet", "-B", branch])
            .current_dir(path)
            .status()
            .unwrap()
            .success()
    );
}

fn resident_ready_product_chain_options(
    root: &Path,
    mut options: ProductChainRecertificationOptions,
) -> ProductChainRecertificationOptions {
    let binary = root.join("resident-ready-candidate");
    write_candidate_service_contract(&binary, true);
    options.resident_default_daemon_binary_source = Some(binary);
    options
}

fn resident_service_only_product_chain_options(
    root: &Path,
    mut options: ProductChainRecertificationOptions,
) -> ProductChainRecertificationOptions {
    let binary = root.join("resident-service-only-candidate");
    write_candidate_service_contract(&binary, false);
    options.resident_default_daemon_binary_source = Some(binary);
    options
}

fn clean_product_chain_evidence() -> ProductChainEvidence {
    ProductChainEvidence {
        topology: json!({
            "chain": "daed2.0-web-wing-daecore",
            "daed2_wing_repo_used": true,
            "standalone_dae_wing_repo_used": false,
        }),
        service: json!({
            "status": "pass",
            "service_contract_preserved": true,
        }),
        go_mod: json!({
            "status": "pass",
            "outbound_quic_go_dependency_boundary_preserved": true,
        }),
        repos: Vec::new(),
        runtime_control_api: json!({
            "status": "pass",
            "runtime_control_api_source_contract_preserved": true,
        }),
        dirty_repos: Vec::new(),
        missing_repos: Vec::new(),
        unavailable_repos: Vec::new(),
        branch_mismatched_repos: Vec::new(),
    }
}
