use serde_json::Value;

use crate::{
    ProductRunIdentityAdmissionOptions, RunOptions, control_plane_entrypoint_admission_report,
    control_plane_owner_preflight_report, daemon_identity, identity_preflight_report,
    lifecycle_smoke_report, listener_ebpf_preflight_report, product_run_identity_admission_report,
    run_entrypoint_preflight_report, run_product_run_report, run_with_args_and_version,
    signal_control_plane_smoke_report,
};

mod bounded_run;
mod contract_scans;
mod identity_runner;
mod lifecycle_control;
mod listener_preflight;
mod run_command_basic;

pub(crate) fn in_isolated_process() -> bool {
    in_isolated_process_with_env(&[])
}

// Each test that observes process-wide state runs its exact libtest case in a
// fresh process, including any runtime threads the test itself starts.
pub(crate) fn in_isolated_process_with_env(env: &[(&str, &str)]) -> bool {
    const CHILD: &str = "DAE_ISOLATED_LIB_TEST";
    let current = std::thread::current();
    let name = current.name().expect("libtest thread name");
    if std::env::var(CHILD).as_deref() == Ok(name) {
        return true;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name])
        .envs(env.iter().copied())
        .env(CHILD, name)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed;"),
        "isolated test {name} exited with {}\n{stdout}{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    false
}
