use super::super::topology::preflight_nonexclusive_blockers;
use super::start_entry::{resident_runtime_artifact_dir, resident_runtime_options};
use super::*;

pub(crate) fn preflight_resident_runtime_candidate(config: &Config) -> Result<Value, String> {
    let artifact_dir = resident_runtime_artifact_dir(std::process::id());
    let options = resident_runtime_options(config, Vec::<PathBuf>::new(), &artifact_dir)?;
    let lan_ifaces = configured_lan_ifaces(config);
    let wan_ifaces = configured_wan_ifaces(config)?;
    let mut checks = preflight_checks(&options);
    checks.extend(resident_interface_validation_checks(
        &lan_ifaces,
        &wan_ifaces,
    ));
    checks.extend(resident_kernel_feature_checks(&lan_ifaces, &wan_ifaces));
    checks.push(resident_cgroup_preflight_check(&options, &wan_ifaces));
    let blockers = preflight_nonexclusive_blockers(&checks);
    if !blockers.is_empty() {
        return Err(format!(
            "resident candidate preflight failed before current runtime teardown: {}",
            blockers.join("; ")
        ));
    }
    Ok(json!({
        "status": "pass",
        "checks": checks,
        "exclusiveActivationChecksDeferred": [
            "production-names-free",
            "tproxy-port-free"
        ],
    }))
}
