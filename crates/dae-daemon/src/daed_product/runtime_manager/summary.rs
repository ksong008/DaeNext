use super::*;

pub(super) fn runtime_instance_health_states(runtime: &ProductRuntimeInstance) -> Vec<Value> {
    match runtime {
        ProductRuntimeInstance::Resident(runtime) => runtime.snapshot_health_states(),
        ProductRuntimeInstance::Fake(_) => Vec::new(),
    }
}

pub(super) fn runtime_instance_dns_reload_snapshot(
    runtime: &ProductRuntimeInstance,
) -> Result<Option<ResidentDnsReloadSnapshot>, String> {
    match runtime {
        ProductRuntimeInstance::Resident(runtime) => runtime.dns_reload_snapshot().map(Some),
        ProductRuntimeInstance::Fake(_) => Ok(None),
    }
}
