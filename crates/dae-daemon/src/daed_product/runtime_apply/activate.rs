use super::*;

pub(super) fn activate_runtime_generation(
    runtime: &ProductRuntimeManager,
    prepared: PreparedProductRuntime,
    config_content: String,
    source: &str,
    latency_seed: &[Value],
    checkpoints: &mut dyn FaultCheckpoints<RuntimeApplyCheckpoint>,
) -> Result<Value, String> {
    checkpoints
        .checkpoint(RuntimeApplyCheckpoint::StartCandidate)
        .map_err(|err| format!("start candidate runtime checkpoint: {err}"))?;
    runtime
        .reload_prepared_with_config_content(prepared, Some(config_content), source, latency_seed)
        .map(|outcome| outcome.report)
}
