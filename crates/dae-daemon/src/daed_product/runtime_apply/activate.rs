use super::*;

pub(super) fn activate_runtime_generation(
    runtime: &ProductRuntimeManager,
    config: Config,
    config_content: String,
    source: &str,
    latency_seed: &[Value],
    checkpoints: &mut dyn RuntimeApplyCheckpoints,
) -> Result<Value, String> {
    checkpoints
        .checkpoint(RuntimeApplyCheckpoint::StartCandidate)
        .map_err(|err| format!("start candidate runtime checkpoint: {err}"))?;
    runtime
        .reload_with_config_content(config, Some(config_content), source, latency_seed)
        .map(|outcome| outcome.report)
}
