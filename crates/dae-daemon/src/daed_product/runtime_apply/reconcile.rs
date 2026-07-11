use super::*;

pub(super) fn record_apply_success(runtime: &ProductRuntimeManager, generation: &str) {
    runtime.finish_apply_generation(generation, "committed", None, false);
}

pub(super) fn record_apply_failure(
    runtime: &ProductRuntimeManager,
    generation: &str,
    phase: &str,
    error: &str,
    rollback_result: &str,
    reconciliation_required: bool,
) {
    runtime.finish_apply_generation(
        generation,
        phase,
        Some((error, rollback_result)),
        reconciliation_required,
    );
}
