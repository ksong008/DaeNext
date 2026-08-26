use super::prepare::PreparedRuntimeGeneration;

pub(super) fn write_runtime_apply_journal(
    candidate: &mut PreparedRuntimeGeneration,
) -> Result<(), String> {
    let output = candidate
        .output_path
        .as_ref()
        .ok_or_else(|| "runtime apply journal has no output path".to_owned())?;
    let staged = candidate
        .candidate_path
        .as_ref()
        .ok_or_else(|| "runtime apply journal has no candidate path".to_owned())?;
    let runtime_dir = output
        .parent()
        .ok_or_else(|| "runtime materialization path has no parent".to_owned())?;
    let parts = dae_product_runtime::prepare_runtime_apply_transaction(
        runtime_dir,
        &candidate.generation,
        output,
        staged,
        candidate.previous_content.as_deref(),
    )?;
    candidate.journal_path = Some(parts.journal_path);
    candidate.backup_path = parts.backup_path;
    candidate.transaction = Some(parts.transaction);
    Ok(())
}

pub(super) fn remove_runtime_apply_journal(
    candidate: &mut PreparedRuntimeGeneration,
) -> Result<(), String> {
    if let Some(transaction) = candidate.transaction.take() {
        transaction
            .finish()
            .map_err(|error| format!("finish runtime apply transaction: {error}"))?;
    }
    candidate.journal_path = None;
    candidate.backup_path = None;
    Ok(())
}
