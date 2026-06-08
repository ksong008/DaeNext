use super::*;
pub fn product_chain_recertification_report(
    run_root: &Path,
    options: &ProductChainRecertificationOptions,
    admission: ProductChainAdmissionEvidence,
) -> Result<Value, String> {
    ensure_safe_run_root(run_root)?;
    let artifact_dir = run_root.join("run").join("product-chain-recertification");
    let manifest_file = artifact_dir.join("product-chain-recertification.json");
    if !options.execute {
        return Ok(report_value(
            options,
            &artifact_dir,
            &manifest_file,
            admission,
            None,
        ));
    }
    fs::create_dir_all(&artifact_dir).map_err(|err| {
        format!(
            "failed to create product-chain recertification artifact dir {}: {err}",
            path_string(&artifact_dir)
        )
    })?;
    let evidence = collect_evidence(options, admission);
    let mut report = report_value(
        options,
        &artifact_dir,
        &manifest_file,
        admission,
        Some(evidence),
    );
    let production_run_command_artifacts =
        materialize_production_run_command_replacement_artifacts(options, &report, &artifact_dir)?;
    attach_production_run_command_replacement_artifacts(
        &mut report,
        production_run_command_artifacts,
    );
    let production_replacement_readiness =
        materialize_production_replacement_readiness_report(&report, &artifact_dir)?;
    attach_production_replacement_readiness(&mut report, production_replacement_readiness);
    let daed2_switch_rehearsal =
        materialize_daed2_product_chain_switch_rehearsal_report(&report, &artifact_dir)?;
    attach_daed2_product_chain_switch_rehearsal(&mut report, daed2_switch_rehearsal);
    let local_validation_fresh_install_plan =
        materialize_local_validation_fresh_install_plan(options, &report, &artifact_dir)?;
    attach_local_validation_fresh_install_plan(&mut report, local_validation_fresh_install_plan);
    let host_write_plan_freeze =
        materialize_production_host_write_plan_freeze_report(&report, &artifact_dir)?;
    attach_production_host_write_plan_freeze(&mut report, host_write_plan_freeze);
    attach_release_default_switch_gate_from_report(&mut report);
    attach_go_free_product_chain_gate_from_report(&mut report);
    let encoded = serde_json::to_vec_pretty(&report)
        .map_err(|err| format!("failed to encode product-chain recertification report: {err}"))?;
    fs::write(&manifest_file, encoded).map_err(|err| {
        format!(
            "failed to write product-chain recertification manifest {}: {err}",
            path_string(&manifest_file)
        )
    })?;
    Ok(report)
}
