pub fn product_chain_admission_from_run_report(
    path: &Path,
) -> Result<ProductChainAdmissionEvidence, String> {
    let text = fs::read_to_string(path).map_err(|err| {
        format!(
            "failed to read product-chain admission evidence {}: {err}",
            path_string(path)
        )
    })?;
    let value: Value = serde_json::from_str(&text).map_err(|err| {
        format!(
            "failed to parse product-chain admission evidence {}: {err}",
            path_string(path)
        )
    })?;
    Ok(ProductChainAdmissionEvidence {
        production_dataplane_admitted: required_bool(
            &value,
            "production_dataplane_admitted",
            path,
        )?,
        reload_runtime_parity_admitted: required_bool(
            &value,
            "reload_runtime_parity_admitted",
            path,
        )?,
        matched_benchmark_recorded: required_bool(
            &value,
            "matched_go_rust_default_daemon_benchmark_recorded",
            path,
        )?,
        bpf_go_fallback_retired: required_bool(&value, "bpf_go_fallback_retired", path)?,
        true_rust_default_daemon_admitted: required_bool(
            &value,
            "true_rust_default_daemon_admitted",
            path,
        )?,
    })
}
