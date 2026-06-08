use super::*;
pub(super) fn rust_aya_datapath_contract() -> Result<Value, String> {
    let output = dae_aya_bpf_loader::run_with_args(["bpf-loader", "contract"]);
    if output.exit_code != 0 {
        return Err(format!(
            "rust/Aya datapath contract failed: {}",
            output.stderr.trim()
        ));
    }
    serde_json::from_str(output.stdout.trim())
        .map_err(|err| format!("rust/Aya datapath contract JSON decode failed: {err}"))
}
