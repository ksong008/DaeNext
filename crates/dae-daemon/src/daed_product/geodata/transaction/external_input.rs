use super::*;
pub(super) use dae_product_geodata::ensure_runtime_input_versions_bumped;

pub(in crate::daed_product::geodata) fn runtime_input_versions_if_running(
    context: &ProductGeodataUpdateContext,
) -> io::Result<Option<dae_product_geodata::RuntimeInputVersions>> {
    let running = context
        .runtime
        .inner
        .lock()
        .map(|inner| inner.runtime.is_some())
        .unwrap_or(false);
    if !running {
        return Ok(None);
    }
    dae_product_geodata::read_runtime_input_versions(&context.state).map(Some)
}
