use super::*;

pub(in crate::daed_product::geodata) fn runtime_input_versions_if_running(
    context: &ProductGeodataUpdateContext,
) -> io::Result<Option<dae_product_control::geodata::RuntimeInputVersions>> {
    let running = context.runtime.is_running();
    if !running {
        return Ok(None);
    }
    dae_product_control::geodata::read_runtime_input_versions(&context.state).map(Some)
}
