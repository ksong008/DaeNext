pub(crate) use dae_resident_transport::{
    VlessMuxGenerationOwnerHandle, acquire_vless_mux_logical_stream,
    start_vless_mux_generation_owner_on,
};
#[cfg(test)]
pub(crate) use dae_resident_transport::{
    VlessMuxLogicalStream, start_vless_mux_generation_owner,
    start_vless_mux_generation_owner_for_test,
};
