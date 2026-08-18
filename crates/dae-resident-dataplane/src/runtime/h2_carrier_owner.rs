#[cfg(test)]
pub(crate) use dae_resident_transport::acquire_h2_carrier;
#[cfg(test)]
pub(crate) use dae_resident_transport::start_h2_carrier_generation_owner;
pub(crate) use dae_resident_transport::{
    H2CarrierGenerationOwnerHandle, H2CarrierLease, start_h2_carrier_generation_owner_on,
};
