pub(crate) use dae_resident_transport::{
    AnyTlsOwnerRegistryHandle, start_anytls_owner_registry, start_anytls_owner_registry_on,
};
#[cfg(test)]
pub(crate) use dae_resident_transport::{
    anytls_owner_key_digest_for_test, start_anytls_owner_registry_with_resources,
};
