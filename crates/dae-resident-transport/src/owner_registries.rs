use crate::{
    AnyTlsOwnerRegistryHandle, Hysteria2OwnerRegistryHandle, JuicityOwnerRegistryHandle,
    TuicOwnerRegistryHandle,
};

#[derive(Clone, Default)]
pub struct ResidentTransportOwnerRegistries {
    hysteria2: Option<Hysteria2OwnerRegistryHandle>,
    tuic: Option<TuicOwnerRegistryHandle>,
    juicity: Option<JuicityOwnerRegistryHandle>,
    anytls: Option<AnyTlsOwnerRegistryHandle>,
}

impl ResidentTransportOwnerRegistries {
    pub fn new(
        hysteria2: Option<Hysteria2OwnerRegistryHandle>,
        tuic: Option<TuicOwnerRegistryHandle>,
        juicity: Option<JuicityOwnerRegistryHandle>,
    ) -> Self {
        Self {
            hysteria2,
            tuic,
            juicity,
            anytls: None,
        }
    }

    pub fn with_anytls(mut self, anytls: Option<AnyTlsOwnerRegistryHandle>) -> Self {
        self.anytls = anytls;
        self
    }

    pub fn hysteria2(&self) -> Option<Hysteria2OwnerRegistryHandle> {
        self.hysteria2.clone()
    }

    pub fn tuic(&self) -> Option<TuicOwnerRegistryHandle> {
        self.tuic.clone()
    }

    pub fn juicity(&self) -> Option<JuicityOwnerRegistryHandle> {
        self.juicity.clone()
    }

    pub fn anytls(&self) -> Option<AnyTlsOwnerRegistryHandle> {
        self.anytls.clone()
    }
}
