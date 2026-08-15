use super::*;

#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub(crate) struct ControlTransportOwnerRequirements {
    pub(super) hysteria2: bool,
    pub(super) tuic: bool,
    pub(super) juicity: bool,
    pub(super) anytls: bool,
    pub(super) h2_carrier: bool,
    pub(super) meek: bool,
    pub(super) vless_mux: bool,
}

impl ControlTransportOwnerRequirements {
    pub(crate) fn from_binding(binding: &plan::ResidentProxyBinding) -> Self {
        let mut requirements = Self::default();
        requirements.include_plan(binding.plan());
        requirements
    }

    pub(crate) fn from_probe_plans<'a>(
        plans: impl Iterator<Item = &'a plan::ResidentProxyProbePlan>,
    ) -> Self {
        let mut requirements = Self::default();
        for probe in plans {
            requirements.include_plan(probe.binding.plan());
        }
        requirements
    }

    pub(crate) fn is_empty(self) -> bool {
        !self.hysteria2
            && !self.tuic
            && !self.juicity
            && !self.anytls
            && !self.h2_carrier
            && !self.meek
            && !self.vless_mux
    }

    pub(crate) fn requires_registered_carrier_scope(self) -> bool {
        self.h2_carrier || self.meek || self.vless_mux
    }

    fn include_plan(&mut self, plan: &plan::ResidentProxyPlan) {
        match &plan.handler {
            plan::ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. } => self.hysteria2 = true,
            plan::ResidentProxyProtocolPlan::TuicQuicTcp { .. } => self.tuic = true,
            plan::ResidentProxyProtocolPlan::JuicityQuicTcp { .. } => self.juicity = true,
            plan::ResidentProxyProtocolPlan::AnyTlsTcpTls { .. } => self.anytls = true,
            _ => {}
        }
        self.h2_carrier |= plan.requires_h2_carrier_owner();
        self.meek |= plan.requires_meek_transport_owner();
        self.vless_mux |= plan.requires_vless_mux_owner();
        if let Some(parent) = &plan.chain_parent {
            self.include_plan(parent);
        }
    }

    #[cfg(test)]
    pub(super) fn with_hysteria2() -> Self {
        Self {
            hysteria2: true,
            ..Self::default()
        }
    }

    #[cfg(test)]
    pub(super) fn with_h2_carrier() -> Self {
        Self {
            h2_carrier: true,
            ..Self::default()
        }
    }
}
