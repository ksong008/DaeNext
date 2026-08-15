use std::fmt;

use dae_runtime_control::OwnerGeneration;

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResidentProxyBindingScope {
    Configuration,
    Resident,
    ControlPlane,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResidentSocketMarkPolicy {
    Configured,
    RouteOverride(u32),
    ControlFallback(u32),
}

impl ResidentSocketMarkPolicy {
    const fn effective_mark(self, configured: u32) -> u32 {
        match self {
            Self::Configured => configured,
            Self::RouteOverride(mark) => mark,
            Self::ControlFallback(mark) => {
                if configured == 0 {
                    mark
                } else {
                    configured
                }
            }
        }
    }

    const fn for_chain_parent(self) -> Self {
        match self {
            Self::RouteOverride(_) => Self::Configured,
            policy => policy,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResidentXhttpReusePolicy {
    Configured,
    NoPersistentReuse,
}

impl ResidentXhttpReusePolicy {
    pub(crate) const fn allows_persistent_reuse(self) -> bool {
        matches!(self, Self::Configured)
    }
}

#[derive(Clone)]
pub(crate) struct ResidentProxyBinding {
    plan: Arc<ResidentProxyPlan>,
    execution: ResidentExecutionPlan,
    scope: ResidentProxyBindingScope,
    socket_mark: ResidentSocketMarkPolicy,
    xhttp_reuse: ResidentXhttpReusePolicy,
}

impl ResidentProxyBinding {
    pub(crate) fn configuration(plan: Arc<ResidentProxyPlan>) -> Result<Self, String> {
        Self::new(
            plan,
            ResidentProxyBindingScope::Configuration,
            OwnerGeneration::new(0),
        )
    }

    #[cfg(test)]
    pub(crate) fn resident(
        plan: Arc<ResidentProxyPlan>,
        generation: OwnerGeneration,
    ) -> Result<Self, String> {
        if generation.get() == 0 {
            return Err("resident proxy binding generation must be nonzero".to_owned());
        }
        Self::new(plan, ResidentProxyBindingScope::Resident, generation)
    }

    pub(crate) fn control_plane(plan: Arc<ResidentProxyPlan>) -> Result<Self, String> {
        Self::new(
            plan,
            ResidentProxyBindingScope::ControlPlane,
            OwnerGeneration::new(0),
        )
    }

    fn new(
        plan: Arc<ResidentProxyPlan>,
        scope: ResidentProxyBindingScope,
        generation: OwnerGeneration,
    ) -> Result<Self, String> {
        let execution = plan
            .materialized_execution()?
            .with_runtime_generation(generation);
        Ok(Self {
            plan,
            execution,
            scope,
            socket_mark: ResidentSocketMarkPolicy::Configured,
            xhttp_reuse: ResidentXhttpReusePolicy::Configured,
        })
    }

    pub(crate) fn bind_resident_generation(
        &mut self,
        generation: OwnerGeneration,
    ) -> Result<(), String> {
        if generation.get() == 0 {
            return Err("resident proxy binding generation must be nonzero".to_owned());
        }
        self.execution = self.execution.with_runtime_generation(generation);
        self.scope = ResidentProxyBindingScope::Resident;
        Ok(())
    }

    pub(crate) fn bind_control_plane(&mut self) {
        self.execution = self
            .execution
            .with_runtime_generation(OwnerGeneration::new(0));
        self.scope = ResidentProxyBindingScope::ControlPlane;
    }

    pub(crate) fn with_route_socket_mark(mut self, mark: u32) -> Self {
        if mark != 0 && self.plan.mark != mark {
            self.socket_mark = ResidentSocketMarkPolicy::RouteOverride(mark);
        }
        self
    }

    #[cfg(test)]
    pub(crate) fn with_control_socket_mark(mut self, mark: u32) -> Self {
        self.apply_control_socket_mark(mark);
        self
    }

    pub(crate) fn apply_control_socket_mark(&mut self, mark: u32) {
        if mark != 0 {
            self.socket_mark = ResidentSocketMarkPolicy::ControlFallback(mark);
        }
    }

    pub(crate) fn without_persistent_xhttp_reuse(mut self) -> Self {
        self.xhttp_reuse = ResidentXhttpReusePolicy::NoPersistentReuse;
        self
    }

    pub(crate) fn chain_parent(&self) -> Result<Option<Self>, String> {
        self.plan
            .chain_parent
            .as_ref()
            .map(|parent| {
                let execution = parent
                    .materialized_execution()?
                    .with_runtime_generation(self.execution.runtime_generation());
                Ok(Self {
                    plan: Arc::clone(parent),
                    execution,
                    scope: self.scope,
                    socket_mark: self.socket_mark.for_chain_parent(),
                    xhttp_reuse: self.xhttp_reuse,
                })
            })
            .transpose()
    }

    pub(crate) fn plan(&self) -> &ResidentProxyPlan {
        &self.plan
    }

    pub(crate) fn shared_plan(&self) -> &Arc<ResidentProxyPlan> {
        &self.plan
    }

    pub(crate) fn into_shared_plan(self) -> Arc<ResidentProxyPlan> {
        self.plan
    }

    pub(crate) const fn execution(&self) -> ResidentExecutionPlan {
        self.execution
    }

    #[cfg(test)]
    pub(crate) const fn scope(&self) -> ResidentProxyBindingScope {
        self.scope
    }

    pub(crate) const fn runtime_generation(&self) -> OwnerGeneration {
        self.execution.runtime_generation()
    }

    pub(crate) fn effective_socket_mark(&self) -> u32 {
        self.socket_mark.effective_mark(self.plan.mark)
    }

    #[cfg(test)]
    pub(crate) const fn xhttp_reuse_policy(&self) -> ResidentXhttpReusePolicy {
        self.xhttp_reuse
    }

    pub(crate) fn persistent_xhttp_xmux(&self) -> Option<&ResidentXhttpXmuxPlan> {
        self.xhttp_reuse
            .allows_persistent_reuse()
            .then_some(self.plan.xhttp_xmux.as_ref())
            .flatten()
    }

    pub(crate) fn persistent_xhttp_download_xmux(&self) -> Option<&ResidentXhttpXmuxPlan> {
        self.xhttp_reuse
            .allows_persistent_reuse()
            .then(|| {
                self.plan
                    .xhttp_download
                    .as_ref()
                    .and_then(|download| download.xmux.as_ref())
            })
            .flatten()
    }
}

impl fmt::Debug for ResidentProxyBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResidentProxyBinding")
            .field("graph_id", &self.plan.graph_id)
            .field("protocol", &self.plan.protocol)
            .field("node_tag", &self.plan.node_tag)
            .field("scope", &self.scope)
            .field("runtime_generation", &self.runtime_generation())
            .field("socket_mark", &self.socket_mark)
            .field("xhttp_reuse", &self.xhttp_reuse)
            .finish()
    }
}

impl std::ops::Deref for ResidentProxyBinding {
    type Target = ResidentProxyPlan;

    fn deref(&self) -> &Self::Target {
        self.plan()
    }
}

#[cfg(test)]
mod tests;
