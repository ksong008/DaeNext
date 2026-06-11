use super::*;
pub(super) const fn api(module: &'static str) -> OutboundModuleContract {
    OutboundModuleContract {
        module,
        surface: OutboundSurface::PublicApi,
        split_decision: OutboundSplitDecision::KeepInCrate,
    }
}

pub(super) const fn core(module: &'static str) -> OutboundModuleContract {
    OutboundModuleContract {
        module,
        surface: OutboundSurface::Core,
        split_decision: OutboundSplitDecision::KeepInCrate,
    }
}

pub(super) const fn protocol(module: &'static str) -> OutboundModuleContract {
    OutboundModuleContract {
        module,
        surface: OutboundSurface::Protocol,
        split_decision: OutboundSplitDecision::KeepInCrate,
    }
}

pub(super) const fn transport(module: &'static str) -> OutboundModuleContract {
    OutboundModuleContract {
        module,
        surface: OutboundSurface::Transport,
        split_decision: OutboundSplitDecision::ExtractLater,
    }
}

pub(super) const fn dataplane(module: &'static str) -> OutboundModuleContract {
    OutboundModuleContract {
        module,
        surface: OutboundSurface::Dataplane,
        split_decision: OutboundSplitDecision::KeepInCrate,
    }
}

pub(super) const fn support(module: &'static str) -> OutboundModuleContract {
    OutboundModuleContract {
        module,
        surface: OutboundSurface::TestSupport,
        split_decision: OutboundSplitDecision::MoveToTestSupport,
    }
}

pub(super) const fn dep(
    crate_name: &'static str,
    boundary: OutboundDependencyBoundary,
    product_runtime_required: bool,
    feature_candidate: Option<&'static str>,
) -> OutboundDependencyContract {
    OutboundDependencyContract {
        crate_name,
        boundary,
        product_runtime_required,
        feature_candidate,
    }
}

pub(super) const fn runtime_owner(
    path: &'static str,
    surface: RuntimeOwnerSurface,
    ownership: RuntimeOwnership,
    production_state_product_path: bool,
    local_runtime_allowed: bool,
) -> RuntimeOwnershipContract {
    RuntimeOwnershipContract {
        path,
        surface,
        ownership,
        production_state_product_path,
        local_runtime_allowed,
    }
}
