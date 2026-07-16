use super::*;
use serde_json::Value;

mod h2;
mod h3;
mod identity;
mod metrics;
mod request;

pub(in crate::production_runtime_owner::resident_dataplane::udp) use self::h2::ConnectUdpH2Session;
pub(in crate::production_runtime_owner::resident_dataplane) use self::h2::clear_connect_udp_h2_pools;
use self::h2::connect_udp_h2_pool_metrics_snapshot;
pub(in crate::production_runtime_owner::resident_dataplane::udp) use self::h3::ConnectUdpH3Session;
pub(in crate::production_runtime_owner::resident_dataplane) use self::h3::clear_connect_udp_h3_pools;
use self::h3::connect_udp_h3_pool_metrics_snapshot;
#[cfg(test)]
pub(in crate::production_runtime_owner::resident_dataplane) use self::h3::{
    ConnectUdpH3TestServer, ConnectUdpH3TestServerConfig,
};
use self::identity::connect_udp_authentication_identity;
use self::metrics::{ConnectUdpConnectionRetirementReason, ConnectUdpPoolEvents};
use self::request::{
    CAPSULE_PROTOCOL_HEADER, CAPSULE_PROTOCOL_TRUE, connect_udp_request_parts,
    validate_connect_udp_response,
};

pub(in crate::production_runtime_owner::resident_dataplane) fn connect_udp_pool_metrics_snapshot(
    generation: u64,
) -> Value {
    json!({
        "schemaVersion": 1,
        "reloadGeneration": generation,
        "h2": connect_udp_h2_pool_metrics_snapshot(generation),
        "h3": connect_udp_h3_pool_metrics_snapshot(generation),
    })
}

pub(super) struct ConnectUdpPlanRef<'a> {
    pub(super) authentication: &'a ResidentConnectUdpAuthPlan,
    pub(super) target_template: &'a MasqueUriTemplate,
    pub(super) runtime: ResidentConnectUdpRuntimePlan,
}

pub(super) fn connect_udp_h2_plan(
    proxy: &ResidentProxyPlan,
) -> Result<ConnectUdpPlanRef<'_>, String> {
    match &proxy.handler {
        ResidentProxyProtocolPlan::ConnectUdpH2Tls {
            authentication,
            target_template,
            runtime,
        } => Ok(ConnectUdpPlanRef {
            authentication,
            target_template,
            runtime: *runtime,
        }),
        _ => Err(format!(
            "CONNECT-UDP H2 executor received incompatible protocol shape {:?}",
            proxy.execution_plan().protocol
        )),
    }
}

pub(super) fn connect_udp_h3_plan(
    proxy: &ResidentProxyPlan,
) -> Result<ConnectUdpPlanRef<'_>, String> {
    match &proxy.handler {
        ResidentProxyProtocolPlan::ConnectUdpH3Tls {
            authentication,
            target_template,
            runtime,
        } => Ok(ConnectUdpPlanRef {
            authentication,
            target_template,
            runtime: *runtime,
        }),
        _ => Err(format!(
            "CONNECT-UDP H3 executor received incompatible protocol shape {:?}",
            proxy.execution_plan().protocol
        )),
    }
}
