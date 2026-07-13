use super::*;

mod h2;

pub(in crate::production_runtime_owner::resident_dataplane::udp) use self::h2::ConnectUdpH2Session;
pub(in crate::production_runtime_owner::resident_dataplane) use self::h2::clear_connect_udp_h2_pools;

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
