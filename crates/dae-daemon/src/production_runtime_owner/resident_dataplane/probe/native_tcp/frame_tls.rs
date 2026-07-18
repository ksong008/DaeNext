use std::sync::Arc;

use super::super::super::AnyTlsOwnerRegistryHandle;
use super::super::super::plan::{ResidentProxyPlan, ResidentProxyProtocolPlan};
use super::errors::NativeTcpProbeError;
use super::tunnel::NativeTcpTunnel;

pub(super) async fn open_frame_tls_native_tcp_tunnel(
    proxy: Arc<ResidentProxyPlan>,
    target: &str,
    owner_registry: Option<AnyTlsOwnerRegistryHandle>,
    owner_deadline: dae_runtime_control::AbsoluteDeadline,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    if !matches!(
        &proxy.handler,
        ResidentProxyProtocolPlan::AnyTlsTcpTls { .. }
    ) {
        return Err(NativeTcpProbeError::NotAdmitted);
    }
    let owner_registry = owner_registry.ok_or_else(|| {
        NativeTcpProbeError::Open(
            "AnyTLS generation transport owner is unavailable for native TCP probe".to_owned(),
        )
    })?;
    let logical = owner_registry
        .acquire(proxy, target.to_owned(), owner_deadline)
        .await
        .map_err(NativeTcpProbeError::Open)?;
    Ok(Box::new(logical))
}
