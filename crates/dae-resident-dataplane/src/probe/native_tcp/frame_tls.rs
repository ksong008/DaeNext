use super::super::super::AnyTlsOwnerRegistryHandle;
use super::super::super::plan::{ResidentProxyBinding, ResidentProxyProtocolPlan};
use super::errors::NativeTcpProbeError;
use super::tunnel::{NativeTcpTunnel, boxed_native_tcp_tunnel};

pub(super) async fn open_frame_tls_native_tcp_tunnel(
    binding: ResidentProxyBinding,
    target: &str,
    owner_registry: Option<AnyTlsOwnerRegistryHandle>,
    owner_deadline: dae_runtime_control::AbsoluteDeadline,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    if !matches!(
        &binding.plan().handler,
        ResidentProxyProtocolPlan::AnyTlsTcpTls { .. }
    ) {
        return Err(NativeTcpProbeError::NotAdmitted);
    }
    let owner_registry = owner_registry.ok_or_else(|| {
        NativeTcpProbeError::OwnerAcquire(
            "AnyTLS generation transport owner is unavailable for native TCP probe".to_owned(),
        )
    })?;
    let logical = owner_registry
        .acquire(binding, target.to_owned(), owner_deadline)
        .await
        .map_err(NativeTcpProbeError::OwnerAcquire)?;
    Ok(boxed_native_tcp_tunnel(logical))
}
