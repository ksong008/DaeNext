use std::time::{Duration, Instant};

mod basic_tcp;
mod check;
mod errors;
mod frame_tls;
mod quic_stream;
mod shadowsocks;
mod target;
mod trojan;
mod tunnel;
mod vless;
mod vmess;

use self::basic_tcp::open_basic_native_tcp_tunnel;
use self::check::probe_native_tcp_tunnel;
use self::errors::{NativeTcpProbeError, NativeTcpProbeFailure, NativeTcpProbeStage};
use self::frame_tls::open_frame_tls_native_tcp_tunnel;
use self::quic_stream::open_quic_stream_native_tcp_tunnel;
use self::shadowsocks::open_shadowsocks_native_tcp_tunnel;
use self::trojan::open_trojan_native_tcp_tunnel;
use self::tunnel::{NativeTcpTunnel, cleanup_native_tcp_tunnel};
use self::vless::open_vless_native_tcp_tunnel;
use self::vmess::open_vmess_native_tcp_tunnel;
use super::super::plan::{ResidentProxyBinding, ResidentTcpProbeDispatch};
use super::super::tcp::QuicEndpointCallerClass;
use super::super::{
    AnyTlsOwnerRegistryHandle, Hysteria2OwnerRegistryHandle, JuicityOwnerRegistryHandle,
    RESIDENT_RUNTIME_TASK_JOIN_GRACE, TuicOwnerRegistryHandle,
};

#[allow(clippy::too_many_arguments)]
pub(in crate::production_runtime_owner::resident_dataplane) async fn probe_native_proxy_tcp_async(
    binding: ResidentProxyBinding,
    scheme: &str,
    target: &str,
    host: &str,
    path: &str,
    method: &str,
    timeout: Duration,
    hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
    caller: QuicEndpointCallerClass,
) -> Result<Duration, String> {
    let attempt_started = Instant::now();
    let owner_deadline =
        dae_runtime_control::AbsoluteDeadline::from_now(std::time::Instant::now(), timeout);
    let opened = await_native_tcp_probe_with_timeout(
        owner_deadline,
        native_tcp_probe_open_stage(binding.execution().protocol.probe_dispatch()),
        open_native_tcp_tunnel(
            binding.clone(),
            target,
            hysteria2_owner_registry,
            tuic_owner_registry,
            juicity_owner_registry,
            anytls_owner_registry,
            caller,
            owner_deadline,
        ),
    )
    .await
    .map_err(|error| error.to_string())?;
    let mut tunnel = match opened {
        Ok(tunnel) => tunnel,
        Err(NativeTcpProbeError::NotAdmitted) => {
            return Err(NativeTcpProbeFailure::new(
                NativeTcpProbeStage::Admission,
                format!(
                    "not admitted for protocol {} net {} tls {}",
                    binding.plan().protocol,
                    binding.plan().net,
                    binding.plan().tls
                ),
            )
            .to_string());
        }
        Err(NativeTcpProbeError::Open(error)) => {
            return Err(
                NativeTcpProbeFailure::new(NativeTcpProbeStage::ProtocolOpen, error).to_string(),
            );
        }
        Err(NativeTcpProbeError::OwnerAcquire(error)) => {
            return Err(
                NativeTcpProbeFailure::new(NativeTcpProbeStage::OwnerAcquire, error).to_string(),
            );
        }
        Err(NativeTcpProbeError::Connect(error)) => {
            return Err(
                NativeTcpProbeFailure::new(NativeTcpProbeStage::Connect, error).to_string(),
            );
        }
        Err(NativeTcpProbeError::Security(error)) => {
            return Err(
                NativeTcpProbeFailure::new(NativeTcpProbeStage::Security, error).to_string(),
            );
        }
    };
    let probe_result =
        probe_native_tcp_tunnel(&mut *tunnel, scheme, host, path, method, owner_deadline).await;
    let response_elapsed = probe_result
        .as_ref()
        .ok()
        .map(|_| attempt_started.elapsed());
    let cleanup_result = tokio::time::timeout(
        RESIDENT_RUNTIME_TASK_JOIN_GRACE,
        cleanup_native_tcp_tunnel(&mut *tunnel),
    )
    .await
    .map_err(|_| NativeTcpProbeFailure::deadline(NativeTcpProbeStage::Cleanup))
    .and_then(|result| {
        result.map_err(|error| {
            NativeTcpProbeFailure::new(
                NativeTcpProbeStage::Cleanup,
                format!("clean up native outbound probe tunnel: {error}"),
            )
        })
    });
    match (probe_result, cleanup_result) {
        (Err(error), _) => Err(error.to_string()),
        (Ok(()), Err(error)) => Err(error.to_string()),
        (Ok(()), Ok(())) => Ok(response_elapsed.unwrap_or_default()),
    }
}

fn native_tcp_probe_open_stage(dispatch: ResidentTcpProbeDispatch) -> NativeTcpProbeStage {
    match dispatch {
        ResidentTcpProbeDispatch::Basic => NativeTcpProbeStage::Connect,
        ResidentTcpProbeDispatch::AnyTls | ResidentTcpProbeDispatch::Quic => {
            NativeTcpProbeStage::OwnerAcquire
        }
        ResidentTcpProbeDispatch::Vless
        | ResidentTcpProbeDispatch::Vmess
        | ResidentTcpProbeDispatch::Trojan
        | ResidentTcpProbeDispatch::Shadowsocks => NativeTcpProbeStage::ProtocolOpen,
    }
}

async fn await_native_tcp_probe_with_timeout<F>(
    deadline: dae_runtime_control::AbsoluteDeadline,
    stage: NativeTcpProbeStage,
    operation: F,
) -> Result<F::Output, NativeTcpProbeFailure>
where
    F: std::future::Future,
{
    let remaining = deadline
        .remaining_at(std::time::Instant::now())
        .unwrap_or(Duration::ZERO);
    tokio::time::timeout(remaining, operation)
        .await
        .map_err(|_| NativeTcpProbeFailure::deadline(stage))
}

#[allow(clippy::too_many_arguments)]
async fn open_native_tcp_tunnel(
    binding: ResidentProxyBinding,
    target: &str,
    hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
    caller: QuicEndpointCallerClass,
    owner_deadline: dae_runtime_control::AbsoluteDeadline,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    match binding.execution().protocol.probe_dispatch() {
        ResidentTcpProbeDispatch::Basic => open_basic_native_tcp_tunnel(binding, target).await,
        ResidentTcpProbeDispatch::Vless => {
            open_vless_native_tcp_tunnel(binding, target, owner_deadline).await
        }
        ResidentTcpProbeDispatch::Vmess => open_vmess_native_tcp_tunnel(binding, target).await,
        ResidentTcpProbeDispatch::Trojan => open_trojan_native_tcp_tunnel(binding, target).await,
        ResidentTcpProbeDispatch::AnyTls => {
            open_frame_tls_native_tcp_tunnel(binding, target, anytls_owner_registry, owner_deadline)
                .await
        }
        ResidentTcpProbeDispatch::Shadowsocks => {
            open_shadowsocks_native_tcp_tunnel(binding, target).await
        }
        ResidentTcpProbeDispatch::Quic => {
            open_quic_stream_native_tcp_tunnel(
                binding,
                target,
                hysteria2_owner_registry,
                tuic_owner_registry,
                juicity_owner_registry,
                caller,
                owner_deadline,
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn timeout_bounds_the_complete_native_probe_future() {
        let timeout = Duration::from_millis(1);
        let deadline =
            dae_runtime_control::AbsoluteDeadline::from_now(std::time::Instant::now(), timeout);
        let result = await_native_tcp_probe_with_timeout(
            deadline,
            NativeTcpProbeStage::ResponseRead,
            std::future::pending::<Result<(), String>>(),
        )
        .await;
        let error = result.unwrap_err();
        assert_eq!(error.stage(), NativeTcpProbeStage::ResponseRead);
        assert_eq!(
            error.to_string(),
            "native outbound probe [response-read]: deadline elapsed"
        );
    }
}
