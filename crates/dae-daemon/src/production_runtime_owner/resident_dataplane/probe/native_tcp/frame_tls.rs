use std::sync::{Arc, atomic::Ordering};

use dae_outbound::{anytls::contract as anytls_contract, anytls::link as anytls_link};

use super::super::super::ResidentStopSignal;

use super::super::super::client::open_async_resident_tls_client_with_flow;
use super::super::super::plan::{ResidentProxyPlan, ResidentProxyProtocolPlan};
use super::super::super::{
    ResidentDataplaneMetrics,
    tcp::{relay_tcp_over_anytls_async, wait_anytls_synack, write_anytls_frame},
};
use super::errors::NativeTcpProbeError;
use super::target::native_tcp_probe_selection;
use super::tunnel::{NativeTcpTunnel, SpawnedNativeTcpTunnel};

pub(super) async fn open_frame_tls_native_tcp_tunnel(
    proxy: Arc<ResidentProxyPlan>,
    target: &str,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    let selection = native_tcp_probe_selection(proxy, target);
    let ResidentProxyProtocolPlan::AnyTlsTcpTls { auth } = &selection.proxy.handler else {
        return Err(NativeTcpProbeError::NotAdmitted);
    };

    let mut client =
        open_async_resident_tls_client_with_flow(&selection.proxy, selection.mark, selection.mptcp)
            .await
            .map_err(NativeTcpProbeError::Open)?;
    let sid = 1_u32;
    client
        .write_plain_all(
            &anytls_link::handshake_auth_bytes(auth),
            "write native AnyTLS auth handshake",
        )
        .await
        .map_err(NativeTcpProbeError::Open)?;
    write_anytls_frame(
        &mut client,
        anytls_contract::CMD_SETTINGS,
        sid,
        &anytls_link::settings_bytes(),
        "write native AnyTLS settings",
    )
    .await
    .map_err(NativeTcpProbeError::Open)?;
    write_anytls_frame(
        &mut client,
        anytls_contract::CMD_SYN,
        sid,
        &[],
        "write native AnyTLS SYN",
    )
    .await
    .map_err(NativeTcpProbeError::Open)?;
    let target_addr = anytls_link::socks_addr(target)
        .map_err(|err| NativeTcpProbeError::Open(format!("build native AnyTLS target: {err}")))?;
    write_anytls_frame(
        &mut client,
        anytls_contract::CMD_PSH,
        sid,
        &target_addr,
        "write native AnyTLS target",
    )
    .await
    .map_err(NativeTcpProbeError::Open)?;
    wait_anytls_synack(&mut client, sid)
        .await
        .map_err(NativeTcpProbeError::Open)?;

    let (probe, mut relay_side) = tokio::io::duplex(64 * 1024);
    let stop = ResidentStopSignal::shared();
    let relay_stop = Arc::clone(&stop);
    let metrics = ResidentDataplaneMetrics::default();
    let task = tokio::spawn(async move {
        let _ =
            relay_tcp_over_anytls_async(&mut relay_side, &mut client, relay_stop, sid, &metrics)
                .await;
        stop.store(true, Ordering::Relaxed);
    });
    Ok(Box::new(SpawnedNativeTcpTunnel::new(probe, task)))
}
