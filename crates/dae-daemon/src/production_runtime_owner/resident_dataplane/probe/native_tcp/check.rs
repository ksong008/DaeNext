use std::time::Duration;

use super::super::{
    ResidentTcpProbeHttpStage, read_resident_tcp_probe_https_response_over_stream_async,
    read_resident_tcp_probe_response_async, resident_tcp_probe_http_request,
};
use super::errors::{NativeTcpProbeFailure, NativeTcpProbeStage};
use super::tunnel::NativeTcpTunnel;

pub(super) async fn probe_native_tcp_tunnel(
    tunnel: &mut dyn NativeTcpTunnel,
    scheme: &str,
    host: &str,
    path: &str,
    method: &str,
    deadline: dae_runtime_control::AbsoluteDeadline,
) -> Result<(), NativeTcpProbeFailure> {
    match scheme {
        "http" => {
            let request = resident_tcp_probe_http_request(method, path, host);
            tokio::time::timeout(
                probe_remaining(deadline, NativeTcpProbeStage::RequestWrite)?,
                tokio::io::AsyncWriteExt::write_all(tunnel, &request),
            )
            .await
            .map_err(|_| NativeTcpProbeFailure::deadline(NativeTcpProbeStage::RequestWrite))?
            .map_err(|err| {
                NativeTcpProbeFailure::new(
                    NativeTcpProbeStage::RequestWrite,
                    format!("write native TCP probe HTTP request: {err}"),
                )
            })?;
            tokio::time::timeout(
                probe_remaining(deadline, NativeTcpProbeStage::RequestWrite)?,
                tokio::io::AsyncWriteExt::flush(tunnel),
            )
            .await
            .map_err(|_| NativeTcpProbeFailure::deadline(NativeTcpProbeStage::RequestWrite))?
            .map_err(|err| {
                NativeTcpProbeFailure::new(
                    NativeTcpProbeStage::RequestWrite,
                    format!("flush native TCP probe HTTP request: {err}"),
                )
            })?;
            read_resident_tcp_probe_response_async(tunnel, path, deadline)
                .await
                .map_err(map_http_probe_error)
        }
        "https" => read_resident_tcp_probe_https_response_over_stream_async(
            tunnel, host, path, method, deadline,
        )
        .await
        .map_err(map_http_probe_error),
        other => Err(NativeTcpProbeFailure::new(
            NativeTcpProbeStage::Admission,
            format!("unsupported scheme: {other}"),
        )),
    }
}

fn probe_remaining(
    deadline: dae_runtime_control::AbsoluteDeadline,
    stage: NativeTcpProbeStage,
) -> Result<Duration, NativeTcpProbeFailure> {
    deadline
        .remaining_at(std::time::Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| NativeTcpProbeFailure::deadline(stage))
}

fn map_http_probe_error(error: super::super::ResidentTcpProbeHttpError) -> NativeTcpProbeFailure {
    let stage = match error.stage {
        ResidentTcpProbeHttpStage::Security => NativeTcpProbeStage::Security,
        ResidentTcpProbeHttpStage::Write => NativeTcpProbeStage::RequestWrite,
        ResidentTcpProbeHttpStage::Read => NativeTcpProbeStage::ResponseRead,
    };
    NativeTcpProbeFailure::new(stage, error.detail)
}
