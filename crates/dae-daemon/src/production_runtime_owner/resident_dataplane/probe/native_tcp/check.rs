use std::time::Duration;

use super::super::{
    read_resident_tcp_probe_https_response_over_stream_async,
    read_resident_tcp_probe_response_async, resident_tcp_probe_http_request,
};
use super::tunnel::NativeTcpTunnel;

pub(super) async fn probe_native_tcp_tunnel(
    tunnel: &mut dyn NativeTcpTunnel,
    scheme: &str,
    host: &str,
    path: &str,
    method: &str,
    timeout: Duration,
) -> Result<(), String> {
    match scheme {
        "http" => {
            let request = resident_tcp_probe_http_request(method, path, host);
            tokio::time::timeout(
                timeout,
                tokio::io::AsyncWriteExt::write_all(tunnel, &request),
            )
            .await
            .map_err(|_| "write native TCP probe HTTP request: timeout".to_owned())?
            .map_err(|err| format!("write native TCP probe HTTP request: {err}"))?;
            tokio::time::timeout(timeout, tokio::io::AsyncWriteExt::flush(tunnel))
                .await
                .map_err(|_| "flush native TCP probe HTTP request: timeout".to_owned())?
                .map_err(|err| format!("flush native TCP probe HTTP request: {err}"))?;
            read_resident_tcp_probe_response_async(tunnel, path, timeout).await
        }
        "https" => {
            read_resident_tcp_probe_https_response_over_stream_async(
                tunnel, host, path, method, timeout,
            )
            .await
        }
        other => Err(format!("native TCP probe unsupported scheme: {other}")),
    }
}
