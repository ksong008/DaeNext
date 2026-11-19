use super::*;

pub trait VlessCarrierIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> VlessCarrierIo for T {}

/// Opens the byte stream on which the VLESS encryption handshake runs.
/// This stream retains any outer TLS and transport framing during Vision handoff.
pub async fn open_vless_carrier(
    binding: &ResidentProxyBinding,
    mptcp: bool,
) -> Result<(Box<dyn VlessCarrierIo>, &'static str), String> {
    let execution = binding.execution();
    let wrapper = if execution.wrapper == ResidentStreamWrapperPlan::Mux && binding.net == "tcp" {
        ResidentStreamWrapperPlan::None
    } else {
        execution.wrapper
    };
    match wrapper {
        ResidentStreamWrapperPlan::Xhttp(_) => {
            let (stream, underlay) = match binding.xhttp_mode {
                ResidentXhttpMode::PacketUp => {
                    let parts = open_xhttp_packet_up_parts(binding, mptcp).await?;
                    let underlay = parts.upload_underlay;
                    (spawn_xhttp_packet_up_payload_stream(parts), underlay)
                }
                _ => {
                    let parts = open_xhttp_stream_parts(binding, mptcp, Bytes::new()).await?;
                    let underlay = parts.upload_underlay;
                    (spawn_xhttp_stream_payload_stream(parts), underlay)
                }
            };
            Ok((Box::new(stream), underlay))
        }
        ResidentStreamWrapperPlan::Grpc => {
            let (send, recv, lease) = open_grpc_h2_stream(binding, &[]).await?;
            let underlay = lease.tls_underlay();
            Ok((
                Box::new(spawn_grpc_h2_payload_stream(send, recv, lease)),
                underlay,
            ))
        }
        wrapper @ (ResidentStreamWrapperPlan::None
        | ResidentStreamWrapperPlan::WebSocket
        | ResidentStreamWrapperPlan::HttpUpgrade) => {
            if execution.security == ResidentSecurityUnderlayPlan::None {
                let stream = open_plain_vless_tcp_stream(binding, mptcp, wrapper).await?;
                return Ok((Box::new(stream), "none"));
            }
            let mut client = open_async_resident_tls_client_with_binding(binding, mptcp).await?;
            let underlay = async_resident_tls_underlay_name(&client);
            let options = HttpUpgradeOptions::new(&binding.stream_host, &binding.stream_path);
            let stream: Box<dyn VlessCarrierIo> = match wrapper {
                ResidentStreamWrapperPlan::WebSocket => {
                    let prefix =
                        websocket_handshake_over_resident_tls_async(&mut client, &options).await?;
                    Box::new(spawn_websocket_payload_stream(client, prefix))
                }
                ResidentStreamWrapperPlan::HttpUpgrade => {
                    let prefix =
                        httpupgrade_handshake_over_resident_tls_async(&mut client, &options)
                            .await?;
                    Box::new(AsyncPrefixedStream::new(prefix, client))
                }
                _ => Box::new(client),
            };
            Ok((stream, underlay))
        }
        _ => Err("unsupported VLESS byte-stream carrier".to_owned()),
    }
}
