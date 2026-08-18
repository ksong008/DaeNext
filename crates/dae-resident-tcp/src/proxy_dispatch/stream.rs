use super::*;

mod basic;
mod shadowsocks;
mod vmess;

use self::basic::handle_basic_stream_proxy_async;
use self::shadowsocks::handle_shadowsocks_stream_proxy_async;
use self::vmess::handle_vmess_stream_proxy_async;

pub async fn handle_resident_proxy_tcp_connection_async(
    inbound: TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: TcpSniffReport,
    metrics: Arc<ResidentDataplaneMetrics>,
) -> Result<Value, String> {
    match selection.proxy.execution_plan().protocol {
        ResidentProtocolShape::VmessAead => {
            handle_vmess_stream_proxy_async(
                inbound,
                peer,
                original_dst,
                selection,
                stop,
                sniff,
                metrics,
            )
            .await
        }
        ResidentProtocolShape::Socks5 | ResidentProtocolShape::HttpProxy => {
            handle_basic_stream_proxy_async(
                inbound,
                peer,
                original_dst,
                selection,
                stop,
                sniff,
                metrics,
            )
            .await
        }
        ResidentProtocolShape::ShadowsocksAead
        | ResidentProtocolShape::Shadowsocks2022
        | ResidentProtocolShape::ShadowsocksSimpleObfsHttp
        | ResidentProtocolShape::ShadowsocksSimpleObfsTls
        | ResidentProtocolShape::ShadowsocksV2rayPluginTlsWebSocket
        | ResidentProtocolShape::Shadowsocks2022SimpleObfsHttp
        | ResidentProtocolShape::ShadowsocksRHttpSimple => {
            handle_shadowsocks_stream_proxy_async(
                inbound,
                peer,
                original_dst,
                selection,
                stop,
                sniff,
                metrics,
            )
            .await
        }
        protocol => Err(format!(
            "resident stream TCP dispatcher has no handler for exact protocol shape {protocol:?}"
        )),
    }
}
