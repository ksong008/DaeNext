use super::*;
use crate::production_runtime_owner::resident_dataplane::plan::ResidentProxyProtocolPlan;
use crate::production_runtime_owner::resident_dataplane::tcp::{
    http_proxy_connect_plain_async, socks5_connect_async,
};

pub(super) async fn open_proxy_tcp_stream_through_parent_async(
    proxy: &ResidentProxyPlan,
    parent: &ResidentProxyPlan,
) -> Result<TokioTcpStream, String> {
    let mut parent_chain = Vec::new();
    let mut current = Some(parent);
    while let Some(parent) = current {
        parent_chain.push(parent);
        current = parent.chain_parent.as_deref();
    }

    let first_parent = parent_chain
        .first()
        .ok_or_else(|| "resident chain has no parent".to_owned())?;
    let parent_target =
        authority_from_host_port(first_parent.server_host.as_str(), first_parent.server_port);
    let connection =
        open_direct_tcp_connection_async(parent_target, first_parent.mark, first_parent.mptcp)
            .await?;
    let mut stream = TokioTcpStream::from_std(connection.stream)
        .map_err(|err| format!("adopt async parent proxy TCP stream: {err}"))?;

    for window in parent_chain.windows(2) {
        let current_parent = window[0];
        let next_parent = window[1];
        let next_target =
            authority_from_host_port(next_parent.server_host.as_str(), next_parent.server_port);
        connect_plain_parent_to_target_async(&mut stream, current_parent, &next_target).await?;
    }

    let final_parent = parent_chain
        .last()
        .ok_or_else(|| "resident chain has no final parent".to_owned())?;
    let final_target = authority_from_host_port(proxy.server_host.as_str(), proxy.server_port);
    connect_plain_parent_to_target_async(&mut stream, final_parent, &final_target).await?;
    Ok(stream)
}

async fn connect_plain_parent_to_target_async(
    stream: &mut TokioTcpStream,
    parent: &ResidentProxyPlan,
    target: &str,
) -> Result<(), String> {
    match &parent.handler {
        ResidentProxyProtocolPlan::Socks5Tcp { username, password } => {
            socks5_connect_async(stream, target, username, password).await?;
        }
        ResidentProxyProtocolPlan::HttpProxyTcp {
            username, password, ..
        } if parent.tls == "none" => {
            http_proxy_connect_plain_async(stream, target, username, password, false, "", "")
                .await?;
        }
        _ => {
            return Err(format!(
                "resident chain parent {} is not backed by a plain parent CONNECT executor",
                parent.protocol
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "parent_transport/tests.rs"]
mod tests;
