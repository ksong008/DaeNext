use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{
    ProxyDnsRequestContext, ProxyDnsRequestError, ProxyDnsRequestFailure, ProxyDnsRequestStage,
};

pub(in crate::production_runtime_owner::resident_dataplane) async fn exchange_proxy_dns_framed_stream<
    S,
>(
    stream: &mut S,
    payload: &[u8],
    response_limit: usize,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ProxyDnsRequestError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let len = u16::try_from(payload.len()).map_err(|_| {
        ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Send,
            ProxyDnsRequestFailure::Capacity,
            format!("DNS request exceeds TCP frame limit: {}", payload.len()),
        )
    })?;
    context
        .run(
            ProxyDnsRequestStage::Send,
            ProxyDnsRequestFailure::Network,
            stream.write_all(&len.to_be_bytes()),
        )
        .await?;
    context
        .run(
            ProxyDnsRequestStage::Send,
            ProxyDnsRequestFailure::Network,
            stream.write_all(payload),
        )
        .await?;
    context
        .run(
            ProxyDnsRequestStage::Send,
            ProxyDnsRequestFailure::Network,
            stream.flush(),
        )
        .await?;

    let mut len = [0_u8; 2];
    context
        .run(
            ProxyDnsRequestStage::Read,
            ProxyDnsRequestFailure::Network,
            stream.read_exact(&mut len),
        )
        .await?;
    let len = u16::from_be_bytes(len) as usize;
    if len > response_limit {
        return Err(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Read,
            ProxyDnsRequestFailure::Capacity,
            format!("proxy DNS TCP response length {len} exceeds {response_limit}"),
        ));
    }
    let mut response = vec![0_u8; len];
    context
        .run(
            ProxyDnsRequestStage::Read,
            ProxyDnsRequestFailure::Network,
            stream.read_exact(&mut response),
        )
        .await?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn framed_proxy_dns_exchange_preserves_large_responses() {
        for response_size in [1500_usize, 4096_usize] {
            let (mut client, mut server) = tokio::io::duplex(response_size.saturating_add(64));
            let response = (0..response_size)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>();
            let expected = response.clone();
            let server_task = tokio::spawn(async move {
                let request_len = server.read_u16().await.unwrap() as usize;
                let mut request = vec![0_u8; request_len];
                server.read_exact(&mut request).await.unwrap();
                assert_eq!(request, b"proxy-dns-request");
                server.write_u16(response.len() as u16).await.unwrap();
                server.write_all(&response).await.unwrap();
                server.flush().await.unwrap();
            });
            let context = ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(1));
            let actual = exchange_proxy_dns_framed_stream(
                &mut client,
                b"proxy-dns-request",
                u16::MAX as usize,
                context,
            )
            .await
            .unwrap();
            assert_eq!(actual, expected);
            server_task.await.unwrap();
        }
    }
}
