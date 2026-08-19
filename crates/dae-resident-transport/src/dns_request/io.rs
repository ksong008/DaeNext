use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{
    ProxyDnsRequestContext, ProxyDnsRequestError, ProxyDnsRequestFailure, ProxyDnsRequestStage,
};

pub async fn exchange_proxy_dns_framed_stream<S>(
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
            write_proxy_dns_framed_request(stream, len, payload),
        )
        .await?;

    context
        .run_typed(
            ProxyDnsRequestStage::Read,
            read_proxy_dns_framed_response(stream, response_limit),
        )
        .await
}

async fn write_proxy_dns_framed_request<S>(
    stream: &mut S,
    length: u16,
    payload: &[u8],
) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(payload).await?;
    stream.flush().await
}

async fn read_proxy_dns_framed_response<S>(
    stream: &mut S,
    response_limit: usize,
) -> Result<Vec<u8>, ProxyDnsRequestError>
where
    S: AsyncRead + Unpin,
{
    let mut length = [0_u8; 2];
    stream.read_exact(&mut length).await.map_err(|error| {
        ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Read,
            ProxyDnsRequestFailure::Network,
            error.to_string(),
        )
    })?;
    let length = u16::from_be_bytes(length) as usize;
    if length > response_limit {
        return Err(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Read,
            ProxyDnsRequestFailure::Capacity,
            format!("proxy DNS TCP response length {length} exceeds {response_limit}"),
        ));
    }
    let mut response = vec![0_u8; length];
    stream.read_exact(&mut response).await.map_err(|error| {
        ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Read,
            ProxyDnsRequestFailure::Network,
            error.to_string(),
        )
    })?;
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

    #[tokio::test]
    async fn framed_proxy_dns_send_uses_the_request_deadline_and_send_stage() {
        let (mut client, _server) = tokio::io::duplex(1);
        let error = exchange_proxy_dns_framed_stream(
            &mut client,
            &[0_u8; 1024],
            u16::MAX as usize,
            ProxyDnsRequestContext::from_timeout(std::time::Duration::from_millis(10)),
        )
        .await
        .unwrap_err();

        assert_eq!(error.stage(), ProxyDnsRequestStage::Send);
        assert_eq!(error.failure(), ProxyDnsRequestFailure::Deadline);
    }

    #[tokio::test]
    async fn framed_proxy_dns_read_uses_the_same_request_deadline_and_read_stage() {
        let (mut client, _server) = tokio::io::duplex(64);
        let error = exchange_proxy_dns_framed_stream(
            &mut client,
            b"query",
            u16::MAX as usize,
            ProxyDnsRequestContext::from_timeout(std::time::Duration::from_millis(10)),
        )
        .await
        .unwrap_err();

        assert_eq!(error.stage(), ProxyDnsRequestStage::Read);
        assert_eq!(error.failure(), ProxyDnsRequestFailure::Deadline);
    }

    #[tokio::test]
    async fn framed_proxy_dns_read_keeps_capacity_failures_typed() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let server_task = tokio::spawn(async move {
            let request_len = server.read_u16().await.unwrap() as usize;
            let mut request = vec![0_u8; request_len];
            server.read_exact(&mut request).await.unwrap();
            server.write_u16(65).await.unwrap();
            server.flush().await.unwrap();
        });
        let error = exchange_proxy_dns_framed_stream(
            &mut client,
            b"query",
            64,
            ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(1)),
        )
        .await
        .unwrap_err();

        assert_eq!(error.stage(), ProxyDnsRequestStage::Read);
        assert_eq!(error.failure(), ProxyDnsRequestFailure::Capacity);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn framed_proxy_dns_transport_failure_keeps_the_network_class() {
        let (mut client, server) = tokio::io::duplex(64);
        drop(server);
        let error = exchange_proxy_dns_framed_stream(
            &mut client,
            b"query",
            u16::MAX as usize,
            ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(1)),
        )
        .await
        .unwrap_err();

        assert_eq!(error.stage(), ProxyDnsRequestStage::Send);
        assert_eq!(error.failure(), ProxyDnsRequestFailure::Network);
    }
}
