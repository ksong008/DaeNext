use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::DNS_TCP_MESSAGE_READ_LIMIT;

pub(in crate::production_runtime_owner::resident_dataplane) async fn read_dns_tcp_payload_async<S>(
    stream: &mut S,
) -> Result<Option<Vec<u8>>, String>
where
    S: AsyncRead + Unpin,
{
    let mut len = [0_u8; 2];
    match stream.read_exact(&mut len).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(format!("read DNS TCP request length: {err}")),
    }
    let len = u16::from_be_bytes(len) as usize;
    if len == 0 {
        return Err("DNS TCP request has empty payload".to_owned());
    }
    if len > DNS_TCP_MESSAGE_READ_LIMIT {
        return Err(format!("DNS TCP request length {len} exceeds read limit"));
    }
    let mut payload = vec![0_u8; len];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|err| format!("read DNS TCP request payload: {err}"))?;
    Ok(Some(payload))
}

pub(in crate::production_runtime_owner::resident_dataplane) async fn write_dns_tcp_payload_async<
    S,
>(
    stream: &mut S,
    payload: &[u8],
) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
{
    let len = u16::try_from(payload.len())
        .map_err(|_| format!("DNS TCP response exceeds frame limit: {}", payload.len()))?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|err| format!("write DNS TCP response length: {err}"))?;
    stream
        .write_all(payload)
        .await
        .map_err(|err| format!("write DNS TCP response payload: {err}"))?;
    stream
        .flush()
        .await
        .map_err(|err| format!("flush DNS TCP response: {err}"))
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;

    #[tokio::test]
    async fn tcp_wire_round_trips_dns_payload_with_length_prefix() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let request = b"dns-payload".to_vec();

        client
            .write_all(&(request.len() as u16).to_be_bytes())
            .await
            .unwrap();
        client.write_all(&request).await.unwrap();

        assert_eq!(
            read_dns_tcp_payload_async(&mut server).await.unwrap(),
            Some(request)
        );
    }

    #[tokio::test]
    async fn tcp_wire_writes_dns_payload_with_length_prefix() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let response = b"dns-response";

        write_dns_tcp_payload_async(&mut client, response)
            .await
            .unwrap();

        let mut framed = vec![0_u8; response.len() + 2];
        server.read_exact(&mut framed).await.unwrap();
        assert_eq!(
            u16::from_be_bytes([framed[0], framed[1]]) as usize,
            response.len()
        );
        assert_eq!(&framed[2..], response);
    }
}
