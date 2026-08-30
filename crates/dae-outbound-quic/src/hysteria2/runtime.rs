use tokio::io::AsyncWriteExt;

use dae_outbound_core::error::OutboundError;

use super::padding::tcp_request_padding;
use super::wire::build_tcp_request_stream_with_padding;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hysteria2TcpResponseHead {
    pub ok: bool,
    pub message: String,
}
pub async fn write_hysteria2_tcp_request(
    send: &mut quinn::SendStream,
    target: &str,
) -> Result<(), OutboundError> {
    let padding = tcp_request_padding();
    let request = build_tcp_request_stream_with_padding(target, &[], &padding)?;
    send.write_all(&request)
        .await
        .map_err(|err| bad_runtime(format!("write Hysteria2 TCP request: {err}")))?;
    send.flush()
        .await
        .map_err(|err| bad_runtime(format!("flush Hysteria2 TCP request: {err}")))
}

pub async fn read_hysteria2_tcp_response(
    recv: &mut quinn::RecvStream,
) -> Result<Hysteria2TcpResponseHead, OutboundError> {
    let status = read_u8(recv, "read Hysteria2 TCP response status").await?;
    let message_len = read_quic_varint(recv, "read Hysteria2 TCP response message length").await?;
    if message_len > 2048 {
        return Err(bad_runtime("invalid Hysteria2 TCP response message length"));
    }
    let mut message = vec![0_u8; message_len as usize];
    recv.read_exact(&mut message)
        .await
        .map_err(|err| bad_runtime(format!("read Hysteria2 TCP response message: {err}")))?;
    let padding_len = read_quic_varint(recv, "read Hysteria2 TCP response padding length").await?;
    if padding_len > 4096 {
        return Err(bad_runtime("invalid Hysteria2 TCP response padding length"));
    }
    if padding_len > 0 {
        let mut padding = vec![0_u8; padding_len as usize];
        recv.read_exact(&mut padding)
            .await
            .map_err(|err| bad_runtime(format!("read Hysteria2 TCP response padding: {err}")))?;
    }
    let message = String::from_utf8(message)
        .map_err(|err| bad_runtime(format!("Hysteria2 TCP response message utf8: {err}")))?;
    Ok(Hysteria2TcpResponseHead {
        ok: status == 0,
        message,
    })
}

async fn read_u8(recv: &mut quinn::RecvStream, label: &str) -> Result<u8, OutboundError> {
    let mut byte = [0_u8; 1];
    recv.read_exact(&mut byte)
        .await
        .map_err(|err| bad_runtime(format!("{label}: {err}")))?;
    Ok(byte[0])
}

async fn read_quic_varint(recv: &mut quinn::RecvStream, label: &str) -> Result<u64, OutboundError> {
    let first = read_u8(recv, label).await?;
    let len = 1_usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    if len > 1 {
        let mut rest = vec![0_u8; len - 1];
        recv.read_exact(&mut rest)
            .await
            .map_err(|err| bad_runtime(format!("{label}: {err}")))?;
        for byte in rest {
            value = (value << 8) | u64::from(byte);
        }
    }
    Ok(value)
}

fn bad_runtime(message: impl Into<String>) -> OutboundError {
    OutboundError::BadHysteria2(message.into())
}
