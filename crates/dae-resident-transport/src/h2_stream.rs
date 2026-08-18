use bytes::Bytes;
use std::time::Instant;

use dae_resident_core::RESIDENT_CONNECT_TIMEOUT;
use dae_resident_plan::ResidentProxyBinding;
use tokio::time;

use crate::{
    H2CarrierLease, H2CarrierResponseFuture, acquire_h2_carrier, send_h2_data_with_context,
};

pub async fn open_h2_body_stream(
    binding: &ResidentProxyBinding,
    first_payload: &[u8],
    context: &str,
) -> Result<(h2::SendStream<Bytes>, h2::RecvStream, H2CarrierLease), String> {
    let initial_chunks = if first_payload.is_empty() {
        Vec::new()
    } else {
        vec![Bytes::copy_from_slice(first_payload)]
    };
    open_h2_body_stream_with_initial_chunks(binding, initial_chunks, context).await
}

pub async fn open_h2_body_stream_with_initial_chunks(
    binding: &ResidentProxyBinding,
    initial_chunks: Vec<Bytes>,
    context: &str,
) -> Result<(h2::SendStream<Bytes>, h2::RecvStream, H2CarrierLease), String> {
    let proxy = binding.plan();
    let deadline =
        dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), RESIDENT_CONNECT_TIMEOUT);
    let lease = acquire_h2_carrier(binding.clone(), deadline).await?;
    let uri = format!(
        "https://{}{}",
        h2_body_authority(proxy),
        h2_body_request_path(&proxy.stream_path)
    );
    let request = h2_body_request(uri, context)?;
    let (response, mut send_stream) = lease
        .open_request(request, false, deadline, context)
        .await?;
    for chunk in initial_chunks {
        if !chunk.is_empty() {
            send_h2_data_with_context(&mut send_stream, chunk, false, context).await?;
        }
    }
    let response = time::timeout(RESIDENT_CONNECT_TIMEOUT, response)
        .await
        .map_err(|_| format!("{context} HTTP/2 response headers timeout"))?
        .map_err(|err| format!("read {context} HTTP/2 response headers: {err}"))?;
    if response.status() != http::StatusCode::OK {
        return Err(format!(
            "{context} HTTP/2 response status {}",
            response.status()
        ));
    }
    Ok((send_stream, response.into_body(), lease))
}

pub async fn open_h2_body_stream_with_deferred_response(
    binding: &ResidentProxyBinding,
    initial_chunks: Vec<Bytes>,
    context: &'static str,
) -> Result<
    (
        h2::SendStream<Bytes>,
        H2CarrierResponseFuture,
        H2CarrierLease,
    ),
    String,
> {
    let proxy = binding.plan();
    let deadline =
        dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), RESIDENT_CONNECT_TIMEOUT);
    let lease = acquire_h2_carrier(binding.clone(), deadline).await?;
    let uri = format!(
        "https://{}{}",
        h2_body_authority(proxy),
        h2_body_request_path(&proxy.stream_path)
    );
    let request = h2_body_request(uri, context)?;
    let (response, mut send_stream) = lease
        .open_request(request, false, deadline, context)
        .await?;
    for chunk in initial_chunks {
        if !chunk.is_empty() {
            send_h2_data_with_context(&mut send_stream, chunk, false, context).await?;
        }
    }
    Ok((send_stream, response, lease))
}

fn h2_body_authority(proxy: &dae_resident_plan::ResidentProxyPlan) -> String {
    if proxy.stream_host.is_empty() {
        proxy.server_name.clone()
    } else {
        proxy.stream_host.clone()
    }
}

fn h2_body_request_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_owned()
    } else if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    }
}

fn h2_body_request(uri: String, context: &str) -> Result<http::Request<()>, String> {
    http::Request::builder()
        .method(http::Method::PUT)
        .version(http::Version::HTTP_2)
        .uri(uri)
        .header(http::header::ACCEPT_ENCODING, "identity")
        .header(http::header::USER_AGENT, "dae-rust-native-resident")
        .body(())
        .map_err(|err| format!("build {context} HTTP/2 request: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_h2_body_request_uses_http2_pseudo_header_encoding() {
        let request = h2_body_request(
            "https://transport.invalid/tunnel".to_owned(),
            "legacy carrier test",
        )
        .unwrap();

        assert_eq!(request.version(), http::Version::HTTP_2);
        assert_eq!(request.method(), http::Method::PUT);
        assert_eq!(request.uri().authority().unwrap(), "transport.invalid");
    }
}
