use super::*;

type GrpcH2ResponseFuture =
    Pin<Box<dyn Future<Output = Result<http::Response<h2::RecvStream>, h2::Error>> + Send>>;

pub(crate) struct GrpcH2Response {
    response: Option<GrpcH2ResponseFuture>,
    recv_stream: Option<h2::RecvStream>,
    header_deadline: Pin<Box<time::Sleep>>,
    grpc_status_seen: bool,
    completed: bool,
}

impl GrpcH2Response {
    fn new<F>(response: F) -> Self
    where
        F: Future<Output = Result<http::Response<h2::RecvStream>, h2::Error>> + Send + 'static,
    {
        Self {
            response: Some(Box::pin(response)),
            recv_stream: None,
            header_deadline: Box::pin(time::sleep(RESIDENT_CONNECT_TIMEOUT)),
            grpc_status_seen: false,
            completed: false,
        }
    }

    pub(crate) async fn next_data(&mut self) -> Result<Option<Bytes>, String> {
        if self.completed {
            return Ok(None);
        }
        self.ensure_headers().await?;
        let recv_stream = self
            .recv_stream
            .as_mut()
            .ok_or_else(|| "gRPC HTTP/2 response body is unavailable".to_owned())?;
        match recv_stream.data().await {
            Some(Ok(bytes)) => {
                recv_stream
                    .flow_control()
                    .release_capacity(bytes.len())
                    .map_err(|err| format!("release gRPC HTTP/2 response capacity: {err}"))?;
                Ok(Some(bytes))
            }
            Some(Err(err)) => Err(format!("read gRPC HTTP/2 response data: {err}")),
            None => {
                let trailers = recv_stream
                    .trailers()
                    .await
                    .map_err(|err| format!("read gRPC HTTP/2 response trailers: {err}"))?;
                if let Some(trailers) = trailers.as_ref() {
                    self.grpc_status_seen |= validate_grpc_status(trailers, "trailers")?;
                }
                if !self.grpc_status_seen {
                    return Err("gRPC HTTP/2 response ended without grpc-status".to_owned());
                }
                self.completed = true;
                Ok(None)
            }
        }
    }

    async fn ensure_headers(&mut self) -> Result<(), String> {
        if self.recv_stream.is_some() {
            return Ok(());
        }
        let response = {
            let response = self
                .response
                .as_mut()
                .ok_or_else(|| "gRPC HTTP/2 response future is unavailable".to_owned())?;
            tokio::select! {
                response = response => response
                    .map_err(|err| format!("read gRPC HTTP/2 response headers: {err}"))?,
                _ = self.header_deadline.as_mut() => {
                    return Err("gRPC HTTP/2 response headers timeout".to_owned());
                }
            }
        };
        self.response = None;
        if !response.status().is_success() {
            return Err(format!("gRPC HTTP/2 response status {}", response.status()));
        }
        self.grpc_status_seen |= validate_grpc_status(response.headers(), "headers")?;
        self.recv_stream = Some(response.into_body());
        Ok(())
    }
}

fn validate_grpc_status(headers: &http::HeaderMap, location: &str) -> Result<bool, String> {
    let Some(status) = headers.get("grpc-status") else {
        return Ok(false);
    };
    let status = status
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| format!("gRPC HTTP/2 {location} contains malformed grpc-status"))?;
    if status != 0 {
        return Err(format!(
            "gRPC HTTP/2 {location} reported grpc-status {status}"
        ));
    }
    Ok(true)
}

pub(crate) async fn open_grpc_h2_stream(
    binding: &ResidentProxyBinding,
    first_payload: &[u8],
) -> Result<(h2::SendStream<Bytes>, GrpcH2Response, H2CarrierLease), String> {
    let proxy = binding.plan();
    let request = grpc_h2_request(proxy)?;
    let deadline =
        dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), RESIDENT_CONNECT_TIMEOUT);
    let lease = acquire_h2_carrier(binding.clone(), deadline).await?;
    let (response, mut send_stream) = lease.open_request(request, false, deadline, "gRPC").await?;
    if !first_payload.is_empty() {
        send_grpc_hunk(&mut send_stream, first_payload, false).await?;
    }
    Ok((send_stream, GrpcH2Response::new(response), lease))
}

/// Bridges a gRPC byte stream to a bounded logical duplex stream.  The VLESS
/// Encryption layer is placed on the returned stream, above gRPC framing.
pub(crate) fn spawn_grpc_h2_payload_stream(
    send_stream: h2::SendStream<Bytes>,
    response: GrpcH2Response,
    carrier_lease: H2CarrierLease,
) -> SpawnedLogicalStream {
    SpawnedLogicalStream::spawn(move |logical| {
        drive_grpc_h2_payload_stream(logical, send_stream, response, carrier_lease)
    })
}

async fn drive_grpc_h2_payload_stream(
    logical: tokio::io::DuplexStream,
    mut send_stream: h2::SendStream<Bytes>,
    mut response: GrpcH2Response,
    _carrier_lease: H2CarrierLease,
) -> Result<(), String> {
    let (mut logical_read, mut logical_write) = tokio::io::split(logical);
    let upload = async {
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let read = logical_read
                .read(&mut buffer)
                .await
                .map_err(|error| format!("read VLESS Encryption gRPC logical stream: {error}"))?;
            if read == 0 {
                send_grpc_hunk(&mut send_stream, &[], true).await?;
                return Ok(());
            }
            send_grpc_hunk(&mut send_stream, &buffer[..read], false).await?;
        }
    };
    let download = async {
        let mut response_buf = GrpcHunkReadBuffer::default();
        loop {
            let Some(data) = response.next_data().await? else {
                if !response_buf.is_empty() {
                    return Err("VLESS Encryption gRPC response ended with partial hunk".to_owned());
                }
                logical_write.shutdown().await.map_err(|error| {
                    format!("shutdown VLESS Encryption gRPC logical stream: {error}")
                })?;
                return Ok(());
            };
            response_buf.extend_from_slice(&data);
            while let Some(payload) = response_buf.next_payload()? {
                if !payload.is_empty() {
                    logical_write.write_all(payload).await.map_err(|error| {
                        format!("write VLESS Encryption gRPC logical stream: {error}")
                    })?;
                    logical_write.flush().await.map_err(|error| {
                        format!("flush VLESS Encryption gRPC logical stream: {error}")
                    })?;
                }
            }
        }
    };
    tokio::select! {
        result = upload => result,
        result = download => result,
    }
}

#[cfg(test)]
pub(crate) async fn open_grpc_h2_stream_on_io<T>(
    client: T,
    request: http::Request<()>,
    first_payload: &[u8],
) -> Result<
    (
        h2::SendStream<Bytes>,
        GrpcH2Response,
        tokio::task::JoinHandle<()>,
    ),
    String,
>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) =
        time::timeout(RESIDENT_CONNECT_TIMEOUT, h2::client::handshake(client))
            .await
            .map_err(|_| "gRPC HTTP/2 handshake timeout".to_owned())?
            .map_err(|err| format!("gRPC HTTP/2 client handshake: {err}"))?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let (response, send_stream) = sender
        .send_request(request, false)
        .map_err(|err| format!("send gRPC HTTP/2 request headers: {err}"))?;
    let mut send_stream = send_stream;
    send_grpc_hunk(&mut send_stream, first_payload, false).await?;
    Ok((send_stream, GrpcH2Response::new(response), connection_task))
}
