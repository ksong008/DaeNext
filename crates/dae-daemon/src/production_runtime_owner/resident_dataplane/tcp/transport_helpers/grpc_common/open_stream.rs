use super::*;

pub(crate) struct GrpcH2Response {
    response: Option<h2::client::ResponseFuture>,
    recv_stream: Option<h2::RecvStream>,
    header_deadline: Pin<Box<time::Sleep>>,
}

impl GrpcH2Response {
    fn new(response: h2::client::ResponseFuture) -> Self {
        Self {
            response: Some(response),
            recv_stream: None,
            header_deadline: Box::pin(time::sleep(RESIDENT_CONNECT_TIMEOUT)),
        }
    }

    pub(crate) async fn next_data(&mut self) -> Result<Option<Bytes>, String> {
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
            None => Ok(None),
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
        self.recv_stream = Some(response.into_body());
        Ok(())
    }
}

pub(crate) async fn open_grpc_h2_stream(
    client: AsyncResidentTlsClient,
    proxy: &ResidentProxyPlan,
    first_payload: &[u8],
) -> Result<
    (
        h2::SendStream<Bytes>,
        GrpcH2Response,
        tokio::task::JoinHandle<()>,
    ),
    String,
> {
    let request = grpc_h2_request(proxy)?;
    open_grpc_h2_stream_on_io(client, request, first_payload).await
}

pub(super) async fn open_grpc_h2_stream_on_io<T>(
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
