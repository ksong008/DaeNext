use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TrojanUdpCarrierKind {
    Tls,
    WebSocket,
    HttpUpgrade,
    Grpc,
}

impl TrojanUdpCarrierKind {
    pub(super) fn evidence_fields(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Tls => ("tokio-stream-session", "tls-stream-reused", "standard-tls"),
            Self::WebSocket => (
                "tokio-wrapper-stream-session",
                "tls-websocket-tunnel-reused",
                "standard-tls",
            ),
            Self::HttpUpgrade => (
                "tokio-wrapper-stream-session",
                "tls-httpupgrade-tunnel-reused",
                "standard-tls",
            ),
            Self::Grpc => (
                "tokio-h2-wrapper-stream-session",
                "tls-grpc-h2-stream-reused",
                "standard-tls",
            ),
        }
    }
}

pub(super) enum TrojanUdpCarrier {
    Tls {
        client: AsyncResidentTlsClient,
        tls_underlay: &'static str,
    },
    WebSocket {
        client: AsyncResidentTlsClient,
        state: AsyncWebSocketPayloadState,
        tls_underlay: &'static str,
    },
    HttpUpgrade {
        client: AsyncResidentTlsClient,
        tls_underlay: &'static str,
    },
    Grpc {
        send_stream: h2::SendStream<Bytes>,
        response: GrpcH2Response,
        response_buf: GrpcHunkReadBuffer,
        connection_task: tokio::task::JoinHandle<()>,
        tls_underlay: &'static str,
    },
}

impl TrojanUdpCarrier {
    pub(super) async fn open(
        kind: TrojanUdpCarrierKind,
        proxy: &ResidentProxyPlan,
        initial_packet: &[u8],
    ) -> Result<Self, String> {
        let mut client = open_async_resident_tls_client(proxy).await?;
        let tls_underlay = async_resident_tls_underlay_name(&client);
        match kind {
            TrojanUdpCarrierKind::Tls => {
                write_async_tls_plain_all(
                    &mut client,
                    initial_packet,
                    "write Trojan UDP session first packet",
                )
                .await?;
                Ok(Self::Tls {
                    client,
                    tls_underlay,
                })
            }
            TrojanUdpCarrierKind::WebSocket => {
                let options = HttpUpgradeOptions::new(&proxy.stream_host, &proxy.stream_path);
                websocket_handshake_over_resident_tls_async(&mut client, &options).await?;
                write_websocket_packet(
                    &mut client,
                    initial_packet,
                    "write Trojan WebSocket UDP first packet",
                )
                .await?;
                Ok(Self::WebSocket {
                    client,
                    state: AsyncWebSocketPayloadState::default(),
                    tls_underlay,
                })
            }
            TrojanUdpCarrierKind::HttpUpgrade => {
                let options = HttpUpgradeOptions::new(&proxy.stream_host, &proxy.stream_path);
                httpupgrade_handshake_over_resident_tls_async(&mut client, &options).await?;
                write_async_tls_plain_all(
                    &mut client,
                    initial_packet,
                    "write Trojan HTTPUpgrade UDP first packet",
                )
                .await?;
                Ok(Self::HttpUpgrade {
                    client,
                    tls_underlay,
                })
            }
            TrojanUdpCarrierKind::Grpc => {
                let (send_stream, response, connection_task) =
                    open_grpc_h2_stream(client, proxy, initial_packet).await?;
                Ok(Self::Grpc {
                    send_stream,
                    response,
                    response_buf: GrpcHunkReadBuffer::default(),
                    connection_task,
                    tls_underlay,
                })
            }
        }
    }

    pub(super) async fn write_packet(&mut self, payload: &[u8]) -> Result<(), String> {
        match self {
            Self::Tls { client, .. } => {
                write_async_tls_plain_all(client, payload, "write Trojan UDP session packet").await
            }
            Self::WebSocket { client, .. } => {
                write_websocket_packet(client, payload, "write Trojan WebSocket UDP packet").await
            }
            Self::HttpUpgrade { client, .. } => {
                write_async_tls_plain_all(client, payload, "write Trojan HTTPUpgrade UDP packet")
                    .await
            }
            Self::Grpc { send_stream, .. } => send_grpc_hunk(send_stream, payload, false).await,
        }
    }

    pub(super) async fn read_chunk(
        &mut self,
        mode: UdpStreamReadMode,
    ) -> Result<Option<Vec<u8>>, String> {
        match self {
            Self::Grpc { .. } => self.read_grpc_chunk(mode).await,
            _ => self.read_stream_chunk(mode).await,
        }
    }

    async fn read_stream_chunk(
        &mut self,
        mode: UdpStreamReadMode,
    ) -> Result<Option<Vec<u8>>, String> {
        let mut out = [0_u8; 8192];
        let read = match self {
            Self::Tls { client, .. } | Self::HttpUpgrade { client, .. } => {
                read_udp_stream_once(client, &mut out, mode, "read Trojan UDP session plaintext")
                    .await?
            }
            Self::WebSocket { client, state, .. } => {
                let mut reader = AsyncWebSocketPayloadReader::new(client, state);
                read_udp_stream_once(
                    &mut reader,
                    &mut out,
                    mode,
                    "read Trojan WebSocket UDP session payload",
                )
                .await?
            }
            Self::Grpc { .. } => {
                return Err("Trojan gRPC UDP uses the hunk response reader".to_owned());
            }
        };
        Ok(read.map(|read| out[..read].to_vec()))
    }

    async fn read_grpc_chunk(
        &mut self,
        mode: UdpStreamReadMode,
    ) -> Result<Option<Vec<u8>>, String> {
        let Self::Grpc {
            response,
            response_buf,
            ..
        } = self
        else {
            return Err("Trojan gRPC reader received a non-gRPC carrier".to_owned());
        };
        loop {
            if let Some(payload) = response_buf.pop_payload()?
                && !payload.is_empty()
            {
                return Ok(Some(payload));
            }
            let data = if mode.waits_for_readiness() {
                Some(response.next_data().await)
            } else {
                poll_future_once(response.next_data()).await
            };
            match data {
                Some(Ok(Some(bytes))) => response_buf.extend_from_slice(&bytes),
                Some(Err(err)) => return Err(err),
                Some(Ok(None)) => return Err("Trojan gRPC response stream closed".to_owned()),
                None => return Ok(None),
            }
        }
    }

    pub(super) fn evidence_fields(&self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Tls { tls_underlay, .. } => {
                ("tokio-stream-session", "tls-stream-reused", *tls_underlay)
            }
            Self::WebSocket { tls_underlay, .. } => (
                "tokio-wrapper-stream-session",
                "tls-websocket-tunnel-reused",
                *tls_underlay,
            ),
            Self::HttpUpgrade { tls_underlay, .. } => (
                "tokio-wrapper-stream-session",
                "tls-httpupgrade-tunnel-reused",
                *tls_underlay,
            ),
            Self::Grpc { tls_underlay, .. } => (
                "tokio-h2-wrapper-stream-session",
                "tls-grpc-h2-stream-reused",
                *tls_underlay,
            ),
        }
    }

    pub(super) async fn shutdown(&mut self) {
        match self {
            Self::Tls { client, .. }
            | Self::WebSocket { client, .. }
            | Self::HttpUpgrade { client, .. } => client.shutdown().await,
            Self::Grpc {
                send_stream,
                connection_task,
                ..
            } => {
                let _ = send_grpc_hunk(send_stream, &[], true).await;
                connection_task.abort();
            }
        }
    }
}

async fn write_websocket_packet(
    client: &mut AsyncResidentTlsClient,
    payload: &[u8],
    label: &str,
) -> Result<(), String> {
    time::timeout(
        RESIDENT_UDP_RESPONSE_TIMEOUT,
        write_websocket_binary_frame_over_resident_tls_async(client, payload, label),
    )
    .await
    .map_err(|_| format!("{label} timeout"))?
}
