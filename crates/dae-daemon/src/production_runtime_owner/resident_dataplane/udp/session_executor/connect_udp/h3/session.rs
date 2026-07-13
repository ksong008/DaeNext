use tokio::sync::mpsc::error::TryRecvError;

use super::actor::ConnectUdpH3ActorCommand;
use super::pool::ConnectUdpH3ActorLease;
use super::*;

mod open;

use self::open::open_connect_udp_h3_binding;

pub(in crate::production_runtime_owner::resident_dataplane::udp) struct ConnectUdpH3Session {
    runtime: ResidentConnectUdpRuntimePlan,
    target: Option<SocketAddr>,
    binding: Option<ConnectUdpH3SessionBinding>,
}

struct ConnectUdpH3SessionBinding {
    quarter_stream_id: MasqueQuarterStreamId,
    responses: tokio::sync::mpsc::Receiver<Result<Bytes, String>>,
    actor: ConnectUdpH3ActorLease,
    closed: bool,
}

impl ConnectUdpH3Session {
    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn new(
        runtime: ResidentConnectUdpRuntimePlan,
    ) -> Self {
        Self {
            runtime,
            target: None,
            binding: None,
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        if self.binding.is_none() {
            self.open(proxy, original_dst).await?;
        }
        if self.target != Some(original_dst) {
            return Err(format!(
                "CONNECT-UDP H3 session target changed from {:?} to {}; cross-target tunnel reuse is forbidden",
                self.target, original_dst,
            ));
        }
        let binding = self
            .binding
            .as_mut()
            .ok_or_else(|| "CONNECT-UDP H3 session is not initialized".to_owned())?;
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        time::timeout(
            RESIDENT_CONNECT_TIMEOUT,
            binding
                .actor
                .sender
                .send(ConnectUdpH3ActorCommand::SendDatagram {
                    quarter_stream_id: binding.quarter_stream_id,
                    payload: Bytes::copy_from_slice(payload),
                    response: response_tx,
                }),
        )
        .await
        .map_err(|_| "CONNECT-UDP H3 actor command queue timeout".to_owned())?
        .map_err(|_| "CONNECT-UDP H3 actor is closed".to_owned())?;
        time::timeout(RESIDENT_CONNECT_TIMEOUT, response_rx)
            .await
            .map_err(|_| "CONNECT-UDP H3 datagram send completion timeout".to_owned())?
            .map_err(|_| "CONNECT-UDP H3 actor dropped datagram completion".to_owned())??;
        if let Some(response) = self.poll_response().await? {
            Ok(response)
        } else {
            Ok(self.pending_response_result())
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) async fn poll_response(
        &mut self,
    ) -> Result<Option<UdpExchangeResult>, String> {
        let Some(binding) = self.binding.as_mut() else {
            return Ok(None);
        };
        match binding.responses.try_recv() {
            Ok(Ok(payload)) => Ok(Some(self.response_result(payload))),
            Ok(Err(err)) => Err(err),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => {
                Err("CONNECT-UDP H3 actor closed the session response queue".to_owned())
            }
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) async fn wait_response(
        &mut self,
    ) -> Result<Option<UdpExchangeResult>, String> {
        let Some(binding) = self.binding.as_mut() else {
            return std::future::pending().await;
        };
        match binding.responses.recv().await {
            Some(Ok(payload)) => Ok(Some(self.response_result(payload))),
            Some(Err(err)) => Err(err),
            None => Err("CONNECT-UDP H3 actor closed the session response queue".to_owned()),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) async fn shutdown(&mut self) {
        if let Some(mut binding) = self.binding.take() {
            binding.close().await;
        }
        self.target = None;
    }

    async fn open(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
    ) -> Result<(), String> {
        let proxy_runtime = connect_udp_h3_plan(proxy)?.runtime;
        if proxy_runtime != self.runtime {
            return Err(format!(
                "CONNECT-UDP H3 session runtime {:?} does not match the selected proxy runtime {:?}",
                self.runtime, proxy_runtime,
            ));
        }
        let opened = open_connect_udp_h3_binding(proxy, original_dst, self.runtime).await?;
        self.target = Some(original_dst);
        self.binding = Some(ConnectUdpH3SessionBinding {
            quarter_stream_id: opened.quarter_stream_id,
            responses: opened.responses,
            actor: opened.actor,
            closed: false,
        });
        Ok(())
    }

    fn response_result(&self, payload: Bytes) -> UdpExchangeResult {
        UdpExchangeResult::new(payload.to_vec(), "connect-udp-h3-http-datagram")
            .with_session_executor("http3-extended-connect")
            .with_underlay_reuse("generation-owned-h3-connection-reused")
            .with_quic_underlay("quinn")
    }

    fn pending_response_result(&self) -> UdpExchangeResult {
        UdpExchangeResult::pending_response("connect-udp-h3-http-datagram")
            .with_session_executor("http3-extended-connect")
            .with_underlay_reuse("generation-owned-h3-connection-reused")
            .with_quic_underlay("quinn")
    }
}

impl ConnectUdpH3SessionBinding {
    async fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        let _ = time::timeout(
            RESIDENT_CONNECT_TIMEOUT,
            self.actor
                .sender
                .send(ConnectUdpH3ActorCommand::CloseSession {
                    quarter_stream_id: self.quarter_stream_id,
                }),
        )
        .await;
    }
}

impl Drop for ConnectUdpH3SessionBinding {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self
                .actor
                .sender
                .try_send(ConnectUdpH3ActorCommand::CloseSession {
                    quarter_stream_id: self.quarter_stream_id,
                });
        }
    }
}
