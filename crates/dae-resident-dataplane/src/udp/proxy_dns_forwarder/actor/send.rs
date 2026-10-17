use super::*;
use dae_resident_core::ResidentUdpPayloadPermit;
use dae_resident_udp::{ProxyDnsUdpSend, ProxyDnsUdpSendCompletion};
use std::{future::Future, pin::Pin};

type ExchangeResult = Result<(ResidentEventKind, UdpExchangeResult), String>;
type OpenResult = (Box<UdpSessionExecutor>, ExchangeResult);
type OpenFuture = Pin<Box<dyn Future<Output = ExchangeResult> + Send>>;

pub(super) enum ProxyDnsSendOperation {
    Packet(ProxyDnsUdpSend),
    Opening {
        future: OpenFuture,
        executor: Arc<tokio::sync::Mutex<Option<Box<UdpSessionExecutor>>>>,
    },
}

pub(super) struct ActiveProxyDnsSend {
    pub(super) id: u16,
    pub(super) generation: u64,
    pub(super) deadline: time::Instant,
    pub(super) stage: ProxyDnsRequestStage,
    pub(super) response_delivered: bool,
    pub(super) permit: Option<ResidentUdpPayloadPermit>,
    pub(super) operation: ProxyDnsSendOperation,
}

impl ActiveProxyDnsSend {
    pub(super) fn reset_on_cancel(&self) -> bool {
        match &self.operation {
            ProxyDnsSendOperation::Packet(send) => send.reset_on_cancel,
            ProxyDnsSendOperation::Opening { .. } => true,
        }
    }

    pub(super) async fn cancel(self, selected: &mut Option<Box<UdpSessionExecutor>>) {
        if let ProxyDnsSendOperation::Opening { future, executor } = self.operation {
            // Drop the borrowing future before recovering the executor. A
            // partially opened carrier still receives normal shutdown cleanup.
            drop(future);
            *selected = executor.lock().await.take();
        }
    }
}

pub(super) enum ProxyDnsSendCompletion {
    Packet(ProxyDnsUdpSendCompletion),
    Opened(OpenResult),
}

pub(super) async fn wait_proxy_dns_send(
    active: &mut Option<ActiveProxyDnsSend>,
) -> ProxyDnsSendCompletion {
    let Some(active) = active.as_mut() else {
        return std::future::pending().await;
    };
    match &mut active.operation {
        ProxyDnsSendOperation::Packet(send) => {
            ProxyDnsSendCompletion::Packet((&mut send.future).await)
        }
        ProxyDnsSendOperation::Opening { future, executor } => {
            let result = future.await;
            let selected = executor
                .lock()
                .await
                .take()
                .expect("opening executor retained until completion");
            ProxyDnsSendCompletion::Opened((selected, result))
        }
    }
}

pub(super) fn mark_send_response_delivered(
    active: &mut Option<ActiveProxyDnsSend>,
    pending: &HashMap<u16, PendingProxyDnsUdpRequest>,
) {
    if let Some(active) = active
        && !pending.contains_key(&active.id)
    {
        active.response_delivered = true;
    }
}
