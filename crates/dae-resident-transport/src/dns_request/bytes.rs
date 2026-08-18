use std::sync::Arc;

use super::{ProxyDnsRequestContext, ProxyDnsRequestStage};
use dae_resident_core::{ResidentDataplaneMetrics, ResidentUdpPayloadPermit};

pub struct ProxyDnsQueuedRequestBytes {
    permit: Option<ResidentUdpPayloadPermit>,
    metrics: Arc<ResidentDataplaneMetrics>,
    bytes: usize,
    context: ProxyDnsRequestContext,
    drop_reason: ProxyDnsQueuedDropReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProxyDnsQueuedDropReason {
    Abandoned,
    Expired,
    Rejected,
}

impl ProxyDnsQueuedRequestBytes {
    pub fn new(
        permit: ResidentUdpPayloadPermit,
        metrics: Arc<ResidentDataplaneMetrics>,
        bytes: usize,
        context: ProxyDnsRequestContext,
    ) -> Self {
        metrics.proxy_dns_udp_queued_added(bytes);
        Self {
            permit: Some(permit),
            metrics,
            bytes,
            context,
            drop_reason: ProxyDnsQueuedDropReason::Abandoned,
        }
    }

    pub fn mark_expired(&mut self) {
        self.drop_reason = ProxyDnsQueuedDropReason::Expired;
    }

    pub fn mark_rejected(&mut self) {
        self.drop_reason = ProxyDnsQueuedDropReason::Rejected;
    }

    pub fn into_pending(
        mut self,
        metadata_permit: ResidentUdpPayloadPermit,
        metadata_bytes: usize,
    ) -> ProxyDnsPendingRequestBytes {
        self.drop_reason = ProxyDnsQueuedDropReason::Rejected;
        self.metrics.proxy_dns_udp_queued_removed(self.bytes);
        let permit = self
            .permit
            .take()
            .expect("queued proxy DNS byte owner must hold its admission permit");
        self.metrics.proxy_dns_udp_pending_added(self.bytes);
        self.metrics
            .proxy_dns_udp_pending_metadata_added(metadata_bytes);
        ProxyDnsPendingRequestBytes {
            _permit: permit,
            _metadata_permit: metadata_permit,
            metrics: Arc::clone(&self.metrics),
            bytes: self.bytes,
            metadata_bytes,
            drop_reason: ProxyDnsPendingDropReason::Rejected,
        }
    }
}

impl Drop for ProxyDnsQueuedRequestBytes {
    fn drop(&mut self) {
        if self.permit.is_none() {
            return;
        }
        self.metrics.proxy_dns_udp_queued_removed(self.bytes);
        let drop_reason = if self.drop_reason == ProxyDnsQueuedDropReason::Abandoned
            && self.context.ensure(ProxyDnsRequestStage::Cleanup).is_err()
        {
            ProxyDnsQueuedDropReason::Expired
        } else {
            self.drop_reason
        };
        match drop_reason {
            ProxyDnsQueuedDropReason::Abandoned => {
                self.metrics.proxy_dns_udp_abandoned(self.bytes);
            }
            ProxyDnsQueuedDropReason::Expired => {
                self.metrics.proxy_dns_udp_expired(self.bytes);
            }
            ProxyDnsQueuedDropReason::Rejected => {}
        }
    }
}

pub struct ProxyDnsPendingRequestBytes {
    _permit: ResidentUdpPayloadPermit,
    _metadata_permit: ResidentUdpPayloadPermit,
    metrics: Arc<ResidentDataplaneMetrics>,
    bytes: usize,
    metadata_bytes: usize,
    drop_reason: ProxyDnsPendingDropReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProxyDnsPendingDropReason {
    Rejected,
    Abandoned,
    Expired,
}

impl ProxyDnsPendingRequestBytes {
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn mark_abandoned(&mut self) {
        self.drop_reason = ProxyDnsPendingDropReason::Abandoned;
    }

    pub fn mark_expired(&mut self) {
        self.drop_reason = ProxyDnsPendingDropReason::Expired;
    }
}

impl Drop for ProxyDnsPendingRequestBytes {
    fn drop(&mut self) {
        self.metrics.proxy_dns_udp_pending_removed(self.bytes);
        self.metrics
            .proxy_dns_udp_pending_metadata_removed(self.metadata_bytes);
        match self.drop_reason {
            ProxyDnsPendingDropReason::Rejected => {}
            ProxyDnsPendingDropReason::Abandoned => {
                self.metrics.proxy_dns_udp_abandoned(self.bytes);
            }
            ProxyDnsPendingDropReason::Expired => {
                self.metrics.proxy_dns_udp_expired(self.bytes);
            }
        }
    }
}

pub struct ProxyDnsResponseBytes {
    payload: Option<Vec<u8>>,
    _permit: ResidentUdpPayloadPermit,
    metrics: Arc<ResidentDataplaneMetrics>,
    bytes: usize,
}

impl ProxyDnsResponseBytes {
    pub fn new(
        payload: Vec<u8>,
        permit: ResidentUdpPayloadPermit,
        metrics: Arc<ResidentDataplaneMetrics>,
    ) -> Self {
        let bytes = payload.len();
        metrics.proxy_dns_udp_response_added(bytes);
        Self {
            payload: Some(payload),
            _permit: permit,
            metrics,
            bytes,
        }
    }

    pub fn into_payload(mut self) -> Vec<u8> {
        self.payload
            .take()
            .expect("proxy DNS response byte owner must hold its payload")
    }
}

impl Drop for ProxyDnsResponseBytes {
    fn drop(&mut self) {
        self.metrics.proxy_dns_udp_response_removed(self.bytes);
    }
}
