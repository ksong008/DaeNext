use std::sync::Arc;

use super::{ProxyDnsRequestContext, ProxyDnsRequestStage};
use crate::production_runtime_owner::resident_dataplane::ResidentDataplaneMetrics;
use crate::production_runtime_owner::udp_payload_admission::ResidentUdpPayloadPermit;

pub(in crate::production_runtime_owner::resident_dataplane) struct ProxyDnsQueuedRequestBytes {
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
    pub(in crate::production_runtime_owner::resident_dataplane) fn new(
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

    pub(in crate::production_runtime_owner::resident_dataplane) fn mark_expired(&mut self) {
        self.drop_reason = ProxyDnsQueuedDropReason::Expired;
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn mark_rejected(&mut self) {
        self.drop_reason = ProxyDnsQueuedDropReason::Rejected;
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn into_pending(
        mut self,
    ) -> ProxyDnsPendingRequestBytes {
        self.drop_reason = ProxyDnsQueuedDropReason::Rejected;
        self.metrics.proxy_dns_udp_queued_removed(self.bytes);
        let permit = self
            .permit
            .take()
            .expect("queued proxy DNS byte owner must hold its admission permit");
        self.metrics.proxy_dns_udp_pending_added(self.bytes);
        ProxyDnsPendingRequestBytes {
            _permit: permit,
            metrics: Arc::clone(&self.metrics),
            bytes: self.bytes,
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

pub(in crate::production_runtime_owner::resident_dataplane) struct ProxyDnsPendingRequestBytes {
    _permit: ResidentUdpPayloadPermit,
    metrics: Arc<ResidentDataplaneMetrics>,
    bytes: usize,
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
    pub(in crate::production_runtime_owner::resident_dataplane) fn bytes(&self) -> usize {
        self.bytes
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn mark_abandoned(&mut self) {
        self.drop_reason = ProxyDnsPendingDropReason::Abandoned;
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn mark_expired(&mut self) {
        self.drop_reason = ProxyDnsPendingDropReason::Expired;
    }
}

impl Drop for ProxyDnsPendingRequestBytes {
    fn drop(&mut self) {
        self.metrics.proxy_dns_udp_pending_removed(self.bytes);
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
