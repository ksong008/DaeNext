use std::sync::Arc;

use super::*;
use crate::ResidentDataplaneMetrics;
use crate::ResidentUdpPayloadAdmission;

#[tokio::test]
async fn request_context_keeps_one_absolute_deadline_across_stages() {
    let context = ProxyDnsRequestContext::from_timeout(std::time::Duration::from_millis(20));
    context
        .run(
            ProxyDnsRequestStage::OwnerAcquire,
            ProxyDnsRequestFailure::Network,
            async {
                time::sleep(std::time::Duration::from_millis(10)).await;
                Ok::<_, String>(())
            },
        )
        .await
        .unwrap();
    let error = context
        .run(
            ProxyDnsRequestStage::Retry,
            ProxyDnsRequestFailure::Network,
            async {
                time::sleep(std::time::Duration::from_millis(30)).await;
                Ok::<_, String>(())
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error.failure(), ProxyDnsRequestFailure::Deadline);
    assert_eq!(error.stage(), ProxyDnsRequestStage::Retry);
}

#[tokio::test]
async fn elapsed_direct_phase_does_not_restart_deadline_before_proxy_reroute() {
    let context = ProxyDnsRequestContext::from_timeout(std::time::Duration::from_millis(20));
    time::sleep(std::time::Duration::from_millis(25)).await;

    let error = context.ensure(ProxyDnsRequestStage::Retry).unwrap_err();
    assert_eq!(error.failure(), ProxyDnsRequestFailure::Deadline);
    assert_eq!(error.stage(), ProxyDnsRequestStage::Retry);
}

#[test]
fn queued_bytes_transition_to_pending_and_release_exactly_once() {
    let admission = ResidentUdpPayloadAdmission::new(9, 4096);
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let queued = ProxyDnsQueuedRequestBytes::new(
        admission.try_acquire(1500).unwrap(),
        Arc::clone(&metrics),
        1500,
        ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(1)),
    );
    assert_eq!(metrics.snapshot()["proxyDnsUdpQueuedCurrent"], 1);
    assert_eq!(metrics.snapshot()["proxyDnsUdpQueuedBytesCurrent"], 1500);
    let pending = queued.into_pending(admission.try_acquire(128).unwrap(), 128);
    assert_eq!(pending.bytes(), 1500);
    assert_eq!(metrics.snapshot()["proxyDnsUdpQueuedCurrent"], 0);
    assert_eq!(metrics.snapshot()["proxyDnsUdpPendingCurrent"], 1);
    assert_eq!(metrics.snapshot()["proxyDnsUdpPendingBytesCurrent"], 1500);
    assert_eq!(
        metrics.snapshot()["proxyDnsUdpPendingMetadataBytesCurrent"],
        128
    );
    assert_eq!(admission.current(), 1628);
    drop(pending);
    assert_eq!(metrics.snapshot()["proxyDnsUdpPendingCurrent"], 0);
    assert_eq!(metrics.snapshot()["proxyDnsUdpPendingBytesCurrent"], 0);
    assert_eq!(
        metrics.snapshot()["proxyDnsUdpPendingMetadataBytesCurrent"],
        0
    );
    assert_eq!(admission.current(), 0);
}

#[test]
fn queued_drop_classifies_abandoned_expired_and_rejected_bytes() {
    let admission = ResidentUdpPayloadAdmission::new(10, 4096);
    let metrics = Arc::new(ResidentDataplaneMetrics::default());

    drop(ProxyDnsQueuedRequestBytes::new(
        admission.try_acquire(700).unwrap(),
        Arc::clone(&metrics),
        700,
        ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(1)),
    ));
    let mut expired = ProxyDnsQueuedRequestBytes::new(
        admission.try_acquire(800).unwrap(),
        Arc::clone(&metrics),
        800,
        ProxyDnsRequestContext::from_deadline(time::Instant::now()),
    );
    expired.mark_expired();
    drop(expired);
    let mut rejected = ProxyDnsQueuedRequestBytes::new(
        admission.try_acquire(900).unwrap(),
        Arc::clone(&metrics),
        900,
        ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(1)),
    );
    rejected.mark_rejected();
    drop(rejected);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot["proxyDnsUdpQueuedCurrent"], 0);
    assert_eq!(snapshot["proxyDnsUdpQueuedBytesCurrent"], 0);
    assert_eq!(snapshot["proxyDnsUdpAbandoned"], 1);
    assert_eq!(snapshot["proxyDnsUdpAbandonedBytes"], 700);
    assert_eq!(snapshot["proxyDnsUdpExpired"], 1);
    assert_eq!(snapshot["proxyDnsUdpExpiredBytes"], 800);
    assert_eq!(admission.current(), 0);
}

#[test]
fn pending_drop_classifies_abandoned_and_expired_bytes() {
    let admission = ResidentUdpPayloadAdmission::new(11, 4096);
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let context = ProxyDnsRequestContext::from_timeout(std::time::Duration::from_secs(1));

    let mut abandoned = ProxyDnsQueuedRequestBytes::new(
        admission.try_acquire(1500).unwrap(),
        Arc::clone(&metrics),
        1500,
        context,
    )
    .into_pending(admission.try_acquire(64).unwrap(), 64);
    abandoned.mark_abandoned();
    drop(abandoned);
    let mut expired = ProxyDnsQueuedRequestBytes::new(
        admission.try_acquire(1600).unwrap(),
        Arc::clone(&metrics),
        1600,
        context,
    )
    .into_pending(admission.try_acquire(64).unwrap(), 64);
    expired.mark_expired();
    drop(expired);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot["proxyDnsUdpPendingCurrent"], 0);
    assert_eq!(snapshot["proxyDnsUdpPendingBytesCurrent"], 0);
    assert_eq!(snapshot["proxyDnsUdpPendingMetadataBytesCurrent"], 0);
    assert_eq!(snapshot["proxyDnsUdpAbandoned"], 1);
    assert_eq!(snapshot["proxyDnsUdpAbandonedBytes"], 1500);
    assert_eq!(snapshot["proxyDnsUdpExpired"], 1);
    assert_eq!(snapshot["proxyDnsUdpExpiredBytes"], 1600);
    assert_eq!(admission.current(), 0);
}
