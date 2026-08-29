use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::{HttpRequest, ProductHttpMetrics};

use super::{ProductUiRequestLease, ProductUiRuntime, optional_page_id_from_request};

pub(super) const PRODUCT_UI_HEADERLESS_RECLAIM_QUIET: Duration = Duration::from_millis(250);
const PRODUCT_UI_HEADERLESS_RECLAIM_COOLDOWN: Duration = super::PRODUCT_UI_SESSION_LEASE;

#[derive(Debug, Default)]
pub(super) struct ProductUiHeaderlessReclaimActivity {
    pub(super) idle_since: Option<Instant>,
    last_reclaim: Option<Instant>,
}

impl ProductUiRuntime {
    pub fn request_lease(self: &Arc<Self>, request: &HttpRequest) -> Option<ProductUiRequestLease> {
        let page_id = optional_page_id_from_request(request).ok().flatten();
        let headerless = page_id.is_none();
        let charged_bytes = request
            .body
            .len()
            .saturating_add(page_id.map(str::len).unwrap_or_default())
            .try_into()
            .unwrap_or(u64::MAX);
        self.requests_active.fetch_add(1, Ordering::Relaxed);
        self.bytes_in_flight
            .fetch_add(charged_bytes, Ordering::Relaxed);
        if headerless {
            self.headerless_requests_active
                .fetch_add(1, Ordering::Relaxed);
            if let Ok(mut activity) = self.headerless_reclaim_activity.lock() {
                activity.idle_since = None;
            }
        }
        Some(ProductUiRequestLease {
            runtime: Arc::clone(self),
            charged_bytes,
            headerless,
        })
    }

    pub(super) fn request_reclaim_if_headerless_idle(&self, metrics: &ProductHttpMetrics) {
        let drain_epoch = self.headerless_drain_epoch.load(Ordering::Acquire);
        if drain_epoch == 0
            || self.reclaim_headerless_drain_epoch.load(Ordering::Acquire) >= drain_epoch
            || !self.owner_drained(metrics)
        {
            return;
        }
        let now = Instant::now();
        let ready = self
            .headerless_reclaim_activity
            .lock()
            .ok()
            .is_some_and(|activity| {
                activity.idle_since.is_some_and(|idle_since| {
                    now.saturating_duration_since(idle_since) >= PRODUCT_UI_HEADERLESS_RECLAIM_QUIET
                }) && activity.last_reclaim.is_none_or(|last_reclaim| {
                    now.saturating_duration_since(last_reclaim)
                        >= PRODUCT_UI_HEADERLESS_RECLAIM_COOLDOWN
                })
            });
        if !ready {
            return;
        }
        let recorded_epoch = self.reclaim_headerless_drain_epoch.load(Ordering::Acquire);
        if recorded_epoch >= drain_epoch
            || self
                .reclaim_headerless_drain_epoch
                .compare_exchange(
                    recorded_epoch,
                    drain_epoch,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            return;
        }
        if self.owner_drained(metrics) && self.reclaim.request() {
            if let Ok(mut activity) = self.headerless_reclaim_activity.lock() {
                activity.last_reclaim = Some(now);
            }
        } else {
            let _ = self.reclaim_headerless_drain_epoch.compare_exchange(
                drain_epoch,
                recorded_epoch,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }
}
