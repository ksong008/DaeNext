use super::*;
use dae_resident_core::ResidentStopSignal;
use std::sync::atomic::Ordering;

/// Keeps a generation's DNS resources available to their actual consumers,
/// independently of the generation's UDP/workload retirement policy.
#[derive(Clone)]
pub struct ResidentDnsResourceLease {
    _inner: Arc<ResourceLifetime>,
}

struct ResourceLifetime {
    released: SharedResidentStopSignal,
}

impl Drop for ResourceLifetime {
    fn drop(&mut self) {
        self.released.store(true, Ordering::Release);
    }
}

impl ResidentDnsPlan {
    /// The caller must register and join the returned owner future. It owns the
    /// refresh loop directly and performs terminal pool shutdown only after all
    /// consumer leases end, or on explicit physical-runtime shutdown.
    pub fn resource_owner(
        self: &Arc<Self>,
        physical_stop: SharedResidentStopSignal,
    ) -> Result<
        (
            ResidentDnsResourceLease,
            impl std::future::Future<Output = Value> + Send + 'static,
        ),
        String,
    > {
        let released = ResidentStopSignal::shared();
        let child_stop = ResidentStopSignal::shared();
        let refresh = self.take_target_refresh_owner_task(Arc::clone(&child_stop))?;
        let lease = ResidentDnsResourceLease {
            _inner: Arc::new(ResourceLifetime {
                released: Arc::clone(&released),
            }),
        };
        let plan = Arc::clone(self);
        Ok((lease, async move {
            let mut physical = physical_stop.listener();
            let mut last_user = released.listener();
            let cleanup = async {
                tokio::select! {
                    _ = physical.cancelled() => {},
                    _ = last_user.cancelled() => {},
                }
                child_stop.store(true, Ordering::Release);
                plan.shutdown_forwarders(
                    time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE,
                )
                .await
            };
            let (report, ()) = tokio::join!(cleanup, async {
                if let Some(refresh) = refresh {
                    refresh.await;
                }
            });
            report
        }))
    }
}

#[cfg(all(test, feature = "dns-runtime-tests"))]
#[path = "resource_lifetime_tests.rs"]
mod tests;
