use super::*;
use dae_resident_transport::{
    ProxyDnsRequestContext, ProxyDnsRequestFailure, ProxyDnsRequestStage,
};
use std::sync::atomic::{AtomicBool, Ordering};

struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl ResidentDnsDomainRouting {
    pub(crate) async fn record_accepted_response_async(
        self: &Arc<Self>,
        cache_plan: DnsResponseCachePlan,
        context: ProxyDnsRequestContext,
        publish_response: impl FnOnce() -> Result<(), String> + Send + 'static,
    ) -> Result<(), String> {
        // Register before admission so Reject/newer responses can invalidate
        // an older response even while its transaction is queued.
        let revision = self.response_revisions.begin(&cache_plan.key)?;
        self.dispatch_mutation(context, move |routing, mutation| {
            let plan = routing.prepare_response(&cache_plan)?;
            if routing.commit_response_locked(plan, &revision, publish_response, mutation)? {
                routing.maintenance.notify_deadline_changed();
            }
            Ok(())
        })
        .await
    }

    pub(crate) async fn remove_key_async(
        self: &Arc<Self>,
        key: DnsCacheKey,
        context: ProxyDnsRequestContext,
        remove_response: impl FnOnce() -> Result<(), String> + Send + 'static,
    ) -> Result<(), String> {
        self.dispatch_mutation(context, move |routing, mutation| {
            routing.remove_key_locked(&key, remove_response, mutation)
        })
        .await
    }

    async fn dispatch_mutation(
        self: &Arc<Self>,
        context: ProxyDnsRequestContext,
        operation: impl FnOnce(&Self, &std::sync::MutexGuard<'_, ()>) -> Result<(), String>
        + Send
        + 'static,
    ) -> Result<(), String> {
        let admission = context
            .run(
                ProxyDnsRequestStage::Queued,
                ProxyDnsRequestFailure::Cancelled,
                async {
                    Ok::<_, std::convert::Infallible>(Arc::clone(&self.dispatch).lock_owned().await)
                },
            )
            .await
            .map_err(|error| error.to_string())?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let _cancel_on_drop = CancelOnDrop(Arc::clone(&cancelled));
        let routing = Arc::clone(self);
        // Admission remains owned by the blocking job even when its caller
        // times out. No second blocking job can accumulate behind this one.
        let task = tokio::task::spawn_blocking(move || {
            let _admission = admission;
            let mutation = routing.lock_mutation()?;
            if cancelled.load(Ordering::Acquire) {
                return Err(
                    "resident DNS domain routing transaction cancelled before commit".into(),
                );
            }
            context
                .ensure(ProxyDnsRequestStage::Cleanup)
                .map_err(|error| error.to_string())?;
            // Once BPF starts, finish the transaction, including rollback and
            // cache publication. Cancellation must not split those effects.
            operation(&routing, &mutation)
        });
        context
            .run(
                ProxyDnsRequestStage::Cleanup,
                ProxyDnsRequestFailure::Cancelled,
                async {
                    task.await.map_err(|error| {
                        format!("join resident DNS domain routing transaction: {error}")
                    })?
                },
            )
            .await
            .map_err(|error| error.to_string())
    }
}
