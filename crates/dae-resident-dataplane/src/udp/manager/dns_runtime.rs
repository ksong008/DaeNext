use super::*;

pub(super) struct ResidentUdpDnsRuntime {
    plan: ResidentDnsDispatcher,
    dispatcher: ResidentDnsFastPathDispatcher,
    pub(super) handle: ResidentDnsFastPathHandle,
}

impl ResidentUdpDnsRuntime {
    pub(super) fn start(
        plan: ResidentDnsDispatcher,
        udp_reply: UdpReplyHandle,
        metrics: Arc<ResidentDataplaneMetrics>,
        concurrency: usize,
        queue_depth: usize,
    ) -> Self {
        let dispatcher = ResidentDnsFastPathDispatcher::start(
            plan.clone(),
            udp_reply,
            metrics,
            concurrency,
            queue_depth,
        );
        let handle = dispatcher.handle();
        Self {
            plan,
            dispatcher,
            handle,
        }
    }

    pub(super) async fn shutdown(self, deadline: time::Instant) -> Value {
        let Self {
            plan,
            dispatcher,
            handle,
        } = self;
        drop(handle);
        let (fast_path, forwarders) = tokio::join!(
            dispatcher.shutdown(deadline),
            plan.shutdown_forwarders(deadline),
        );
        let cleanup_passed =
            cleanup_report_passed(&fast_path) && cleanup_report_passed(&forwarders);
        let (graceful, completion_mode) =
            udp_cleanup_completion(cleanup_passed, [&fast_path, &forwarders]);
        json!({
            "status": if cleanup_passed { "pass" } else { "fail" },
            "safetyStatus": if cleanup_passed { "pass" } else { "fail" },
            "graceful": graceful,
            "completionMode": completion_mode,
            "dnsFastPathDispatcher": fast_path,
            "dnsForwarders": forwarders,
        })
    }
}
