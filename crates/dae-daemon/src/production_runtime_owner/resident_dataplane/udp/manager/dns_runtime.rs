use super::*;

pub(super) struct ResidentUdpDnsRuntime {
    plan: Arc<ResidentDnsPlan>,
    dispatcher: ResidentDnsFastPathDispatcher,
    pub(super) handle: ResidentDnsFastPathHandle,
}

impl ResidentUdpDnsRuntime {
    pub(super) fn start(
        plan: Arc<ResidentDnsPlan>,
        udp_reply: UdpReplyHandle,
        metrics: Arc<ResidentDataplaneMetrics>,
        concurrency: usize,
        queue_depth: usize,
    ) -> Self {
        let dispatcher = ResidentDnsFastPathDispatcher::start(
            Arc::clone(&plan),
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
        let fast_path = match dispatcher.shutdown(deadline).await {
            Ok(completed) => json!({"status": "pass", "completed": completed}),
            Err(err) => json!({"status": "fail", "error": err}),
        };
        let forwarders = plan.shutdown_forwarders(deadline).await;
        json!({
            "status": if cleanup_report_passed(&fast_path) && cleanup_report_passed(&forwarders) {
                "pass"
            } else {
                "fail"
            },
            "dnsFastPathDispatcher": fast_path,
            "dnsForwarders": forwarders,
        })
    }
}
