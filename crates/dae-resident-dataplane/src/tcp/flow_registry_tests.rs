use super::super::admission::ResidentTcpAdmission;
use super::*;

#[tokio::test]
async fn tcp_flow_handoff_keeps_stop_and_budget_until_actual_owner_finishes() {
    let registry = ResidentTcpFlowRegistry::default();
    let admission = ResidentTcpAdmission::new(1, Arc::new(ResidentDataplaneMetrics::default()));
    let lease = registry
        .register(
            1,
            "tcp",
            Some(admission.admitted(admission.acquire().await.unwrap())),
        )
        .unwrap();
    let true_owner = lease.clone();
    let stop = lease.stop_handle();
    drop(lease);
    assert_eq!(registry.snapshot()["active"], 1);
    assert_eq!(admission.snapshot()["used"], 1);
    assert!(!stop.load(Ordering::Acquire));
    registry.stop_all();
    assert!(stop.load(Ordering::Acquire));
    assert!(registry.register(2, "tcp", None).is_err());
    drop(true_owner);
    assert_eq!(registry.snapshot()["active"], 0);
    assert_eq!(registry.snapshot()["releasedTotal"], 1);
    assert_eq!(admission.snapshot()["used"], 0);
}

#[tokio::test]
async fn panic_and_abort_release_tcp_registry_and_budget_exactly_once() {
    for panic in [false, true] {
        let registry = ResidentTcpFlowRegistry::default();
        let admission = ResidentTcpAdmission::new(1, Arc::new(ResidentDataplaneMetrics::default()));
        let lease = registry
            .register(
                1,
                "tcp",
                Some(admission.admitted(admission.acquire().await.unwrap())),
            )
            .unwrap();
        let (started, ready) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _lease = lease;
            started.send(()).unwrap();
            if panic {
                panic!("owner panic");
            }
            std::future::pending::<()>().await;
        });
        ready.await.unwrap();
        if !panic {
            task.abort();
        }
        assert!(task.await.is_err());
        assert_eq!(registry.snapshot()["active"], 0);
        assert_eq!(registry.snapshot()["releasedTotal"], 1);
        assert_eq!(admission.snapshot()["used"], 0);
        drop(admission.acquire().await.unwrap());
    }
}
