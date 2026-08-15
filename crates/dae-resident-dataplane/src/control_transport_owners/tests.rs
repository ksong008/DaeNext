use super::*;

fn test_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn empty_requirements_start_no_owner_tasks() {
    let runtime = test_runtime();
    runtime.block_on(async {
        let mut owners = ControlTransportOwners::start(
            runtime.handle(),
            91_001,
            2,
            ControlTransportOwnerRequirements::default(),
        )
        .await
        .unwrap();
        assert_eq!(owners.task_count(), 0);
        assert!(owners.registries().hysteria2().is_none());
        assert!(owners.shutdown().await.is_clean());
    });
}

#[test]
fn requested_registry_runs_on_supplied_runtime_and_joins() {
    let runtime = test_runtime();
    runtime.block_on(async {
        let mut owners = ControlTransportOwners::start(
            runtime.handle(),
            91_002,
            2,
            ControlTransportOwnerRequirements::with_hysteria2(),
        )
        .await
        .unwrap();
        assert_eq!(owners.task_count(), 1);
        assert!(owners.registries().hysteria2().is_some());
        assert_eq!(
            owners.shutdown().await,
            ControlTransportOwnerShutdown {
                joined: 1,
                ..ControlTransportOwnerShutdown::default()
            }
        );
    });
}

#[test]
fn generation_zero_registered_carriers_are_exclusive() {
    let runtime = test_runtime();
    runtime.block_on(async {
        let mut first = ControlTransportOwners::start(
            runtime.handle(),
            0,
            2,
            ControlTransportOwnerRequirements::with_h2_carrier(),
        )
        .await
        .unwrap();
        let handle = runtime.handle().clone();
        let second = tokio::spawn(async move {
            ControlTransportOwners::start(
                &handle,
                0,
                2,
                ControlTransportOwnerRequirements::with_h2_carrier(),
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!second.is_finished());
        assert!(first.shutdown().await.is_clean());
        let mut second = tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(second.shutdown().await.is_clean());
    });
}
