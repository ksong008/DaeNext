use super::super::test_support::{download_test_key, download_test_plan};
use super::*;

const XHTTP_XMUX_TEST_OWNER_STACK_BYTES: usize = 1024 * 1024;

fn cancellation_test_key(runtime_generation: u64) -> XhttpXmuxKey {
    XhttpXmuxKey::isolated_test(
        fastrand::u64(..),
        ResidentXhttpHttpVersion::H3,
        cancellation_test_plan(runtime_generation),
    )
}

fn cancellation_test_plan(runtime_generation: u64) -> ResidentXhttpXmuxPlan {
    ResidentXhttpXmuxPlan {
        runtime_generation,
        physical_connection_limit: 1,
        max_concurrency: None,
        max_connections: Some((1, 1)),
        c_max_reuse_times: None,
        h_max_request_times: None,
        h_max_reusable_secs: None,
        h_keep_alive_period: 0,
    }
}

fn start_test_owner(
    generation: u64,
) -> (XhttpXmuxGenerationOwnerHandle, std::thread::JoinHandle<()>) {
    start_xhttp_xmux_generation_owner(generation, XHTTP_XMUX_TEST_OWNER_STACK_BYTES, 1).unwrap()
}

fn stop_test_owner(
    owner: &XhttpXmuxGenerationOwnerHandle,
    thread: std::thread::JoinHandle<()>,
) -> XhttpXmuxClearReport {
    shutdown_xhttp_xmux_generation_owner(owner, thread, Duration::from_secs(1))
}

fn registered_download_manager(
    owner: &XhttpXmuxGenerationOwnerHandle,
    key: XhttpXmuxKey,
    runtime_generation: u64,
) -> XhttpXmuxManagerHandle<XhttpXmuxH3Manager> {
    owner
        .owner
        .h3
        .managers
        .lock()
        .unwrap()
        .entry(key)
        .or_insert_with(|| {
            XhttpXmuxManagerHandle::new(|lifecycle| {
                XhttpXmuxH3Manager::new(download_test_plan(runtime_generation), lifecycle)
            })
        })
        .clone()
}

#[test]
fn h3_download_manager_reuses_equivalent_keys_and_partitions_physical_identity() {
    let generation = fastrand::u64(..);
    let (owner, thread) = start_test_owner(generation);
    let graph = format!("sha256:{}", fastrand::u64(..));
    let equivalent_key = download_test_key(
        generation,
        &graph,
        1,
        "192.0.2.30:443",
        ResidentXhttpHttpVersion::H3,
    );
    let keys = [
        equivalent_key.clone(),
        download_test_key(
            generation,
            &format!("{graph}-other"),
            1,
            "192.0.2.30:443",
            ResidentXhttpHttpVersion::H3,
        ),
        download_test_key(
            generation,
            &graph,
            2,
            "192.0.2.30:443",
            ResidentXhttpHttpVersion::H3,
        ),
        download_test_key(
            generation,
            &graph,
            1,
            "[2001:db8::30]:443",
            ResidentXhttpHttpVersion::H3,
        ),
    ];
    let base = registered_download_manager(&owner, keys[0].clone(), generation);
    let equivalent = registered_download_manager(&owner, equivalent_key, generation);
    assert!(Arc::ptr_eq(&base.manager, &equivalent.manager));
    for key in &keys[1..] {
        let partitioned = registered_download_manager(&owner, key.clone(), generation);
        assert!(!Arc::ptr_eq(&base.manager, &partitioned.manager));
    }

    let report = stop_test_owner(&owner, thread);
    assert_eq!(report.h3.managers, keys.len());
    assert!(report.owner_thread_joined);
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_h3_open_releases_the_reserved_slot() {
    let generation = fastrand::u64(..);
    let (owner, thread) = start_test_owner(generation);
    let key = cancellation_test_key(generation);
    let started = Arc::new(tokio::sync::Notify::new());
    let task = {
        let key = key.clone();
        let started = Arc::clone(&started);
        tokio::spawn(async move {
            select_xhttp_h3_xmux_client(key, cancellation_test_plan(generation), |_| async move {
                started.notify_one();
                std::future::pending::<Result<XhttpH3EndpointClient, String>>().await
            })
            .await
        })
    };
    started.notified().await;

    let manager = owner
        .owner
        .h3
        .managers
        .lock()
        .unwrap()
        .get(&key)
        .unwrap()
        .clone();
    assert_eq!(manager.lifecycle.opening(), 1);

    task.abort();
    let _ = task.await;
    tokio::task::yield_now().await;
    assert_eq!(
        manager.lifecycle.opening(),
        0,
        "aborting an in-flight H3 open must release xmux capacity"
    );

    let report = stop_test_owner(&owner, thread);
    assert_eq!(report.h3.managers, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn locked_h3_manager_is_drained_after_the_holder_releases_it() {
    let manager = XhttpXmuxManagerHandle::new(|lifecycle| {
        XhttpXmuxH3Manager::new(cancellation_test_plan(0), lifecycle)
    });
    let manager_lock = Arc::clone(&manager.manager);
    let mut guard = manager_lock.lock().await;
    let closing = {
        let manager = manager.clone();
        tokio::spawn(async move {
            close_xhttp_h3_manager(
                &manager,
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await
        })
    };
    tokio::task::yield_now().await;

    assert!(manager.lifecycle.is_closing());
    assert!(matches!(
        guard.select_or_reserve_new(),
        XhttpXmuxH3SelectAction::Closed
    ));
    drop(guard);
    assert_eq!(closing.await.unwrap(), (0, false));
}

#[test]
fn h3_cleanup_removes_only_the_requested_runtime_generation() {
    let generation = fastrand::u64(..);
    let other_generation = generation.wrapping_add(1);
    let (owner, thread) = start_test_owner(generation);
    let (other_owner, other_thread) = start_test_owner(other_generation);
    let key = cancellation_test_key(generation);
    let other_key = cancellation_test_key(other_generation);
    registered_download_manager(&owner, key, generation);
    registered_download_manager(&other_owner, other_key.clone(), other_generation);

    let report = stop_test_owner(&owner, thread);
    assert_eq!(report.h3.managers, 1);
    assert!(
        other_owner
            .owner
            .h3
            .managers
            .lock()
            .unwrap()
            .contains_key(&other_key)
    );
    assert_eq!(stop_test_owner(&other_owner, other_thread).h3.managers, 1);
}
