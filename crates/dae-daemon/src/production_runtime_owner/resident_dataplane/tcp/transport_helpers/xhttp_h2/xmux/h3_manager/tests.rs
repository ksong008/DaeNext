use super::super::test_support::{download_test_key, download_test_plan};
use super::*;

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

fn registered_download_manager(
    key: XhttpXmuxKey,
    runtime_generation: u64,
) -> XhttpXmuxManagerHandle<XhttpXmuxH3Manager> {
    XHTTP_XMUX_H3_MANAGERS
        .get_or_init(|| Mutex::new(HashMap::new()))
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
    let base = registered_download_manager(keys[0].clone(), generation);
    let equivalent = registered_download_manager(equivalent_key, generation);
    assert!(Arc::ptr_eq(&base.manager, &equivalent.manager));
    for key in &keys[1..] {
        let partitioned = registered_download_manager(key.clone(), generation);
        assert!(!Arc::ptr_eq(&base.manager, &partitioned.manager));
    }

    let mut managers = XHTTP_XMUX_H3_MANAGERS.get().unwrap().lock().unwrap();
    for key in keys {
        managers.remove(&key);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_h3_open_releases_the_reserved_slot() {
    let key = cancellation_test_key(0);
    let started = Arc::new(tokio::sync::Notify::new());
    let task = {
        let key = key.clone();
        let started = Arc::clone(&started);
        tokio::spawn(async move {
            select_xhttp_h3_xmux_client(key, cancellation_test_plan(0), || async move {
                started.notify_one();
                std::future::pending::<Result<XhttpH3EndpointClient, String>>().await
            })
            .await
        })
    };
    started.notified().await;

    let manager = {
        let managers = XHTTP_XMUX_H3_MANAGERS.get().unwrap().lock().unwrap();
        managers.get(&key).unwrap().clone()
    };
    assert_eq!(manager.lifecycle.opening(), 1);

    task.abort();
    let _ = task.await;
    tokio::task::yield_now().await;
    assert_eq!(
        manager.lifecycle.opening(),
        0,
        "aborting an in-flight H3 open must release xmux capacity"
    );

    XHTTP_XMUX_H3_MANAGERS
        .get()
        .unwrap()
        .lock()
        .unwrap()
        .remove(&key);
}

#[tokio::test(flavor = "current_thread")]
async fn locked_h3_manager_is_closed_before_cleanup_is_deferred() {
    let manager = XhttpXmuxManagerHandle::new(|lifecycle| {
        XhttpXmuxH3Manager::new(cancellation_test_plan(0), lifecycle)
    });
    let manager_lock = Arc::clone(&manager.manager);
    let mut guard = manager_lock.lock().await;

    let (clients, deferred) = close_xhttp_h3_manager(&manager);
    assert_eq!(clients, 0);
    assert!(deferred);
    assert!(manager.lifecycle.is_closing());
    assert!(matches!(
        guard.select_or_reserve_new(),
        XhttpXmuxH3SelectAction::Closed
    ));
}

#[test]
fn h3_cleanup_removes_only_the_requested_runtime_generation() {
    let generation = fastrand::u64(..);
    let other_generation = generation.wrapping_add(1);
    let key = cancellation_test_key(generation);
    let other_key = cancellation_test_key(other_generation);
    {
        let mut managers = XHTTP_XMUX_H3_MANAGERS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap();
        managers.insert(
            key.clone(),
            XhttpXmuxManagerHandle::new(|lifecycle| {
                XhttpXmuxH3Manager::new(cancellation_test_plan(generation), lifecycle)
            }),
        );
        managers.insert(
            other_key.clone(),
            XhttpXmuxManagerHandle::new(|lifecycle| {
                XhttpXmuxH3Manager::new(cancellation_test_plan(other_generation), lifecycle)
            }),
        );
    }

    let report = clear_xhttp_h3_xmux_managers(generation);
    assert_eq!(report.managers, 1);
    {
        let managers = XHTTP_XMUX_H3_MANAGERS.get().unwrap().lock().unwrap();
        assert!(!managers.contains_key(&key));
        assert!(managers.contains_key(&other_key));
    }
    assert_eq!(clear_xhttp_h3_xmux_managers(other_generation).managers, 1);
}
