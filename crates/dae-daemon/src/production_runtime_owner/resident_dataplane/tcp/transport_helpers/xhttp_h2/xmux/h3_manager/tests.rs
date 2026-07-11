use super::*;

fn cancellation_test_key(runtime_generation: u64) -> XhttpXmuxKey {
    XhttpXmuxKey {
        origin: format!("h3-opening-cancel-{}", fastrand::u64(..)),
        server_host: "xmux.invalid".to_owned(),
        server_port: 443,
        server_name: "xmux.invalid".to_owned(),
        alpn: vec!["h3".to_owned()],
        stream_host: "xmux.invalid".to_owned(),
        stream_path: "/xhttp".to_owned(),
        mode: ResidentXhttpMode::PacketUp,
        allow_insecure: false,
        tls_fragment: None,
        xmux: cancellation_test_plan(runtime_generation),
        mark: 0,
        mptcp: false,
    }
}

fn cancellation_test_plan(runtime_generation: u64) -> ResidentXhttpXmuxPlan {
    ResidentXhttpXmuxPlan {
        runtime_generation,
        max_concurrency: None,
        max_connections: Some((1, 1)),
        c_max_reuse_times: None,
        h_max_request_times: None,
        h_max_reusable_secs: None,
        h_keep_alive_period: 0,
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
