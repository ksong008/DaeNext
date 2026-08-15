use super::super::test_support::{download_test_key, download_test_plan};
use super::*;

const XHTTP_XMUX_TEST_OWNER_STACK_BYTES: usize = 1024 * 1024;

fn cancellation_test_key(runtime_generation: u64) -> XhttpXmuxKey {
    XhttpXmuxKey::isolated_test(
        fastrand::u64(..),
        ResidentXhttpHttpVersion::H2,
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

async fn open_test_h2_sender() -> Result<XhttpH2EndpointSender, String> {
    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    tokio::spawn(async move {
        let Ok(mut server) = h2::server::handshake(server_io).await else {
            return;
        };
        while let Some(Ok((_request, mut response))) = server.accept().await {
            let _ = response.send_response(http::Response::new(()), true);
        }
    });
    let (sender, connection) = h2::client::handshake(client_io)
        .await
        .map_err(|err| format!("test H2 client handshake: {err}"))?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(XhttpH2EndpointSender {
        sender,
        connection_task: Some(connection_task),
        xmux_lease: None,
    })
}

fn registered_download_manager(
    owner: &XhttpXmuxGenerationOwnerHandle,
    key: XhttpXmuxKey,
    runtime_generation: u64,
) -> XhttpXmuxManagerHandle<XhttpXmuxH2Manager> {
    owner
        .owner
        .h2
        .managers
        .lock()
        .unwrap()
        .entry(key)
        .or_insert_with(|| {
            XhttpXmuxManagerHandle::new(|lifecycle| {
                XhttpXmuxH2Manager::new(download_test_plan(runtime_generation), lifecycle)
            })
        })
        .clone()
}

#[test]
fn h2_download_manager_reuses_equivalent_keys_and_partitions_physical_identity() {
    let generation = fastrand::u64(..);
    let (owner, thread) = start_test_owner(generation);
    let graph = format!("sha256:{}", fastrand::u64(..));
    let equivalent_key = download_test_key(
        generation,
        &graph,
        1,
        "192.0.2.20:443",
        ResidentXhttpHttpVersion::H2,
    );
    let keys = [
        equivalent_key.clone(),
        download_test_key(
            generation,
            &format!("{graph}-other"),
            1,
            "192.0.2.20:443",
            ResidentXhttpHttpVersion::H2,
        ),
        download_test_key(
            generation,
            &graph,
            2,
            "192.0.2.20:443",
            ResidentXhttpHttpVersion::H2,
        ),
        download_test_key(
            generation,
            &graph,
            1,
            "[2001:db8::20]:443",
            ResidentXhttpHttpVersion::H2,
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
    assert_eq!(report.h2.managers, keys.len());
    assert!(report.owner_thread_joined);
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_h2_open_releases_the_reserved_slot() {
    let generation = fastrand::u64(..);
    let (owner, thread) = start_test_owner(generation);
    let key = cancellation_test_key(generation);
    let started = Arc::new(tokio::sync::Notify::new());
    let task = {
        let key = key.clone();
        let started = Arc::clone(&started);
        tokio::spawn(async move {
            select_xhttp_h2_xmux_client(key, cancellation_test_plan(generation), || async move {
                started.notify_one();
                std::future::pending::<Result<XhttpH2EndpointSender, String>>().await
            })
            .await
        })
    };
    started.notified().await;

    let manager = owner
        .owner
        .h2
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
        "aborting an in-flight H2 open must release xmux capacity"
    );

    let report = stop_test_owner(&owner, thread);
    assert_eq!(report.h2.managers, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn missing_generation_owner_rejects_before_physical_open() {
    let generation = fastrand::u64(..);
    let invoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let closure_invoked = Arc::clone(&invoked);
    let result = select_xhttp_h2_xmux_client(
        cancellation_test_key(generation),
        cancellation_test_plan(generation),
        move || {
            closure_invoked.store(true, Ordering::Release);
            async { Err::<XhttpH2EndpointSender, String>("unexpected physical open".to_owned()) }
        },
    )
    .await;

    let err = match result {
        Ok(_) => panic!("missing generation owner unexpectedly opened a client"),
        Err(err) => err,
    };
    assert!(err.contains("generation owner"));
    assert!(!invoked.load(Ordering::Acquire));
}

#[tokio::test(flavor = "current_thread")]
async fn physical_open_executes_on_the_generation_owner_runtime() {
    let generation = fastrand::u64(..);
    let (owner, thread) = start_test_owner(generation);
    let (name_tx, name_rx) = std::sync::mpsc::sync_channel(1);
    let result = select_xhttp_h2_xmux_client(
        cancellation_test_key(generation),
        cancellation_test_plan(generation),
        move || async move {
            let name = std::thread::current().name().unwrap_or_default().to_owned();
            let _ = name_tx.send(name);
            Err::<XhttpH2EndpointSender, String>("test open completed".to_owned())
        },
    )
    .await;

    assert_eq!(name_rx.recv().unwrap(), "resident-xhttp-xmux-owner");
    let err = match result {
        Ok(_) => panic!("test physical open unexpectedly returned a client"),
        Err(err) => err,
    };
    assert_eq!(err, "test open completed");
    let report = stop_test_owner(&owner, thread);
    assert_eq!(report.h2.managers, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn retiring_h2_owner_does_not_deadlock_its_replacement_slot() {
    let generation = fastrand::u64(..);
    let (owner, thread) = start_test_owner(generation);
    let key = cancellation_test_key(generation);
    let first = select_xhttp_h2_xmux_client(
        key.clone(),
        cancellation_test_plan(generation),
        open_test_h2_sender,
    )
    .await
    .unwrap();
    let download_lease = first.lease.independent_lease();
    first.lease.retire_physical();
    drop(first);

    let second = tokio::time::timeout(
        Duration::from_secs(1),
        select_xhttp_h2_xmux_client(
            key.clone(),
            cancellation_test_plan(generation),
            open_test_h2_sender,
        ),
    )
    .await
    .expect("retiring physical consumed the only reusable replacement slot")
    .unwrap();

    let manager = owner
        .owner
        .h2
        .managers
        .lock()
        .unwrap()
        .get(&key)
        .unwrap()
        .clone();
    assert_eq!(manager.manager.lock().await.clients.len(), 2);
    drop(download_lease);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if manager.manager.lock().await.clients.len() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("last retired lease did not trigger physical owner reaping");

    drop(second);
    let report = stop_test_owner(&owner, thread);
    assert_eq!(report.h2.clients, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn five_generation_reloads_reuse_and_release_h2_physical_clients() {
    for _ in 0..5 {
        let generation = fastrand::u64(..);
        let (owner, thread) = start_test_owner(generation);
        let key = cancellation_test_key(generation);
        let physical_opens = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let open_counter = Arc::clone(&physical_opens);
        let mut first = select_xhttp_h2_xmux_client(
            key.clone(),
            cancellation_test_plan(generation),
            move || async move {
                open_counter.fetch_add(1, Ordering::AcqRel);
                let (client_io, server_io) = tokio::io::duplex(16 * 1024);
                tokio::spawn(async move {
                    let Ok(mut server) = h2::server::handshake(server_io).await else {
                        return;
                    };
                    while let Some(Ok((_request, mut response))) = server.accept().await {
                        let _ = response.send_response(http::Response::new(()), true);
                    }
                });
                let (sender, connection) = h2::client::handshake(client_io)
                    .await
                    .map_err(|err| format!("test H2 client handshake: {err}"))?;
                let connection_task = tokio::spawn(async move {
                    let _ = connection.await;
                });
                Ok(XhttpH2EndpointSender {
                    sender,
                    connection_task: Some(connection_task),
                    xmux_lease: None,
                })
            },
        )
        .await
        .unwrap();
        let request = http::Request::builder()
            .uri("https://xmux.invalid/first")
            .body(())
            .unwrap();
        first
            .sender
            .send_request(request, true)
            .unwrap()
            .0
            .await
            .unwrap();

        let mut second =
            select_xhttp_h2_xmux_client(key, cancellation_test_plan(generation), || async {
                Err::<XhttpH2EndpointSender, String>(
                    "equivalent key unexpectedly opened a second client".to_owned(),
                )
            })
            .await
            .unwrap();
        let request = http::Request::builder()
            .uri("https://xmux.invalid/second")
            .body(())
            .unwrap();
        second
            .sender
            .send_request(request, true)
            .unwrap()
            .0
            .await
            .unwrap();
        assert_eq!(physical_opens.load(Ordering::Acquire), 1);

        drop(first);
        drop(second);
        let report = stop_test_owner(&owner, thread);
        assert_eq!(report.h2.managers, 1);
        assert_eq!(report.h2.clients, 1);
        assert_eq!(report.h2.locked_managers, 0);
        assert!(!report.cleanup_timed_out);
        assert!(report.owner_thread_joined);
        assert!(xhttp_xmux_generation_owner(generation).is_err());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn locked_h2_manager_is_drained_after_the_holder_releases_it() {
    let manager = XhttpXmuxManagerHandle::new(|lifecycle| {
        XhttpXmuxH2Manager::new(cancellation_test_plan(0), lifecycle)
    });
    let manager_lock = Arc::clone(&manager.manager);
    let mut guard = manager_lock.lock().await;
    let closing = {
        let manager = manager.clone();
        tokio::spawn(async move {
            close_xhttp_h2_manager(
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
        XhttpXmuxH2SelectAction::Closed
    ));
    drop(guard);
    assert_eq!(closing.await.unwrap(), (0, false));
}

#[test]
fn h2_cleanup_removes_only_the_requested_runtime_generation() {
    let generation = fastrand::u64(..);
    let other_generation = generation.wrapping_add(1);
    let (owner, thread) = start_test_owner(generation);
    let (other_owner, other_thread) = start_test_owner(other_generation);
    let key = cancellation_test_key(generation);
    let other_key = cancellation_test_key(other_generation);
    registered_download_manager(&owner, key, generation);
    registered_download_manager(&other_owner, other_key.clone(), other_generation);

    let report = stop_test_owner(&owner, thread);
    assert_eq!(report.h2.managers, 1);
    assert!(
        other_owner
            .owner
            .h2
            .managers
            .lock()
            .unwrap()
            .contains_key(&other_key)
    );
    assert_eq!(stop_test_owner(&other_owner, other_thread).h2.managers, 1);
}
