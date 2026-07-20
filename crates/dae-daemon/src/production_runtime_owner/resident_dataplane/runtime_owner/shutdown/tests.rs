use super::*;
use std::sync::{Condvar, mpsc};

fn test_owner(reload_generation: u64, name: &str) -> ResidentRuntimeOwner {
    let config = Config {
        global: dae_config::Global::default(),
        subscription: Vec::new(),
        node: Vec::new(),
        group: Vec::new(),
        routing: dae_config::Routing::default(),
        dns: dae_config::Dns::default(),
    };
    ResidentRuntimeOwner::new(
        std::env::temp_dir().join(format!("{name}-{}", std::process::id())),
        Arc::new(Mutex::new(())),
        reload_generation,
        Arc::new(ResidentDataplaneMetrics::default()),
        Arc::new(AtomicUsize::new(0)),
        ResidentRuntimeResourceConfig::from_config(&config),
        ResidentUdpPayloadAdmission::new(reload_generation, 1024),
    )
    .unwrap()
}

#[test]
fn resident_runtime_shutdown_enforces_owner_deadline() {
    let mut owner = test_owner(1, "resident-runtime-owner-deadline-test");
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let worker_release = Arc::clone(&release);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    owner.spawn_thread("blocked-worker", "runtime-lifecycle-test", move || {
        let (released, wake) = &*worker_release;
        let released = released.lock().unwrap();
        drop(wake.wait_while(released, |released| !*released).unwrap());
        let _ = done_tx.send(());
    });

    let evidence = owner.shutdown_with_grace(Duration::from_millis(25));
    let (released, wake) = &*release;
    *released.lock().unwrap() = true;
    wake.notify_all();
    done_rx.recv_timeout(Duration::from_secs(1)).unwrap();

    assert_eq!(evidence["task_count_timed_out"], 1);
    assert_eq!(evidence["task_count_joined"], 0);
    assert_eq!(evidence["task_count_aborted"], 0);
    assert_eq!(evidence["task_count_detached"], 1);
}

#[test]
fn resident_runtime_shutdown_reports_worker_panics_without_blocking_join() {
    let mut owner = test_owner(2, "resident-runtime-owner-panic-test");
    owner.spawn_thread("panicking-worker", "runtime-lifecycle-test", || {
        panic!("injected resident worker panic");
    });

    let evidence = owner.shutdown_with_grace(Duration::from_secs(1));

    assert_eq!(evidence["status"], "fail");
    assert_eq!(evidence["task_count_panicked"], 1);
    assert_eq!(evidence["task_count_timed_out"], 0);
    assert_eq!(evidence["tasks"][0]["status"], "panicked");
}

#[test]
fn resident_runtime_shutdown_reports_retained_queued_payload_bytes() {
    let mut owner = test_owner(3, "resident-runtime-owner-payload-test");
    let retained = owner.udp_payload_admission.try_acquire(256).unwrap();

    let evidence = owner.shutdown_with_grace(Duration::from_millis(25));

    assert_eq!(evidence["status"], "fail");
    assert_eq!(evidence["udp_payload_admission"]["currentBytes"], 256);
    drop(retained);
    assert_eq!(owner.udp_payload_admission.current(), 0);
}

#[test]
fn resident_runtime_shutdown_joins_cooperative_shared_tasks() {
    let mut owner = test_owner(4, "resident-runtime-owner-async-join-test");
    let stop = owner.stop_handle();
    owner.spawn_async_task("cooperative-task", "runtime-lifecycle-test", async move {
        stop.listener().cancelled().await;
    });

    let evidence = owner.shutdown_with_grace(Duration::from_secs(1));

    assert_eq!(evidence["status"], "pass");
    assert_eq!(evidence["task_count_joined"], 1);
    assert_eq!(evidence["joined_async_tasks"], 1);
    assert_eq!(evidence["task_count_aborted"], 0);
    assert_eq!(evidence["task_count_detached"], 0);
}

#[test]
fn resident_runtime_shutdown_aborts_uncooperative_shared_tasks() {
    let mut owner = test_owner(5, "resident-runtime-owner-async-timeout-test");
    owner.spawn_async_task("pending-task", "runtime-lifecycle-test", async move {
        std::future::pending::<()>().await;
    });

    let evidence = owner.shutdown_with_grace(Duration::from_millis(10));

    assert_eq!(evidence["status"], "fail");
    assert_eq!(evidence["task_count_timed_out"], 1);
    assert_eq!(evidence["task_count_aborted"], 1);
    assert_eq!(evidence["aborted_async_tasks"], 1);
    assert_eq!(evidence["task_count_detached"], 0);
}

#[test]
fn resident_runtime_shutdown_closes_shared_transport_owners() {
    let mut owner = test_owner(6_001, "resident-runtime-owner-shared-transports-test");
    let runtime = owner.data_plane_handle();
    let stop = owner.stop_handle();

    let (hysteria2, hysteria2_task) =
        start_hysteria2_owner_registry_on(&runtime, 6_001, Arc::clone(&stop));
    owner.install_hysteria2_owner_registry_task(hysteria2, hysteria2_task);
    let (tuic, tuic_task) = start_tuic_owner_registry_on(&runtime, 6_001, Arc::clone(&stop));
    owner.install_tuic_owner_registry_task(tuic, tuic_task);
    let (juicity, juicity_task) =
        start_juicity_owner_registry_on(&runtime, 6_001, Arc::clone(&stop));
    owner.install_juicity_owner_registry_task(juicity, juicity_task);
    let (anytls, anytls_task) = start_anytls_owner_registry_on(&runtime, 6_001, Arc::clone(&stop));
    owner.install_anytls_owner_registry_task(anytls, anytls_task);
    let (h2, h2_task) =
        start_h2_carrier_generation_owner_on(&runtime, 6_001, Arc::clone(&stop), 2).unwrap();
    owner.install_h2_carrier_generation_owner_task(h2, h2_task);
    let (meek, meek_task) =
        start_meek_transport_generation_owner_on(&runtime, 6_001, Arc::clone(&stop), 2).unwrap();
    owner.install_meek_transport_generation_owner_task(meek, meek_task);
    let (vless, vless_task) =
        start_vless_mux_generation_owner_on(&runtime, 6_001, Arc::clone(&stop), 2).unwrap();
    owner.install_vless_mux_generation_owner_task(vless, vless_task);
    let (xhttp, xhttp_task) =
        tcp::start_xhttp_xmux_generation_owner_on(&runtime, 6_001, 2).unwrap();
    owner.install_xhttp_xmux_generation_owner_task(xhttp, xhttp_task);

    let registry = owner.task_registry_value();
    for owner_name in [
        "h2CarrierOwners",
        "meekTransportOwners",
        "vlessMuxOwners",
        "xhttpXmuxOwner",
    ] {
        assert_eq!(
            registry[owner_name]["executor"],
            "generation-owned-shared-multi-thread"
        );
        assert_eq!(registry[owner_name]["sharedDataPlaneExecutor"], true);
    }

    let evidence = owner.shutdown();

    assert_eq!(evidence["status"], "pass");
    assert_eq!(evidence["task_count_timed_out"], 0);
    assert_eq!(evidence["task_count_panicked"], 0);
    assert_eq!(evidence["xhttpXmuxOwnerCleanup"]["status"], "pass");
}
