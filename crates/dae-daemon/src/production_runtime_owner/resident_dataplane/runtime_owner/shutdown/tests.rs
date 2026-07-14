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
