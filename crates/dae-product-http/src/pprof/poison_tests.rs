use super::*;

fn poisoned_runtime() -> (ProductPprofRuntime, u16) {
    let listener = PprofListener::bind(0).unwrap();
    let port = listener.port;
    let runtime = ProductPprofRuntime {
        state: Mutex::new(PprofState {
            listener: Some(listener),
        }),
    };
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = runtime.state.lock().unwrap();
        panic!("injected pprof poison");
    }));
    (runtime, port)
}

#[test]
fn poisoned_pprof_reports_the_live_listener_and_drop_closes_it() {
    let (runtime, port) = poisoned_runtime();
    assert_eq!(runtime.port(), port);
    assert_eq!(runtime.status()["bound"], true);
    assert_eq!(runtime.status()["lockPoisoned"], true);
    drop(runtime);
    assert!(TcpListener::bind(("127.0.0.1", port)).is_ok());
}

#[test]
fn poisoned_pprof_allows_explicit_close_but_rejects_replacement() {
    let (runtime, port) = poisoned_runtime();
    assert!(runtime.apply_port(port).is_err());
    runtime.apply_port(0).unwrap();
    assert_eq!(runtime.port(), 0);
    assert!(TcpListener::bind(("127.0.0.1", port)).is_ok());
}
