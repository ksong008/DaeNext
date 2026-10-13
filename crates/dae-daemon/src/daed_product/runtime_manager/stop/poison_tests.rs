use super::*;

#[test]
fn runtime_stop_poison_fails_closed_without_stranding_the_coordinator() {
    for poison_inner in [false, true] {
        let runtime = ProductRuntimeManager::new();
        runtime.inner().lock().unwrap().runtime =
            Some(ProductRuntimeInstance::Fake(FakeProductRuntime {
                started_at: "2026-10-13T00:00:00+08:00".to_owned(),
                tproxy_port: 12345,
            }));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if poison_inner {
                let _guard = runtime.inner().lock().unwrap();
                panic!("injected manager poison");
            } else {
                let _guard = runtime.lifecycle().lock().unwrap();
                panic!("injected lifecycle poison");
            }
        }));
        for _ in 0..2 {
            let error = runtime.prepare_stop().err().unwrap();
            assert!(
                error.contains(if poison_inner {
                    "manager lock poisoned"
                } else {
                    "lifecycle lock poisoned"
                }),
                "{error}"
            );
            let coordinator = runtime.reconciler().summary();
            assert_eq!(coordinator["stopPending"], 0, "{coordinator}");
            assert_eq!(coordinator["lastResult"], "abandoned", "{coordinator}");
            assert!(
                runtime
                    .inner()
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .runtime
                    .is_some()
            );
        }
    }
}
