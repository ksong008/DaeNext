use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn panicked_callback_is_rejected_on_retry_without_running_it_again() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let resolver = UpstreamResolver::new(move || {
        observed.fetch_add(1, Ordering::Relaxed);
        panic!("injected resolver callback panic");
    });
    assert!(
        resolver
            .get_upstream(0)
            .unwrap_err()
            .to_string()
            .contains("panicked")
    );
    assert!(
        resolver
            .get_upstream(60)
            .unwrap_err()
            .to_string()
            .contains("callback lock poisoned")
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(resolver.stats().refresh_failure_total, 2);
}

#[test]
fn poisoned_state_returns_a_diagnostic_instead_of_panicking_again() {
    let resolver = UpstreamResolver::new(|| panic!("poisoned state must reject refresh"));
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = resolver.state.lock().unwrap();
        panic!("injected resolver state poison");
    }));
    assert!(
        resolver
            .get_upstream(0)
            .unwrap_err()
            .to_string()
            .contains("state lock poisoned")
    );
    assert_eq!(resolver.stats(), UpstreamResolverStats::default());
    assert_eq!(resolver.next_refresh_unix(), 0);
}
