use super::*;

#[test]
fn poisoned_context_cache_discards_entries_but_keeps_live_contexts_usable() {
    let snapshot = system_ca_snapshot().unwrap();
    let context = build_boring_tls_context_with_system_ca(&snapshot, &[b"h2"]).unwrap();
    let weak = Arc::downgrade(&context);
    let cache = Mutex::new(BTreeMap::from([(
        (snapshot.identity().clone(), "h2".to_owned()),
        Arc::clone(&context),
    )]));
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = cache.lock().unwrap();
        panic!("injected TLS context cache poison");
    }));
    assert!(lock_boring_context_cache(&cache).is_empty());
    assert!(!cache.is_poisoned());
    assert!(boring::ssl::Ssl::new(&context).is_ok());
    drop(context);
    assert!(weak.upgrade().is_none());
    let rebuilt = build_boring_tls_context_with_system_ca(&snapshot, &[b"h2"]).unwrap();
    lock_boring_context_cache(&cache)
        .insert((snapshot.identity().clone(), "h2".to_owned()), rebuilt);
    assert_eq!(lock_boring_context_cache(&cache).len(), 1);
}
