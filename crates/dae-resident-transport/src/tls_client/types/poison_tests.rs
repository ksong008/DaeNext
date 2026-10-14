use super::*;

#[test]
fn poisoned_connector_cache_is_rebuilt_while_active_contexts_remain_owned() {
    let key = ResidentTlsClientConfigKey {
        protocol_namespace: "test".to_owned(),
        server_name: "example.com".to_owned(),
        flow: String::new(),
        alpn: vec!["h2".to_owned()],
        allow_insecure: false,
        system_ca: None,
        utls_fingerprint: None,
        ech: None,
        reality: None,
    };
    let active = Arc::new(7);
    let mutex = Mutex::new(ResidentTlsConfigCache::default());
    lock_tls_config_cache(&mutex).insert_or_get(key.clone(), Arc::clone(&active));
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut cache = mutex.lock().unwrap();
        cache.next_generation = u64::MAX;
        panic!("injected connector cache poison");
    }));
    let mut cache = lock_tls_config_cache(&mutex);
    assert!(!mutex.is_poisoned());
    assert_eq!(cache.len(), 0);
    assert_eq!(Arc::strong_count(&active), 1);
    assert_eq!(*active, 7);
    let replacement = cache.insert_or_get(key.clone(), Arc::new(9));
    assert_eq!(*cache.get(&key).unwrap(), 9);
    assert!(Arc::ptr_eq(
        &replacement,
        &cache.get_matching(|candidate| candidate == &key).unwrap()
    ));
}
