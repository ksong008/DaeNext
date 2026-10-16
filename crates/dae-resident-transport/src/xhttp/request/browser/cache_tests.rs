use super::*;

#[test]
fn concurrent_template_misses_share_one_entry() {
    let cache = std::sync::Mutex::new(IndexedCache::new(64));
    let barrier = std::sync::Barrier::new(8);
    let settings = ResidentXhttpSettingsPlan::official_default();
    std::thread::scope(|scope| {
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    request_headers_with_cache(
                        &settings,
                        ResidentXhttpHttpVersion::H1,
                        &cache,
                        || {
                            // All callers must miss before any of them can insert.
                            barrier.wait();
                            build_request_headers(&settings, ResidentXhttpHttpVersion::H1)
                        },
                    )
                })
            })
            .collect();
        let results: Vec<_> = tasks.into_iter().map(|task| task.join().unwrap()).collect();
        for headers in &results[1..] {
            assert!(Arc::ptr_eq(&results[0][0].0, &headers[0].0));
        }
    });
    let mut cache = cache.lock().unwrap();
    let hash = cache.hash((&settings.headers, ResidentXhttpHttpVersion::H1 as u8));
    let visited = std::cell::Cell::new(0);
    assert!(
        cache
            .get(hash, |_| {
                visited.set(visited.get() + 1);
                false
            })
            .is_none()
    );
    assert_eq!(visited.get(), 1);
}
