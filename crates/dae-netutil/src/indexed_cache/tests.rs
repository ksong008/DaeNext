use super::*;

#[test]
fn collisions_require_equality_and_hits_update_lru() {
    let mut cache = IndexedCache::new(2);
    cache.insert(7, "first");
    cache.insert(7, "second");
    assert_eq!(cache.get(7, |v| *v == "first"), Some(&"first"));
    assert_eq!(cache.get(7, |v| *v == "absent"), None);
    assert_eq!(cache.insert(8, "third"), Some("second"));
    assert_eq!(cache.get(7, |v| *v == "first"), Some(&"first"));
    assert_eq!(cache.get(8, |_| true), Some(&"third"));
    assert_eq!(cache.len, 2);
}
