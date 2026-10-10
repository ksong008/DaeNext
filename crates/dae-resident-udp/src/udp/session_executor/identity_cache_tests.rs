use super::*;

#[test]
fn identity_cache_tracks_wire_identity_and_protocol_domain() {
    let mut cache = ProtocolIdentityCache::default();
    let first = cache.token(b"protocol-a", [1; 8]).unwrap();
    assert_eq!(cache.token(b"protocol-a", [1; 8]), Some(first));
    assert_ne!(cache.token(b"protocol-a", [2; 8]), Some(first));
    assert_ne!(cache.token(b"protocol-b", [1; 8]), Some(first));
    assert_eq!(cache.token(b"protocol-a", [1; 8]), Some(first));
}
