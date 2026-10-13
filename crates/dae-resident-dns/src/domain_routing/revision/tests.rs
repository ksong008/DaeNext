use super::*;

#[test]
fn completed_new_response_supersedes_old_pending_response_without_retaining_keys() {
    let revisions = Arc::new(ResponseRevisions::default());
    let key = DnsCacheKey::new("race.test", 1, 1);
    let old = revisions.begin(&key).unwrap();
    let new = revisions.begin(&key).unwrap();
    assert!(old.can_commit().unwrap());
    new.committed().unwrap();
    drop(new);
    assert!(!old.can_commit().unwrap());
    assert_eq!(revisions.state.lock().unwrap().pending.len(), 1);
    drop(old);
    assert!(revisions.state.lock().unwrap().pending.is_empty());
    assert!(revisions.begin(&key).unwrap().can_commit().unwrap());
    assert!(revisions.state.lock().unwrap().pending.is_empty());
}

#[test]
fn failed_new_response_does_not_discard_an_older_valid_response() {
    let revisions = Arc::new(ResponseRevisions::default());
    let key = DnsCacheKey::new("failure.test", 1, 1);
    let old = revisions.begin(&key).unwrap();
    let failed = revisions.begin(&key).unwrap();
    drop(failed);
    assert!(old.can_commit().unwrap());
}

#[test]
fn removal_invalidates_pending_responses_but_not_subsequent_responses_or_other_keys() {
    let revisions = Arc::new(ResponseRevisions::default());
    let key = DnsCacheKey::new("removed.test", 1, 1);
    let old = revisions.begin(&key).unwrap();
    let unrelated = revisions
        .begin(&DnsCacheKey::new("other.test", 1, 1))
        .unwrap();
    revisions.invalidate(&key).unwrap();
    assert!(!old.can_commit().unwrap());
    assert!(unrelated.can_commit().unwrap());
    assert!(revisions.begin(&key).unwrap().can_commit().unwrap());
}
