use super::*;

const TEST_COOLDOWN: Duration = Duration::from_secs(8);

#[test]
fn transient_failure_blocks_only_until_retry_deadline() {
    let now = Instant::now();
    let mut recovery = ResidentDnsH2Recovery::default();

    assert!(recovery.should_attempt(now));
    recovery.record_failure(now, TEST_COOLDOWN);
    assert!(!recovery.should_attempt(now + TEST_COOLDOWN / 2));
    assert!(recovery.should_attempt(now + TEST_COOLDOWN));
    assert!(recovery.should_attempt(now + TEST_COOLDOWN * 2));
}

#[test]
fn successful_reopen_clears_existing_cooldown() {
    let now = Instant::now();
    let mut recovery = ResidentDnsH2Recovery::default();

    recovery.record_failure(now, TEST_COOLDOWN);
    recovery.record_success();

    assert!(recovery.should_attempt(now));
}
