use super::wait_for_listener_adoption;
use std::sync::mpsc::sync_channel;
use std::time::Duration;
#[test]
fn both_distinct_workers_must_adopt_before_publication() {
    for messages in [
        ["tcp", "udp"],
        ["udp", "tcp"],
        ["tcp", "tcp"],
        ["udp", "unknown"],
    ] {
        let (sender, receiver) = sync_channel(2);
        for message in messages {
            sender.send(message).unwrap();
        }
        assert_eq!(
            wait_for_listener_adoption(&receiver, Duration::from_millis(20)).is_ok(),
            messages[0] != messages[1] && messages[1] != "unknown"
        );
    }
}
#[test]
fn adoption_failure_or_missing_worker_prevents_publication() {
    let (sender, receiver) = sync_channel(2);
    sender.send("tcp").unwrap();
    drop(sender);
    assert!(wait_for_listener_adoption(&receiver, Duration::from_millis(20)).is_err());
    let (_sender, receiver) = sync_channel(2);
    assert!(wait_for_listener_adoption(&receiver, Duration::from_millis(5)).is_err());
}
