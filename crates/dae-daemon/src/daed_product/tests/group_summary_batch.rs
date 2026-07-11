use super::support::FreshProductState;
use super::*;

#[test]
fn batched_group_summary_scales_with_shared_subscriptions_when_enabled() {
    if std::env::var_os("DAE_RUN_GROUP_SUMMARY_PRESSURE_FIXTURE").is_none() {
        return;
    }

    let fixture = FreshProductState::new("group-summary-pressure");
    let mut conn = fixture.connection();
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let subscription_count = 20_i64;
    let nodes_per_subscription = 50_i64;
    let group_count = 100_i64;
    for subscription_id in 1..=subscription_count {
        tx.execute(
            "INSERT INTO subscriptions(
                id, updated_at, link, status, info, tag
             ) VALUES(?1, 'now', ?2, 'fetched', '', ?3)",
            params![
                subscription_id,
                format!("https://example.invalid/subscription-{subscription_id}"),
                format!("subscription-{subscription_id}")
            ],
        )
        .unwrap();
        for node_offset in 0..nodes_per_subscription {
            let node_id = subscription_id * 10_000 + node_offset;
            let name = format!("candidate-{subscription_id}-{node_offset}");
            tx.execute(
                "INSERT INTO nodes(
                    id, link, name, address, protocol, tag, subscription_id
                 ) VALUES(?1, ?2, ?3, '127.0.0.1', 'socks', NULL, ?4)",
                params![
                    node_id,
                    format!("socks://127.0.0.1:{}#{name}", 10_000 + node_offset),
                    name,
                    subscription_id
                ],
            )
            .unwrap();
        }
    }
    for group_id in 1..=group_count {
        tx.execute(
            "INSERT INTO groups(id, name, policy, version) VALUES(?1, ?2, 'min', 0)",
            params![group_id, format!("group-{group_id}")],
        )
        .unwrap();
        for subscription_id in 1..=subscription_count {
            tx.execute(
                "INSERT INTO group_subscriptions(
                    group_id, subscription_id, name_filter_regex
                 ) VALUES(?1, ?2, 'candidate-')",
                params![group_id, subscription_id],
            )
            .unwrap();
        }
    }
    tx.commit().unwrap();
    drop(conn);

    let started = Instant::now();
    let summary = list_group_summaries_value(fixture.state()).unwrap();
    let elapsed = started.elapsed();
    let items = summary["items"].as_array().unwrap();
    assert_eq!(items.len(), usize::try_from(group_count).unwrap());
    assert!(items.iter().all(|group| {
        group["materializedCandidateCount"] == json!(subscription_count * nodes_per_subscription)
    }));
    eprintln!(
        "group_summary_pressure groups={} subscriptions={} nodes={} elapsed_ms={}",
        group_count,
        subscription_count,
        subscription_count * nodes_per_subscription,
        elapsed.as_millis()
    );
}
