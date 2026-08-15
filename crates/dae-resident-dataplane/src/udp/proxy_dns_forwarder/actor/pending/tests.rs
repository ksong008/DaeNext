use super::*;

#[test]
fn deadline_queue_orders_older_absolute_deadline_inserted_after_newer_request() {
    let now = time::Instant::now();
    let mut deadlines = BinaryHeap::new();
    insert_proxy_dns_udp_deadline(
        &mut deadlines,
        PendingProxyDnsDeadline {
            id: 30,
            generation: 1,
            deadline: now + std::time::Duration::from_millis(30),
        },
    );
    insert_proxy_dns_udp_deadline(
        &mut deadlines,
        PendingProxyDnsDeadline {
            id: 10,
            generation: 2,
            deadline: now + std::time::Duration::from_millis(10),
        },
    );
    insert_proxy_dns_udp_deadline(
        &mut deadlines,
        PendingProxyDnsDeadline {
            id: 20,
            generation: 3,
            deadline: now + std::time::Duration::from_millis(20),
        },
    );

    let mut ids = Vec::new();
    while let Some(Reverse(deadline)) = deadlines.pop() {
        ids.push(deadline.id);
    }
    assert_eq!(ids, vec![10, 20, 30]);
}

#[test]
fn stale_deadlines_are_compacted_without_linear_removal() {
    let now = time::Instant::now();
    let mut deadlines = BinaryHeap::new();
    for generation in 1_u64..=128 {
        insert_proxy_dns_udp_deadline(
            &mut deadlines,
            PendingProxyDnsDeadline {
                id: generation as u16,
                generation,
                deadline: now + std::time::Duration::from_secs(generation),
            },
        );
    }
    let pending = HashMap::new();
    assert_eq!(next_proxy_dns_udp_deadline(&mut deadlines, &pending), None);
    assert!(deadlines.is_empty());
}
