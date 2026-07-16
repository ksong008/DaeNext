use super::*;

#[test]
fn deadline_queue_orders_older_absolute_deadline_inserted_after_newer_request() {
    let now = time::Instant::now();
    let mut deadlines = VecDeque::new();
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

    assert_eq!(
        deadlines
            .iter()
            .map(|deadline| deadline.id)
            .collect::<Vec<_>>(),
        vec![10, 20, 30]
    );
}

#[test]
fn completed_later_requests_do_not_accumulate_behind_an_older_pending_request() {
    let now = time::Instant::now();
    let oldest = PendingProxyDnsDeadline {
        id: 1,
        generation: 1,
        deadline: now + std::time::Duration::from_secs(1),
    };
    let mut deadlines = VecDeque::from([oldest]);

    for generation in 2_u64..=128 {
        let completed = PendingProxyDnsDeadline {
            id: generation as u16,
            generation,
            deadline: now + std::time::Duration::from_secs(2),
        };
        insert_proxy_dns_udp_deadline(&mut deadlines, completed);
        assert!(remove_proxy_dns_udp_deadline(
            &mut deadlines,
            completed.id,
            completed.generation,
        ));
        assert_eq!(deadlines, VecDeque::from([oldest]));
    }
}
