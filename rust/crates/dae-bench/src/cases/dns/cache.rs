use super::*;
pub(super) fn bench_dns_data_zero_id(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let payload = [0x12, 0x34, 0x56, 0x78];
    Ok(measure(
        || {
            let zeroed = dae_dns::dns_data_with_zero_id(black_box(&payload));
            black_box(zeroed[0] as u64 ^ zeroed[1] as u64 ^ zeroed.len() as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_dns_packed_response_restore(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    let mut entry = DnsCacheEntry::new(60, 60);
    entry.packed_response = vec![
        0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x01, 0x01, 0x01, 0x01,
    ];
    let mut restored = Vec::with_capacity(entry.packed_response.len());
    Ok(measure(
        || {
            entry
                .fill_packed_response_into(black_box(0x1234), &mut restored)
                .expect("packed response restore");
            black_box(restored.len() as u64 ^ restored[0] as u64 ^ restored[1] as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_dns_cache_key_roundtrip(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let key = DnsCacheKey::new(black_box("Example.COM"), black_box(1), black_box(1));
            let structured = parse_dns_cache_key_view(black_box("example.com.|1|1"))
                .expect("structured dns key");
            let legacy =
                parse_dns_cache_key_view(black_box("example.com.1")).expect("legacy dns key");
            black_box(
                key.qname.len() as u64
                    ^ key.matches_view(structured) as u64
                    ^ ((key.matches_view(legacy) as u64) << 1),
            )
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_dns_cache_ttl_lookup(iters: u64, warmup: u64) -> Result<Measurement, String> {
    const NOW: i64 = 1_700_000_000;
    const LIVE_KEY: DnsCacheKeyView<'static> = DnsCacheKeyView {
        qname: "live.example.",
        qtype: 1,
        qclass: 1,
    };
    const CLIENT_EXPIRED_KEY: DnsCacheKeyView<'static> = DnsCacheKeyView {
        qname: "client-expired.example.",
        qtype: 1,
        qclass: 1,
    };
    const EXPIRED_KEY: DnsCacheKeyView<'static> = DnsCacheKeyView {
        qname: "expired.example.",
        qtype: 1,
        qclass: 1,
    };
    const LIVE_QUERY: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, b'l', b'i',
        b'v', b'e', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    Ok(measure(
        || {
            let mut store = DnsCacheStore::new(8);
            store.insert_without_route_owner_key(
                NOW,
                DnsCacheKey::new(LIVE_KEY.qname, LIVE_KEY.qtype, LIVE_KEY.qclass),
                DnsCacheEntry::new(NOW + 60, NOW + 60),
            );
            store.insert_without_route_owner_key(
                NOW,
                DnsCacheKey::new(
                    CLIENT_EXPIRED_KEY.qname,
                    CLIENT_EXPIRED_KEY.qtype,
                    CLIENT_EXPIRED_KEY.qclass,
                ),
                DnsCacheEntry::new(NOW - 60, NOW + 60),
            );
            store.insert_without_route_owner_key(
                NOW,
                DnsCacheKey::new(EXPIRED_KEY.qname, EXPIRED_KEY.qtype, EXPIRED_KEY.qclass),
                DnsCacheEntry::new(NOW - 60, NOW - 60),
            );

            let mut checksum = 0_u64;
            let live_view = DnsPacketView::parse(black_box(LIVE_QUERY)).expect("live dns query");
            let live_question = live_view.questions().next().expect("live dns question");
            checksum ^= store
                .lookup_packet_question(NOW, black_box(&live_question), false)
                .expect("packet question lookup")
                .is_some() as u64;
            checksum ^= (store
                .lookup_view(NOW, black_box(CLIENT_EXPIRED_KEY), false)
                .is_none() as u64)
                << 1;
            checksum ^= (store
                .lookup_view(NOW, black_box(CLIENT_EXPIRED_KEY), true)
                .is_some() as u64)
                << 2;
            checksum ^= (store
                .lookup_view(NOW, black_box(EXPIRED_KEY), false)
                .is_none() as u64)
                << 3;
            checksum ^= store.stats().hit_total << 4;
            checksum ^= store.stats().expired_removal_total << 8;
            black_box(checksum)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_dns_request_cache_hit_packet_view(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    const NOW: i64 = 1_700_000_000;
    const QUERY: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    let response = dns_response_cache_plan_packet_fixture();
    let plan = build_response_cache_plan_from_packet(NOW, &response, None)
        .map_err(|err| err.to_string())?
        .ok_or_else(|| "missing response cache plan".to_owned())?;
    let mut store = DnsCacheStore::new(8);
    store.insert_without_route_owner_key(NOW, plan.key, plan.entry);
    let mut restored = Vec::with_capacity(response.len());
    Ok(measure(
        || {
            let hit = restore_cached_response_for_packet_question(
                black_box(&mut store),
                black_box(NOW),
                black_box(QUERY),
                black_box(false),
                black_box(&mut restored),
            )
            .expect("packet cache lookup")
            .expect("packet cache hit");
            black_box(hit.request_id as u64 ^ hit.response_len as u64 ^ restored[0] as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_dns_response_cache_plan_packet_view(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    const NOW: i64 = 1_700_000_000;
    let response = dns_response_cache_plan_packet_fixture();
    let mut store = DnsCacheStore::new(8);
    Ok(measure(
        || {
            let plan = build_response_cache_plan_from_packet(
                black_box(NOW),
                black_box(&response),
                Some(0),
            )
            .expect("response cache plan")
            .expect("cacheable response");
            let checksum = plan.min_ttl as u64
                ^ plan.answer_count as u64
                ^ plan.ip_count as u64
                ^ plan.client_ttl_zeroed as u64
                ^ plan.entry.deadline_unix as u64
                ^ plan.entry.original_deadline_unix as u64
                ^ plan.entry.packed_response.len() as u64;
            store.insert_without_route_owner_key(black_box(NOW), plan.key, plan.entry);
            black_box(checksum ^ store.len() as u64)
        },
        iters,
        warmup,
    ))
}
