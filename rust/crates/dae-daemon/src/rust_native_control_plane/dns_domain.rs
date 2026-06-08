use super::*;
pub(super) fn build_native_dns_event_seed() -> Result<NativeDnsEventSeed, String> {
    let mut plan = build_response_cache_plan_from_packet(NOW_UNIX, DNS_RESPONSE, None)
        .map_err(|err| format!("rust native DNS response parse failed: {err}"))?
        .ok_or_else(|| "rust native DNS response produced no cache plan".to_owned())?;
    plan.entry.domain_bitmap = vec![0x4, 0x10];

    let mut store = DnsCacheStore::new(8);
    store.insert_without_route_owner_key(NOW_UNIX, plan.key, plan.entry);

    let mut restored = Vec::new();
    let hit = restore_cached_response_for_packet_question(
        &mut store,
        NOW_UNIX,
        DNS_QUERY,
        false,
        &mut restored,
    )
    .map_err(|err| format!("rust native DNS cache restore failed: {err}"))?
    .ok_or_else(|| "rust native DNS cache restore missed".to_owned())?;

    let cached = store
        .lookup(
            NOW_UNIX,
            &dae_dns::DnsCacheKey::new("example.com.", 1, 1),
            false,
        )
        .ok_or_else(|| "rust native DNS cache lookup missed after restore".to_owned())?;
    let mut bitmap = [0_u32; 32];
    for (index, word) in cached.domain_bitmap.iter().copied().enumerate().take(32) {
        bitmap[index] = word;
    }
    Ok(NativeDnsEventSeed {
        owner_key: cached.route_owner_key,
        bitmap,
        ips: cached.ips.iter().copied().map(ip_to_key).collect(),
        cache_hit_response_len: hit.response_len,
    })
}

pub(super) fn apply_domain_event(
    owner: &mut DomainRoutingOwner,
    map_id: u32,
    seed: &NativeDnsEventSeed,
) -> Result<DomainRoutingOwnerApplyReport, String> {
    owner
        .apply_dns_event_with(
            map_id,
            DomainRoutingDnsEvent::from_keys(&seed.owner_key, &seed.bitmap, seed.ips.clone()),
            |_, _, _| Ok(()),
        )
        .map_err(|err| format!("rust native domain routing owner apply failed: {err}"))
}
