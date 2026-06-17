use super::*;
pub(super) fn apply_domain_routing_entries(
    map_id: u32,
    updates: &[DomainRoutingStateEntry],
    deletes: &[DomainRoutingIpKey],
) -> io::Result<()> {
    let updates = updates
        .iter()
        .map(|entry| DomainRoutingMapEntry {
            key: entry.key,
            value: BpfDomainRouting {
                bitmap: entry.bitmap,
            },
        })
        .collect::<Vec<_>>();
    apply_domain_routing_map_by_id(map_id, &updates, deletes).map(|_| ())
}
