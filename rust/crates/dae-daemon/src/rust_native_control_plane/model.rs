use super::*;
pub(super) const NOW_UNIX: i64 = 1_700_000_000;
pub(super) const DOMAIN_ROUTING_MAP_ID: u32 = 101;
pub(super) const DOMAIN_ROUTING_RELOAD_MAP_ID: u32 = 102;
pub(super) const ROUTING_MAP_ID: u32 = 201;
pub(super) const LPM_ARRAY_MAP_ID: u32 = 202;
pub(super) const CONNECTIVITY_MAP_ID: u32 = 301;
pub(super) const DEFAULT_ITERATIONS: u32 = 10_000;

pub(super) const DNS_QUERY: &[u8] = &[
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x', b'a',
    b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
];
pub(super) const DNS_RESPONSE: &[u8] = &[
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x', b'a',
    b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00,
    0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x02, 0xc0, 0x0c, 0xc0, 0x0c, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0xcb, 0x00, 0x71, 0x14,
];

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct NativeDnsEventSeed {
    pub(super) owner_key: String,
    pub(super) bitmap: [u32; 32],
    pub(super) ips: Vec<dae_control::DomainRoutingIpKey>,
    pub(super) cache_hit_response_len: usize,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct NativeFlowEvidence {
    pub(super) dns_event: NativeDnsEventSeed,
    pub(super) domain_apply: DomainRoutingOwnerApplyReport,
    pub(super) domain_duplicate: DomainRoutingOwnerApplyReport,
    pub(super) domain_reload_clear_deletes: usize,
    pub(super) domain_reload_restore: DomainRoutingOwnerApplyReport,
    pub(super) reload_plan: ReloadDnsCachePlan,
    pub(super) routing_apply: RoutingRuleOwnerApplyReport,
    pub(super) routing_duplicate_skipped: bool,
    pub(super) sniff_domain: String,
    pub(super) userspace_routing_outbound: OutboundIndex,
    pub(super) connectivity_apply_entries: usize,
    pub(super) connectivity_duplicate_skipped: bool,
    pub(super) runtime_ready: bool,
    pub(super) admission_ready: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) struct NativeBenchmarkEvidence {
    pub(super) iterations: u32,
    pub(super) dns_packet_to_domain_event_ns_per_op: u64,
    pub(super) domain_routing_duplicate_ns_per_op: u64,
    pub(super) domain_routing_toggle_ns_per_op: u64,
    pub(super) reload_transaction_ns_per_op: u64,
    pub(super) routing_owner_duplicate_ns_per_op: u64,
    pub(super) connectivity_owner_duplicate_ns_per_op: u64,
}
