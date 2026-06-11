use super::super::maps::resident_outbound_connectivity_entries;
use super::super::types::OutboundConnectivityEntry;
use super::super::{
    CONNECTIVITY_IP_VERSION_4, CONNECTIVITY_IP_VERSION_6, CONNECTIVITY_L4_TCP, CONNECTIVITY_L4_UDP,
    CONNECTIVITY_L4_UDP_LEGACY,
};
use super::*;
#[test]
pub(super) fn resident_outbound_connectivity_entries_cover_user_groups() {
    let sections = parse_config(
        r#"
global {
    lan_interface: daerust0
}
group {
    proxy {
        policy: fixed(0)
    }
    backup {
        policy: fixed(1)
    }
}
routing {
    l4proto(udp) && dport(19090) -> proxy
    fallback: direct
}
"#,
    )
    .unwrap();
    let config = build_config(&sections).unwrap();
    let entries = resident_outbound_connectivity_entries(&config);
    let first = OutboundIndex::USER_DEFINED_MIN.value();
    let second = first + 1;

    assert_eq!(entries.len(), 12);
    assert!(!entries.iter().any(|entry| {
        entry.outbound == OutboundIndex::DIRECT.value()
            || entry.outbound == OutboundIndex::BLOCK.value()
    }));
    for outbound in [first, second] {
        for l4proto in [
            CONNECTIVITY_L4_TCP,
            CONNECTIVITY_L4_UDP,
            CONNECTIVITY_L4_UDP_LEGACY,
        ] {
            for ipversion in [CONNECTIVITY_IP_VERSION_4, CONNECTIVITY_IP_VERSION_6] {
                assert!(entries.contains(&OutboundConnectivityEntry {
                    outbound,
                    l4proto,
                    ipversion,
                }));
            }
        }
    }
}
