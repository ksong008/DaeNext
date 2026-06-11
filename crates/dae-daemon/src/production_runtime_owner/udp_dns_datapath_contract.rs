use std::time::Duration;

use dae_datapath::{
    ANYFROM_TIMEOUT_MS, DEFAULT_NAT_TIMEOUT_MS, DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES,
    DNS_NAT_TIMEOUT_MS, MAX_RETRY,
};
use dae_dns::DnsPacketView;
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct UdpDnsPacketClass {
    pub(super) is_dns: bool,
    pub(super) nat_timeout: Duration,
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn classify_udp_packet_for_contract(
    original_dst_port: u16,
    payload: &[u8],
) -> UdpDnsPacketClass {
    if original_dst_port == 53 && DnsPacketView::parse(payload).is_ok() {
        return UdpDnsPacketClass {
            is_dns: true,
            nat_timeout: Duration::from_millis(DNS_NAT_TIMEOUT_MS as u64),
        };
    }
    UdpDnsPacketClass {
        is_dns: false,
        nat_timeout: Duration::from_millis(DEFAULT_NAT_TIMEOUT_MS as u64),
    }
}

pub(super) fn udp_dns_datapath_contract_json() -> Value {
    json!({
        "schema": "generic-udp-dns-datapath-contract",
        "scope": "all-configs-native-runtime-not-test-machine-config",
        "global_hard_rule": {
            "test_machine_config_is_implementation_standard": false,
            "test_machine_config_role": "regression-and-reproduction-sample-only",
            "current_node_dns_ip_port_group_outbound_geodata_code_or_log_specific_fix_allowed": false,
            "required_standard": "native generic parser optimizer matcher DNS datapath contract plus golden fixtures and rule matrix"
        },
        "udp": {
            "key_model": "client-source-full-cone",
            "endpoint_pool_max_entries_default": DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES,
            "default_nat_timeout_ms": DEFAULT_NAT_TIMEOUT_MS,
            "dns_nat_timeout_ms": DNS_NAT_TIMEOUT_MS,
            "anyfrom_timeout_ms": ANYFROM_TIMEOUT_MS,
            "max_retry": MAX_RETRY,
            "dns_detection": "zero-copy UDP/53 DNS packet view; invalid UDP/53 remains ordinary UDP",
            "non_dns_dial_target": "keep original destination string even when QUIC/domain sniffing succeeds",
            "stale_non_fixed_dialer_policy": "remove dead non-fixed endpoint and reroute before retry"
        },
        "dns": {
            "request_entrypoints": [
                "transparent UDP/53",
                "local dns.bind listener",
                "synthetic resolver lookup"
            ],
            "required_semantics": [
                "reject DNS response input on request path",
                "request routing select before upstream",
                "asis allowed only where the compatibility contract allows it",
                "per-key handling de-duplication",
                "cache hit sends response without upstream",
                "response id and question validation",
                "tcp+udp truncated UDP response retries over TCP only for tcp+udp upstream",
                "response routing recursion depth limit",
                "reject response can be cached after answer clearing",
                "domain_routing_map owner migration on cache restore"
            ]
        },
        "outbound_boundary": {
            "protocol_agnostic_outbound_selection_required": true,
            "required_inputs": [
                "routing result outbound",
                "network type including IsDns",
                "strict IP version when dialing IP",
                "SO_MARK",
                "MPTCP",
                "dialer alive state",
                "selection policy"
            ]
        },
        "runtime_admission": {
            "requires_active_udp_evidence": true,
            "requires_active_dns_evidence": true,
            "requires_udp_dns_benchmarks": true,
            "final_native_evidence_required_until_admitted": true,
            "final_native_admission_allowed_by_this_contract": false
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns_query_packet() -> Vec<u8> {
        vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ]
    }

    #[test]
    fn udp_packet_classifier_uses_dns_timeout_only_for_valid_udp53_dns() {
        let dns = classify_udp_packet_for_contract(53, &dns_query_packet());
        let non_dns_port = classify_udp_packet_for_contract(853, &dns_query_packet());
        let invalid_dns = classify_udp_packet_for_contract(53, b"not-dns");

        assert!(dns.is_dns);
        assert_eq!(
            dns.nat_timeout,
            Duration::from_millis(DNS_NAT_TIMEOUT_MS as u64)
        );
        assert!(!non_dns_port.is_dns);
        assert!(!invalid_dns.is_dns);
        assert_eq!(
            non_dns_port.nat_timeout,
            Duration::from_millis(DEFAULT_NAT_TIMEOUT_MS as u64)
        );
        assert_eq!(
            invalid_dns.nat_timeout,
            Duration::from_millis(DEFAULT_NAT_TIMEOUT_MS as u64)
        );
    }

    #[test]
    fn generic_contract_rejects_test_config_as_implementation_standard() {
        let contract = udp_dns_datapath_contract_json();

        assert!(
            !contract["global_hard_rule"]["test_machine_config_is_implementation_standard"]
                .as_bool()
                .unwrap()
        );
        assert!(
            contract["outbound_boundary"]["protocol_agnostic_outbound_selection_required"]
                .as_bool()
                .unwrap()
        );
        assert!(
            contract["runtime_admission"]["final_native_evidence_required_until_admitted"]
                .as_bool()
                .unwrap()
        );
    }
}
