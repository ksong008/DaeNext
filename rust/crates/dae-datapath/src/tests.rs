use base64::Engine;
use serde_json::Value;

use crate::*;

#[test]
fn magic_network_matches_golden_fixture() {
    let fixture = load("datapath/magic_network/mark_mptcp.json");
    for case in fixture["cases"].as_array().unwrap() {
        let got = magic_network_bytes(
            case["network"].as_str().unwrap(),
            case["mark"].as_u64().unwrap() as u32,
            case["mptcp"].as_bool().unwrap(),
        );
        let expected = base64::engine::general_purpose::STANDARD
            .decode(case["encoded_b64"].as_str().unwrap())
            .unwrap();
        assert_eq!(got, expected);
        assert_eq!(
            got == case["network"].as_str().unwrap().as_bytes(),
            case["is_plain"].as_bool().unwrap()
        );
        assert_eq!(got.len(), case["length"].as_u64().unwrap() as usize);
    }
}

#[test]
fn route_loop_matches_golden_fixture() {
    let fixture = load("datapath/route_loop/basic.json");
    for case in fixture["cases"].as_array().unwrap() {
        let rules = case["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|rule| RouteRule {
                kind: rule["type"].as_str().unwrap().to_owned(),
                outbound: rule["outbound"].as_u64().unwrap() as u8,
                mark: rule["mark"].as_u64().unwrap() as u32,
                must: rule["must"].as_bool().unwrap(),
                matched: rule["matched"].as_bool().unwrap(),
            })
            .collect::<Vec<_>>();
        let got = route_loop(&rules).unwrap();
        let expected = &case["expected"];
        assert_eq!(got.outbound, expected["outbound"].as_u64().unwrap() as u8);
        assert_eq!(got.mark, expected["mark"].as_u64().unwrap() as u32);
        assert_eq!(got.must, expected["must"].as_bool().unwrap());
        assert_eq!(got.fallback, expected["fallback"].as_bool().unwrap());
    }
}

#[test]
fn udp_and_sniffer_pool_constants_match_golden_fixture() {
    let fixture = load("datapath/udp_pools/basic.json");
    let endpoint = &fixture["udp_endpoint_pool"];
    assert_eq!(
        DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES,
        endpoint["default_max_entries"].as_i64().unwrap() as i32
    );
    assert_eq!(
        DEFAULT_NAT_TIMEOUT_MS,
        endpoint["default_nat_timeout_ms"].as_i64().unwrap()
    );
    assert_eq!(
        DNS_NAT_TIMEOUT_MS,
        endpoint["dns_nat_timeout_ms"].as_i64().unwrap()
    );
    assert_eq!(
        ANYFROM_TIMEOUT_MS,
        endpoint["anyfrom_timeout_ms"].as_i64().unwrap()
    );
    assert_eq!(MAX_RETRY, endpoint["max_retry"].as_i64().unwrap() as i32);

    for case in endpoint["normalize"].as_array().unwrap() {
        assert_eq!(
            normalize_udp_endpoint_pool_max_entries(case["input"].as_i64().unwrap() as i32),
            case["output"].as_i64().unwrap() as i32
        );
    }
    for case in endpoint["trim_target"].as_array().unwrap() {
        assert_eq!(
            udp_endpoint_pool_trim_target(case["max_entries"].as_i64().unwrap() as i32),
            case["target"].as_i64().unwrap() as i32
        );
    }

    let task = &fixture["udp_task_pool"];
    assert_eq!(
        UDP_TASK_QUEUE_LENGTH,
        task["queue_length"].as_u64().unwrap() as usize
    );
    assert_eq!(
        UDP_TASK_POOL_MAX_QUEUES,
        task["max_queues"].as_u64().unwrap() as usize
    );

    let sniffer = &fixture["packet_sniffer_pool"];
    assert_eq!(PACKET_SNIFFER_TTL_MS, sniffer["ttl_ms"].as_i64().unwrap());
    assert_eq!(
        PACKET_SNIFFER_POOL_MAX_ENTRIES,
        sniffer["max_entries"].as_u64().unwrap() as usize
    );
    assert!(packet_sniffer::packet_sniffer_expired(
        0,
        PACKET_SNIFFER_TTL_MS,
        PACKET_SNIFFER_TTL_MS
    ));
}

#[test]
fn udp_task_pool_model_preserves_fifo_and_drops_on_full_queue() {
    let mut pool = UdpTaskPoolModel::default();
    assert!(pool.emit_task("flow", 1));
    assert!(pool.emit_task("flow", 2));
    assert_eq!(pool.drain_key("flow"), vec![1, 2]);

    for task in 0..UDP_TASK_QUEUE_LENGTH {
        assert!(pool.emit_task("full", task as u64));
    }
    assert!(!pool.emit_task("full", 999));
    assert_eq!(pool.dropped(), 1);
}

fn load(path: &str) -> Value {
    dae_golden::load_json(path).unwrap()
}
