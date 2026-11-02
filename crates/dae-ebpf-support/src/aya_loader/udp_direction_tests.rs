//! Real timer expiry and UDP direction ownership at the physical LAN boundary.
use super::listener_lifecycle_tests::{bytes, load, loaded_with_timeout, map_fd, packet, tuple};
use super::*;
use crate::runtime_maps::{lookup_map_elem_bytes, update_map_elem_bytes};
use crate::{BpfMatchSet, BpfTuplesKey, BpfUdpConnState};
use aya::programs::{TestRun, TestRunOptions};
use std::os::fd::AsFd;

fn run(loaded: &AyaUserspaceLoadedObject, name: &str, data: &[u8], ingress: u32) -> u32 {
    // Linux __sk_buff prefix, through tc_index. Only ifindex/ingress_ifindex
    // are set; the kernel supplies actual packet length and protocol.
    let mut context = [0u32; 12];
    context[9] = ingress;
    context[10] = 1; // loopback exists in the isolated test namespace
    let program: &SchedClassifier = loaded.ebpf.program(name).unwrap().try_into().unwrap();
    program
        .test_run(TestRunOptions {
            data_in: Some(data),
            ctx_in: Some(bytes(&context)),
            ..Default::default()
        })
        .unwrap()
        .return_value
}

fn flow(ipv6: bool) -> (Vec<u8>, Vec<u8>, BpfTuplesKey) {
    let (data, key, offset) = if ipv6 {
        let mut data = vec![0; 14 + 40 + 20];
        data[12..14].copy_from_slice(&[0x86, 0xdd]);
        data[14] = 0x60;
        data[18..20].copy_from_slice(&20u16.to_be_bytes());
        data[20] = 17;
        data[21] = 64;
        let mut key = tuple(17);
        key.sip.u6_addr8 = [0; 16];
        key.sip.u6_addr8[0] = 0xfd;
        key.sip.u6_addr8[15] = 1;
        key.dip = key.sip;
        key.dip.u6_addr8[15] = 2;
        data[22..38].copy_from_slice(&key.sip.u6_addr8);
        data[38..54].copy_from_slice(&key.dip.u6_addr8);
        data[54..56].copy_from_slice(&1234u16.to_be_bytes());
        data[56..58].copy_from_slice(&443u16.to_be_bytes());
        data[58..60].copy_from_slice(&20u16.to_be_bytes());
        (data, key, 54)
    } else {
        (packet(17), tuple(17), 34)
    };
    let mut reverse = data.clone();
    if ipv6 {
        reverse[22..38].copy_from_slice(&data[38..54]);
        reverse[38..54].copy_from_slice(&data[22..38]);
    } else {
        reverse[26..30].copy_from_slice(&data[30..34]);
        reverse[30..34].copy_from_slice(&data[26..30]);
    }
    reverse[offset..offset + 2].copy_from_slice(&data[offset + 2..offset + 4]);
    reverse[offset + 2..offset + 4].copy_from_slice(&data[offset..offset + 2]);
    (data, reverse, key)
}

fn direction(loaded: &AyaUserspaceLoadedObject, key: &BpfTuplesKey) -> u8 {
    let mut value = vec![0; mem::size_of::<BpfUdpConnState>()];
    lookup_map_elem_bytes(map_fd(loaded, "udp_conn_state_map"), bytes(key), &mut value).unwrap();
    value[0]
}

#[test]
fn expired_proxy_reply_does_not_reclassify_client_as_inbound() {
    let mut observations = Vec::new();
    for ipv6 in [false, true] {
        let Some(mut loaded) = loaded_with_timeout(Some(100_000_000)) else {
            return;
        };
        for name in ["tproxy_lan_ingress_l2", "tproxy_lan_egress_l2"] {
            load(&mut loaded, name);
        }
        // An explicit block fallback makes policy bypass distinguishable from
        // listener readiness, redirect, or an uninitialized routing table.
        let block = BpfMatchSet {
            kind: crate::MATCH_TYPE_FALLBACK,
            outbound: 1,
            ..Default::default()
        };
        let routing = match loaded.ebpf.map("routing_map").unwrap() {
            Map::Array(data) => data.fd().as_fd().as_raw_fd(),
            _ => unreachable!(),
        };
        update_map_elem_bytes(routing, &0u32.to_ne_bytes(), bytes(&block)).unwrap();
        let (forward, reverse, key) = flow(ipv6);
        assert_eq!(run(&loaded, "tproxy_lan_ingress_l2", &forward, 0), 2);
        assert_eq!(direction(&loaded, &key), 0);
        let state_fd = map_fd(&loaded, "udp_conn_state_map");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while crate::count_map_entries_by_fd(state_fd).unwrap() != 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "real timer did not expire"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // dae0_ifindex=1 in PARAM. A reply from that ingress must not create
        // an inbound ownership record after the original timer has expired.
        assert_eq!(run(&loaded, "tproxy_lan_egress_l2", &reverse, 1), u32::MAX);
        let recreated = crate::count_map_entries_by_fd(state_fd).unwrap();
        let action = run(&loaded, "tproxy_lan_ingress_l2", &forward, 0);
        let direction = direction(&loaded, &key);
        eprintln!(
            "real expiry, ipv6={ipv6}: reply_entries={recreated}, client_action={action}, direction={direction}"
        );
        observations.push((recreated, action, direction));
    }
    assert_eq!(observations, vec![(0, 2, 0), (0, 2, 0)]);
}

#[test]
fn ordinary_inbound_reply_keeps_direction_contract() {
    for ipv6 in [false, true] {
        let Some(mut loaded) = loaded_with_timeout(None) else {
            return;
        };
        for name in ["tproxy_lan_ingress_l2", "tproxy_lan_egress_l2"] {
            load(&mut loaded, name);
        }
        let (forward, reverse, key) = flow(ipv6);
        // Identical packet bytes without dae0 ingress provenance remain an
        // ordinary incoming flow; neither addresses nor ports authenticate it.
        assert_eq!(run(&loaded, "tproxy_lan_egress_l2", &reverse, 0), u32::MAX);
        assert_eq!(direction(&loaded, &key), 1);
        assert_eq!(run(&loaded, "tproxy_lan_ingress_l2", &forward, 0), u32::MAX);
        assert_eq!(direction(&loaded, &key), 1);
    }
}
