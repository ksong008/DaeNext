use serde_json::Value;

use crate::*;
#[test]
pub(super) fn domain_routing_map_owner_serve_reports_empty_snapshot_without_opening_map() {
    let mut owner = dae_runtime_control::DomainRoutingOwner::default();
    let response = handle_domain_routing_map_owner_serve_line(
        &mut owner,
        r#"{"op":"sync_owner","map_id":0,"owner_key":"empty","bitmap":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"ips":[]}"#,
    );
    let json: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(json["status"].as_str().unwrap(), "pass");
    assert_eq!(json["owner"].as_str().unwrap(), "dae-runtime-control");
    assert_eq!(json["scope"].as_str().unwrap(), "domain-routing-map-owner");
    assert!(json["map_id_changed"].as_bool().unwrap());
    assert!(json["skipped"].as_bool().unwrap());
    assert_eq!(json["entries_updated"].as_u64().unwrap(), 0);
}

#[test]
pub(super) fn connectivity_map_serve_dryrun_skip_does_not_open_map() {
    let mut owner = dae_runtime_control::OutboundConnectivityMapOwner::default();
    let response = handle_connectivity_map_serve_line(
        &mut owner,
        r#"{"map_id":0,"outbound":2,"l4_proto":6,"ip_version":4,"alive":true,"is_init":false,"dryrun":true}"#,
    );
    let json: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(json["status"].as_str().unwrap(), "pass");
    assert!(!json["written"].as_bool().unwrap());
    assert!(!json["accepted"].as_bool().unwrap());
    assert_eq!(json["owner"].as_str().unwrap(), "dae-runtime-control");
    assert_eq!(json["key"]["outbound"].as_u64().unwrap(), 2);
    assert!(owner.state_owner().state().is_empty());
}

#[test]
pub(super) fn connectivity_map_serve_binary_dryrun_skip_does_not_open_map() {
    let mut owner = dae_runtime_control::OutboundConnectivityMapOwner::default();
    let response = handle_connectivity_map_serve_binary_request(
        &mut owner,
        [
            0,
            0,
            0,
            0, // map id
            2,
            6,
            4,           // outbound, l4 proto, ip version
            0x01 | 0x04, // alive + dryrun, no is-init
        ],
    );
    assert_eq!(response[0], 0);
    assert_eq!(response[1], 0);
    assert_eq!(response[2], 0);
    assert_eq!(response[3], 0);
    assert_eq!(
        u32::from_le_bytes([response[4], response[5], response[6], response[7]]),
        0
    );
    assert!(owner.state_owner().state().is_empty());
}

#[test]
pub(super) fn connectivity_map_serve_reports_malformed_requests() {
    let mut owner = dae_runtime_control::OutboundConnectivityMapOwner::default();
    let response = handle_connectivity_map_serve_line(&mut owner, "{bad-json");
    let json: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(json["status"].as_str().unwrap(), "error");
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("bad connectivity-map request")
    );
}

#[test]
fn domain_routing_map_serve_reports_malformed_requests() {
    let response = handle_domain_routing_map_serve_line("{bad-json");
    let json: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(json["status"].as_str().unwrap(), "error");
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("bad domain-routing-map request")
    );
}

#[test]
fn domain_routing_map_owner_serve_reports_malformed_requests() {
    let mut owner = dae_runtime_control::DomainRoutingOwner::default();
    let response = handle_domain_routing_map_owner_serve_line(&mut owner, "{bad-json");
    let json: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(json["status"].as_str().unwrap(), "error");
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("bad domain-routing-map owner request")
    );
}
