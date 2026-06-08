use super::*;
pub(super) fn sample_routing_state() -> Result<RoutingRuleState, String> {
    let prefixes = vec![
        IpPrefix::parse("203.0.113.0/24")
            .map_err(|err| format!("sample routing prefix parse failed: {err}"))?,
    ];
    Ok(RoutingRuleState::new(
        vec![RoutingNativeRule::new(
            RoutingNativeMatch::IpSet(prefixes),
            OutboundIndex::USER_DEFINED_MIN,
        )],
        RoutingNativeFallback::new(OutboundIndex::DIRECT),
        LpmMapTemplate::default(),
    ))
}

pub(super) fn sample_userspace_routing_outbound() -> Result<OutboundIndex, String> {
    let fixture = json!({
        "domain_sets": [{
            "bit": 0,
            "key": "suffix",
            "patterns": ["example.com"]
        }],
        "lpm_sets": [],
        "matches": [
            {
                "type": "domain_set",
                "outbound": format!("user:{}", OutboundIndex::USER_DEFINED_MIN.value())
            },
            {
                "type": "fallback",
                "outbound": "direct"
            }
        ]
    });
    let matcher = RoutingMatcher::from_fixture_value(&fixture)
        .map_err(|err| format!("rust native userspace routing fixture failed: {err}"))?;
    matcher
        .match_query(&Query::tcp(
            "203.0.113.10".parse().unwrap(),
            443,
            "www.example.com",
        ))
        .map_err(|err| format!("rust native userspace routing match failed: {err}"))
}

pub(super) fn sample_connectivity_event() -> ConnectivityEvent {
    ConnectivityEvent {
        key: ConnectivityKey {
            outbound: OutboundIndex::USER_DEFINED_MIN.value(),
            l4proto: 6,
            ipversion: 4,
        },
        alive: true,
        is_init: false,
        dryrun: false,
    }
}
