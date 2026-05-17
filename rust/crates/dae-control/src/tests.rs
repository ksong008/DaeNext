use serde_json::Value;

use crate::*;

#[test]
fn domain_routing_owner_tracker_matches_golden_fixture() {
    let fixture = load("control/domain_routing_tracker/basic.json");
    let mut tracker = DomainRoutingTracker::default();
    let steps = fixture["steps"].as_array().unwrap();

    tracker.sync_owner(
        "q=a.example|type=A|class=IN",
        DomainRoutingOwnerSnapshot::new(&[3], &["192.0.2.1", "2001:db8::1"]),
    );
    assert_domain_view(&tracker.view("after_owner_a"), &steps[0]);

    tracker.sync_owner(
        "q=b.example|type=A|class=IN",
        DomainRoutingOwnerSnapshot::new(&[4], &["192.0.2.1", "198.51.100.7"]),
    );
    assert_domain_view(&tracker.view("after_owner_b"), &steps[1]);

    tracker.sync_owner(
        "q=a.example|type=A|class=IN",
        DomainRoutingOwnerSnapshot::default(),
    );
    assert_domain_view(&tracker.view("after_remove_owner_a"), &steps[2]);

    tracker.sync_owner(
        "q=b.example|type=A|class=IN",
        DomainRoutingOwnerSnapshot::new(&[16], &["198.51.100.7", "2001:db8::2"]),
    );
    assert_domain_view(&tracker.view("after_replace_owner_b"), &steps[3]);
}

#[test]
fn reload_bpf_ownership_matches_golden_fixture() {
    let fixture = load("control/reload_bpf_ownership/eject_inject.json");
    let steps = fixture["steps"].as_array().unwrap();
    let mut flip = CoreFlip::default();
    let mut fresh = ReloadCoreState::new(false, &mut flip);
    assert_reload_state("fresh_init", &fresh, &steps[0]);
    fresh.eject_bpf();
    assert_reload_state("after_eject", &fresh, &steps[1]);
    fresh.inject_bpf();
    assert_reload_state("after_inject", &fresh, &steps[2]);

    let mut reload = ReloadCoreState::new(true, &mut flip);
    assert_reload_state("reload_init", &reload, &steps[3]);
    reload.eject_bpf();
    assert_reload_state("reload_after_eject", &reload, &steps[4]);
}

#[test]
fn runtime_dependency_plan_keeps_stage7_env_gates() {
    let plan = RuntimeDependencyPlan::stage7_default();
    let gates = plan.gates.iter().map(|gate| gate.name).collect::<Vec<_>>();
    assert_eq!(
        gates,
        vec![
            "root",
            "bpffs",
            "netns_permission",
            "memlock",
            "kernel_feature_version"
        ]
    );
}

fn assert_domain_view(got: &DomainRoutingView, expected: &Value) {
    assert_eq!(got.step, expected["step"].as_str().unwrap());
    assert_eq!(got.owners, string_array(&expected["owners"]));
    let expected_ips = expected["ips"].as_array().unwrap();
    assert_eq!(got.ips.len(), expected_ips.len());
    for (got, expected) in got.ips.iter().zip(expected_ips) {
        assert_eq!(got.ip, expected["ip"].as_str().unwrap());
        assert_eq!(got.owners, string_array(&expected["owners"]));
        assert_eq!(
            got.merged,
            expected["merged"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_u64().unwrap() as u32)
                .collect::<Vec<_>>()
        );
        assert_eq!(got.present, expected["present"].as_bool().unwrap());
    }
}

fn assert_reload_state(step: &str, got: &ReloadCoreState, expected: &Value) {
    assert_eq!(step, expected["step"].as_str().unwrap());
    assert_eq!(got.is_reload, expected["is_reload"].as_bool().unwrap());
    assert_eq!(got.bpf_ejected, expected["bpf_ejected"].as_bool().unwrap());
    assert_eq!(
        got.defer_func_count,
        expected["defer_func_count"].as_u64().unwrap() as usize
    );
    assert_eq!(got.flip, expected["flip"].as_u64().unwrap() as u8);
}

fn string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_owned())
        .collect()
}

fn load(path: &str) -> Value {
    dae_golden::load_json(path).unwrap()
}
