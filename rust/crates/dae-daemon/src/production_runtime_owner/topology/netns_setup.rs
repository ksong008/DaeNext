use super::*;
pub(crate) fn setup_production_topology(
    steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
) -> bool {
    setup_link_pair_with_auto_fallback(
        steps,
        "production",
        PRODUCTION_HOST_IFACE,
        PRODUCTION_PEER_IFACE,
        options.netns_link_mode,
        |steps, mode| setup_production_topology_with_link_mode(steps, options, mode),
        |steps| {
            cleanup_partial_link_setup(
                steps,
                "production",
                Some(PRODUCTION_NETNS),
                PRODUCTION_HOST_IFACE,
                PRODUCTION_PEER_IFACE,
            );
        },
    )
}

pub(crate) fn setup_production_topology_with_link_mode(
    steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
    mode: NetnsLinkMode,
) -> bool {
    if !create_link_pair(
        steps,
        "production",
        PRODUCTION_HOST_IFACE,
        PRODUCTION_PEER_IFACE,
        mode,
    ) {
        return false;
    }
    if !run_step(
        steps,
        "create-production-netns",
        CommandSpec::new("ip", ["netns", "add", PRODUCTION_NETNS]),
    ) {
        return false;
    }
    if !assign_production_netns_id(steps, options.dae_netns_id) {
        return false;
    }
    if !run_step(
        steps,
        "move-production-peer-into-netns",
        CommandSpec::new(
            "ip",
            [
                "link",
                "set",
                PRODUCTION_PEER_IFACE,
                "netns",
                PRODUCTION_NETNS,
            ],
        ),
    ) {
        return false;
    }
    if !run_step(
        steps,
        "bring-production-host-link-up",
        CommandSpec::new("ip", ["link", "set", PRODUCTION_HOST_IFACE, "up"]),
    ) {
        return false;
    }
    if !run_step(
        steps,
        "bring-production-netns-loopback-up",
        CommandSpec::new(
            "ip",
            [
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "link",
                "set",
                "lo",
                "up",
            ],
        ),
    ) {
        return false;
    }
    run_step(
        steps,
        "bring-production-peer-link-up",
        CommandSpec::new(
            "ip",
            [
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "link",
                "set",
                PRODUCTION_PEER_IFACE,
                "up",
            ],
        ),
    )
}

pub(crate) fn assign_production_netns_id(
    steps: &mut Vec<Value>,
    configured_dae_netns_id: u32,
) -> bool {
    let before_step = run_observation_step(
        steps,
        "list-production-netns-id-before-auto",
        CommandSpec::new("ip", ["netns", "list-id"]),
    );
    let before = parse_used_netns_ids(before_step["stdout"].as_str().unwrap_or_default());
    let assign_step = run_observation_step(
        steps,
        "assign-production-netns-id-auto",
        CommandSpec::new("ip", ["netns", "set", PRODUCTION_NETNS, "auto"]),
    );
    if assign_step["status"].as_str() != Some("pass") {
        steps.push(json!({
            "name": "assign-production-netns-id-summary",
            "status": "fail",
            "netns": PRODUCTION_NETNS,
            "configured_dae_netns_id": configured_dae_netns_id,
            "strategy": "auto",
            "reason": "kernel auto netns id assignment failed",
        }));
        return false;
    }
    let after_step = run_observation_step(
        steps,
        "list-production-netns-id-after-auto",
        CommandSpec::new("ip", ["netns", "list-id"]),
    );
    let after = parse_used_netns_ids(after_step["stdout"].as_str().unwrap_or_default());
    let Some(effective_id) = new_netns_id_after_auto(&before, &after) else {
        steps.push(json!({
            "name": "assign-production-netns-id-summary",
            "status": "fail",
            "netns": PRODUCTION_NETNS,
            "configured_dae_netns_id": configured_dae_netns_id,
            "strategy": "auto",
            "reason": "kernel auto netns id assignment succeeded but the effective nsid could not be determined from ip netns list-id",
        }));
        return false;
    };
    steps.push(json!({
        "name": "assign-production-netns-id-summary",
        "status": "pass",
        "netns": PRODUCTION_NETNS,
        "configured_dae_netns_id": configured_dae_netns_id,
        "effective_dae_netns_id": effective_id,
        "strategy": "auto",
        "reason": "dae netns id was assigned by the kernel and will be propagated into BPF PARAM, matching Go's runtime netns id behavior",
    }));
    true
}

pub(crate) fn parse_used_netns_ids(stdout: &str) -> BTreeSet<u32> {
    stdout
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("nsid ")?;
            rest.split_whitespace().next()?.parse::<u32>().ok()
        })
        .collect()
}

pub(crate) fn new_netns_id_after_auto(
    before: &BTreeSet<u32>,
    after: &BTreeSet<u32>,
) -> Option<u32> {
    after.difference(before).next().copied()
}

pub(crate) fn effective_dae_netns_id(steps: &[Value], requested_dae_netns_id: u32) -> u32 {
    steps
        .iter()
        .rev()
        .find(|step| {
            step["name"].as_str() == Some("assign-production-netns-id-summary")
                && step["status"].as_str() == Some("pass")
        })
        .and_then(|step| step["effective_dae_netns_id"].as_u64())
        .and_then(|id| u32::try_from(id).ok())
        .unwrap_or(requested_dae_netns_id)
}
