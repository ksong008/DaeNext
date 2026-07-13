use super::*;
use crate::production_runtime_owner::host_ops::{HostOpSpec, HostOps};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn active_postflight(registry: &ResidentDatapathBindingRegistry) -> Value {
    postflight(registry, true)
}

pub(super) fn cleanup_postflight(registry: &ResidentDatapathBindingRegistry) -> Value {
    postflight(registry, false)
}

fn postflight(registry: &ResidentDatapathBindingRegistry, expected_present: bool) -> Value {
    if registry.is_empty() {
        return json!({
            "schemaVersion": 1,
            "status": "pass",
            "generation": registry.generation,
            "expectedState": expected_state(expected_present),
            "skipped": true,
            "reason": "no native TCX, TC netlink, or cgroup bindings were registered",
            "checks": [],
        });
    }

    let owned_tc_ids = registry
        .tc
        .iter()
        .map(|binding| binding.program_id)
        .collect::<BTreeSet<_>>();
    let mut tcx_cache = BTreeMap::new();
    let mut cgroup_cache = BTreeMap::new();
    let mut checks = Vec::with_capacity(registry.tc.len() + registry.cgroup.len());
    for binding in &registry.tc {
        checks.push(match binding.backend {
            ResidentTcBindingBackend::Tcx => {
                observe_tcx_binding(binding, &owned_tc_ids, expected_present, &mut tcx_cache)
            }
            ResidentTcBindingBackend::TcNetlink => {
                observe_tc_netlink_binding(binding, expected_present)
            }
        });
    }
    for binding in &registry.cgroup {
        checks.push(observe_cgroup_binding(
            binding,
            expected_present,
            &mut cgroup_cache,
        ));
    }
    let failed = checks
        .iter()
        .filter(|check| check["status"].as_str() != Some("pass"))
        .count();
    json!({
        "schemaVersion": 1,
        "status": if failed == 0 { "pass" } else { "fail" },
        "generation": registry.generation,
        "ownershipToken": {
            "processId": registry.owner_process_id,
            "generation": registry.generation,
        },
        "expectedState": expected_state(expected_present),
        "bindingCount": checks.len(),
        "failedCount": failed,
        "checks": checks,
    })
}

fn observe_tcx_binding(
    binding: &ResidentTcBinding,
    owned_ids: &BTreeSet<u32>,
    expected_present: bool,
    cache: &mut BTreeMap<String, Result<dae_ebpf_support::AyaTcxBindingSnapshot, String>>,
) -> Value {
    let target = tc_target(binding);
    let cache_key = format!(
        "{}|{}|{}",
        binding.netns.as_deref().unwrap_or("host"),
        binding.interface,
        binding.direction.as_str()
    );
    let observed = cache
        .entry(cache_key)
        .or_insert_with(|| dae_ebpf_support::query_aya_tcx_binding(&target));
    let Ok(observed) = observed else {
        return observation_error_value(
            "tcx",
            binding.role.as_str(),
            &binding.interface,
            expected_present,
            observed.as_ref().unwrap_err(),
        );
    };
    let order = observed
        .program_order
        .iter()
        .map(|program| program.id)
        .collect::<Vec<_>>();
    let own_positions = order
        .iter()
        .enumerate()
        .filter_map(|(index, id)| (*id == binding.program_id).then_some(index))
        .collect::<Vec<_>>();
    let present = own_positions.len() == 1;
    let identity_matches = observed
        .program_order
        .iter()
        .find(|program| program.id == binding.program_id)
        .is_none_or(|program| program.tag == binding.program_tag);
    let ifindex_matches = observed.ifindex == binding.ifindex;
    let order_matches = if expected_present && present {
        tcx_requested_order_matches(binding, own_positions[0], order.len())
            && tcx_anchor_matches(binding, own_positions[0], &order)
    } else {
        true
    };
    let foreign_order = order
        .iter()
        .copied()
        .filter(|id| !owned_ids.contains(id))
        .collect::<Vec<_>>();
    let expected_foreign = binding
        .foreign_program_order_before
        .iter()
        .copied()
        .filter(|id| !owned_ids.contains(id))
        .collect::<Vec<_>>();
    let foreign_preserved = ordered_subsequence(&expected_foreign, &foreign_order);
    let state_matches = present == expected_present;
    let pass = state_matches
        && (!expected_present
            || (identity_matches && ifindex_matches && order_matches && foreign_preserved));
    json!({
        "status": if pass { "pass" } else { "fail" },
        "backend": "tcx",
        "role": binding.role.as_str(),
        "interface": binding.interface,
        "netns": binding.netns,
        "direction": binding.direction.as_str(),
        "expectedPresent": expected_present,
        "observedPresent": present,
        "expectedIfindex": binding.ifindex,
        "observedIfindex": observed.ifindex,
        "ifindexMatches": ifindex_matches,
        "programId": binding.program_id,
        "programTag": binding.program_tag,
        "identityMatches": identity_matches,
        "observedProgramOrder": order,
        "requestedOrder": binding.tcx_order,
        "orderMatches": order_matches,
        "foreignProgramOrderBefore": expected_foreign,
        "foreignProgramOrderObserved": foreign_order,
        "foreignProgramOrderPreserved": foreign_preserved,
        "queryRevision": observed.revision,
    })
}

fn observe_tc_netlink_binding(binding: &ResidentTcBinding, expected_present: bool) -> Value {
    let target = tc_target(binding);
    let ifindex = dae_ebpf_support::query_aya_interface_index(&target);
    let command = target.filter_show_command(false);
    let result = HostOps::observe(HostOpSpec::new(command.program, command.args));
    let step = result.to_step_json();
    let stdout = step["stdout"].as_str().unwrap_or_default();
    let present = tc_output_matches_binding(stdout, binding);
    let ifindex_matches = ifindex.as_ref().ok() == Some(&binding.ifindex);
    let state_matches = present == expected_present;
    let pass = result.passed() && state_matches && (!expected_present || ifindex_matches);
    json!({
        "status": if pass { "pass" } else { "fail" },
        "backend": "tc_netlink",
        "role": binding.role.as_str(),
        "interface": binding.interface,
        "netns": binding.netns,
        "direction": binding.direction.as_str(),
        "expectedPresent": expected_present,
        "observedPresent": present,
        "expectedIfindex": binding.ifindex,
        "observedIfindex": ifindex.ok(),
        "ifindexMatches": ifindex_matches,
        "programId": binding.program_id,
        "priority": binding.priority,
        "handle": binding.handle,
        "observation": step,
    })
}

fn observe_cgroup_binding(
    binding: &ResidentCgroupBinding,
    expected_present: bool,
    cache: &mut BTreeMap<PathBuf, Result<dae_ebpf_support::AyaCgroupAttachPreflightReport, String>>,
) -> Value {
    let observed = cache
        .entry(binding.cgroup_path.clone())
        .or_insert_with(|| dae_ebpf_support::preflight_aya_cgroup_programs(&binding.cgroup_path));
    let Ok(observed) = observed else {
        return observation_error_value(
            "cgroup-bpf-link",
            &binding.role,
            &path_string(&binding.cgroup_path),
            expected_present,
            observed.as_ref().unwrap_err(),
        );
    };
    let line = observed
        .lines
        .iter()
        .find(|line| line.attach_type == binding.attach_type);
    let programs = line
        .map(|line| &line.existing_programs[..])
        .unwrap_or_default();
    let own = programs
        .iter()
        .filter(|program| program.id == binding.program_id)
        .collect::<Vec<_>>();
    let present = own.len() == 1;
    let expected_kernel_name = dae_ebpf_support::truncated_bpf_name(&binding.program_name);
    let identity_matches = own.first().is_none_or(|program| {
        let name_matches = program.name.as_deref() == Some(binding.program_name.as_str())
            || program.name.as_deref() == Some(expected_kernel_name);
        name_matches && program.tag.as_deref() == Some(binding.program_tag.as_str())
    });
    let observed_ids = programs
        .iter()
        .map(|program| program.id)
        .collect::<BTreeSet<_>>();
    let foreign_preserved = binding.foreign_program_ids_before.is_subset(&observed_ids);
    let state_matches = present == expected_present;
    let pass = state_matches && (!expected_present || (identity_matches && foreign_preserved));
    json!({
        "status": if pass { "pass" } else { "fail" },
        "backend": "cgroup-bpf-link",
        "role": binding.role,
        "cgroupPath": path_string(&binding.cgroup_path),
        "attachType": binding.attach_type,
        "expectedPresent": expected_present,
        "observedPresent": present,
        "programId": binding.program_id,
        "programName": binding.program_name,
        "programTag": binding.program_tag,
        "identityMatches": identity_matches,
        "foreignProgramIdsBefore": binding.foreign_program_ids_before,
        "observedProgramIds": observed_ids,
        "foreignProgramsPreserved": foreign_preserved,
        "queryRevision": line.map(|line| line.revision),
    })
}

fn tc_target(binding: &ResidentTcBinding) -> dae_ebpf_support::TcAttachTarget {
    match &binding.netns {
        Some(netns) => dae_ebpf_support::TcAttachTarget::netns(
            netns.clone(),
            binding.interface.clone(),
            binding.direction,
        ),
        None => {
            dae_ebpf_support::TcAttachTarget::host(binding.interface.clone(), binding.direction)
        }
    }
}

pub(super) fn tcx_requested_order_matches(
    binding: &ResidentTcBinding,
    position: usize,
    len: usize,
) -> bool {
    match binding.tcx_order.as_str() {
        "first" => position == 0,
        "last" => position.saturating_add(1) == len,
        _ => false,
    }
}

pub(super) fn tcx_anchor_matches(
    binding: &ResidentTcBinding,
    position: usize,
    order: &[u32],
) -> bool {
    let (Some(relation), Some(anchor)) = (
        binding.tcx_anchor_relation.as_deref(),
        binding.tcx_anchor_program_id,
    ) else {
        return true;
    };
    let Some(anchor_position) = order.iter().position(|id| *id == anchor) else {
        return false;
    };
    match relation {
        "before" => position < anchor_position,
        "after" => position > anchor_position,
        _ => false,
    }
}

pub(super) fn tc_output_matches_binding(stdout: &str, binding: &ResidentTcBinding) -> bool {
    let pref = format!("pref {}", binding.priority);
    let id = format!("id {}", binding.program_id);
    let handle_hex = format!("0x{:x}", binding.handle);
    let handle_plain = format!("handle {:x}", binding.handle);
    stdout.lines().any(|line| {
        let normalized = line.split_whitespace().collect::<Vec<_>>().join(" ");
        normalized.contains(&pref)
            && normalized.contains(&id)
            && normalized.contains(&binding.program_tag)
            && (normalized.contains(&handle_hex) || normalized.contains(&handle_plain))
    })
}

pub(super) fn ordered_subsequence(expected: &[u32], observed: &[u32]) -> bool {
    let mut expected = expected.iter();
    let mut next = expected.next();
    for id in observed {
        if next == Some(id) {
            next = expected.next();
        }
    }
    next.is_none()
}

fn observation_error_value(
    backend: &str,
    role: &str,
    target: &str,
    expected_present: bool,
    error: &str,
) -> Value {
    json!({
        "status": "fail",
        "backend": backend,
        "role": role,
        "target": target,
        "expectedPresent": expected_present,
        "error": error,
    })
}

const fn expected_state(expected_present: bool) -> &'static str {
    if expected_present {
        "attached"
    } else {
        "detached"
    }
}
