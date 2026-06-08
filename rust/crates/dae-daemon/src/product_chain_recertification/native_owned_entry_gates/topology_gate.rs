use super::*;
pub(super) fn c0_product_chain_topology_lock(
    options: &ProductChainRecertificationOptions,
    topology: &Value,
) -> Value {
    let expected_wing_repo = options.daed_repo.join("wing");
    let submodule_build_truth_recorded = options.dae_wing_repo == expected_wing_repo;
    let submodule_status = git_repo_brief_json(&options.dae_wing_repo);
    let sibling_repo = sibling_wing_repo(&options.daed_repo);
    let sibling_present = sibling_repo.is_dir();
    let sibling_status = if sibling_present {
        git_repo_brief_json(&sibling_repo)
    } else {
        json!({
            "path": path_string(&sibling_repo),
            "exists": false,
            "git_status_available": false,
            "head": Value::Null,
            "dirty": false,
        })
    };
    let submodule_head = submodule_status["head"].as_str();
    let sibling_head = sibling_status["head"].as_str();
    let heads_match = sibling_present
        && submodule_head.is_some()
        && sibling_head.is_some()
        && submodule_head == sibling_head;
    let submodule_dirty = submodule_status["dirty"].as_bool().unwrap_or(false);
    let sibling_dirty = sibling_status["dirty"].as_bool().unwrap_or(false);
    let submodule_matches_sibling_repo =
        !sibling_present || (heads_match && !submodule_dirty && !sibling_dirty);
    let product_chain_topology_locked =
        submodule_build_truth_recorded && submodule_matches_sibling_repo;

    let mut blockers = Vec::new();
    if !submodule_build_truth_recorded {
        blockers.push(format!(
            "C0 product-chain topology is not locked to daed/wing submodule: expected {}, got {}",
            path_string(&expected_wing_repo),
            path_string(&options.dae_wing_repo)
        ));
    }
    if sibling_present && !heads_match {
        blockers.push(format!(
            "C0 daed/wing submodule HEAD does not match sibling wing repo: submodule={}, sibling={}",
            submodule_head.unwrap_or("unknown"),
            sibling_head.unwrap_or("unknown")
        ));
    }
    if sibling_present && (submodule_dirty || sibling_dirty) {
        blockers.push(format!(
            "C0 daed/wing submodule or sibling wing repo is dirty: submodule_dirty={submodule_dirty}, sibling_dirty={sibling_dirty}"
        ));
    }

    json!({
        "name": "product-chain-topology-lock",
        "status": if product_chain_topology_locked { "pass" } else { "blocked" },
        "chain": "daed-daex-align -> daed/wing submodule -> dae-daex-align -> outbound-daex-align -> quic-go-daex-align",
        "build_truth": "daed/wing-submodule",
        "product_chain_topology_locked": product_chain_topology_locked,
        "submodule_build_truth_recorded": submodule_build_truth_recorded,
        "expected_wing_repo": path_string(&expected_wing_repo),
        "actual_wing_repo": path_string(&options.dae_wing_repo),
        "daed2_wing_repo_used": topology["daed2_wing_repo_used"].clone(),
        "standalone_dae_wing_repo_used": topology["standalone_dae_wing_repo_used"].clone(),
        "submodule_status": submodule_status,
        "sibling_repo": path_string(&sibling_repo),
        "sibling_present": sibling_present,
        "sibling_status": sibling_status,
        "submodule_matches_sibling_repo": submodule_matches_sibling_repo,
        "quic_go_path": path_string(&options.quic_go_repo),
        "blockers": blockers,
    })
}

pub(super) fn sibling_wing_repo(daed_repo: &Path) -> PathBuf {
    daed_repo
        .parent()
        .and_then(Path::parent)
        .map(|project_root| project_root.join("dae-wing-daex-align"))
        .unwrap_or_else(|| PathBuf::from("/root/project/dae-wing-daex-align"))
}
