use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use super::topology::{ProductChainTopology, ProductChainTopologyKind};
use super::{ProductChainRecertificationOptions, path_string};

pub(super) fn go_mod_dependency_boundary_json(
    options: &ProductChainRecertificationOptions,
    topology: &ProductChainTopology,
) -> Value {
    let root = go_mod_file_dependency_boundary_json(
        &options.go_mod_file,
        false,
        &options.dae_repo,
        &options.outbound_repo,
        &options.quic_go_repo,
    );
    let root_preserved = root["outbound_quic_go_dependency_boundary_preserved"]
        .as_bool()
        .unwrap_or(false);
    if topology.kind == ProductChainTopologyKind::StandaloneDaeWing {
        return json!({
            "status": if root_preserved { "pass" } else { "fail" },
            "topology": topology.chain_name(),
            "path": path_string(&options.go_mod_file),
            "root": root,
            "outbound_quic_go_dependency_boundary_preserved": root_preserved,
        });
    }

    let wing = go_mod_file_dependency_boundary_json(
        &options.dae_wing_repo.join("go.mod"),
        true,
        &options.dae_repo,
        &options.outbound_repo,
        &options.quic_go_repo,
    );
    let dae_core = go_mod_file_dependency_boundary_json(
        &topology.dae_core_repo.join("go.mod"),
        false,
        &options.dae_repo,
        &options.outbound_repo,
        &options.quic_go_repo,
    );
    let wing_preserved = wing["outbound_quic_go_dependency_boundary_preserved"]
        .as_bool()
        .unwrap_or(false)
        && wing["dae_core_replace_preserved"]
            .as_bool()
            .unwrap_or(false);
    let dae_core_preserved = dae_core["outbound_quic_go_dependency_boundary_preserved"]
        .as_bool()
        .unwrap_or(false);
    let preserved = root_preserved && wing_preserved && dae_core_preserved;
    json!({
        "status": if preserved { "pass" } else { "fail" },
        "topology": topology.chain_name(),
        "path": path_string(&options.go_mod_file),
        "root": root,
        "wing": wing,
        "dae_core": dae_core,
        "outbound_quic_go_dependency_boundary_preserved": preserved,
    })
}

fn go_mod_file_dependency_boundary_json(
    path: &Path,
    require_dae_core_replace: bool,
    dae_repo: &Path,
    outbound_repo: &Path,
    quic_go_repo: &Path,
) -> Value {
    let Ok(text) = fs::read_to_string(path) else {
        return json!({
            "status": "fail",
            "path": path_string(path),
            "error": "go.mod could not be read",
            "dae_core_replace_preserved": false,
            "outbound_quic_go_dependency_boundary_preserved": false,
        });
    };
    let dae_replace = dae_dependency_replace_target(&text, dae_repo);
    let outbound_replace = dependency_replace_target(
        &text,
        "github.com/daeuniverse/outbound",
        "github.com/ksong008/outbound",
        outbound_repo,
    );
    let quic_go_replace = dependency_replace_target(
        &text,
        "github.com/daeuniverse/quic-go",
        "github.com/ksong008/quic-go",
        quic_go_repo,
    );
    let dae_core_replace_preserved = !require_dae_core_replace || dae_replace.preserved;
    let preserved =
        dae_core_replace_preserved && outbound_replace.preserved && quic_go_replace.preserved;
    json!({
        "status": if preserved { "pass" } else { "fail" },
        "path": path_string(path),
        "dae_core_replace_required": require_dae_core_replace,
        "dae_core_replace_preserved": dae_core_replace_preserved,
        "dae_core_replace_target": dae_replace.target,
        "dae_core_embedded_replace_preserved": dae_replace.embedded_preserved,
        "dae_core_local_repo_replace_preserved": dae_replace.local_preserved,
        "outbound_replace_preserved": outbound_replace.preserved,
        "outbound_replace_target": outbound_replace.target,
        "outbound_local_replace_preserved": outbound_replace.local_preserved,
        "outbound_remote_replace_preserved": outbound_replace.remote_preserved,
        "quic_go_replace_preserved": quic_go_replace.preserved,
        "quic_go_replace_target": quic_go_replace.target,
        "quic_go_local_replace_preserved": quic_go_replace.local_preserved,
        "quic_go_remote_replace_preserved": quic_go_replace.remote_preserved,
        "outbound_quic_go_still_required": true,
        "outbound_quic_go_dependency_boundary_preserved": preserved,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DaeReplaceTarget {
    preserved: bool,
    embedded_preserved: bool,
    local_preserved: bool,
    target: &'static str,
}

fn dae_dependency_replace_target(text: &str, dae_repo: &Path) -> DaeReplaceTarget {
    let embedded_preserved = text.contains("replace github.com/daeuniverse/dae => ./dae-core");
    let local_preserved = text.contains(&format!(
        "replace github.com/daeuniverse/dae => {}",
        path_string(dae_repo)
    ));
    let target = match (embedded_preserved, local_preserved) {
        (true, _) => "embedded",
        (false, true) => "local",
        (false, false) => "missing",
    };
    DaeReplaceTarget {
        preserved: embedded_preserved || local_preserved,
        embedded_preserved,
        local_preserved,
        target,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DependencyReplaceTarget {
    preserved: bool,
    local_preserved: bool,
    remote_preserved: bool,
    target: &'static str,
}

fn dependency_replace_target(
    text: &str,
    module: &str,
    remote_module: &str,
    local_repo: &Path,
) -> DependencyReplaceTarget {
    let remote_preserved = text.contains(&format!("replace {module} => {remote_module}"));
    let local_preserved =
        text.contains(&format!("replace {module} => {}", path_string(local_repo)));
    let target = match (local_preserved, remote_preserved) {
        (true, _) => "local",
        (false, true) => "remote",
        (false, false) => "missing",
    };
    DependencyReplaceTarget {
        preserved: local_preserved || remote_preserved,
        local_preserved,
        remote_preserved,
        target,
    }
}
