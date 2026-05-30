use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use super::{ProductChainRecertificationOptions, path_string};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProductChainTopologyKind {
    Daed2Wing,
    StandaloneDaeWing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProductChainTopology {
    pub(super) kind: ProductChainTopologyKind,
    pub(super) dae_core_repo: PathBuf,
}

impl ProductChainTopology {
    pub(super) fn chain_name(&self) -> &'static str {
        match self.kind {
            ProductChainTopologyKind::Daed2Wing => "daed2.0-web-wing-daecore",
            ProductChainTopologyKind::StandaloneDaeWing => "standalone-dae-wing",
        }
    }

    pub(super) fn wing_repo_label(&self) -> &'static str {
        match self.kind {
            ProductChainTopologyKind::Daed2Wing => "daed-wing",
            ProductChainTopologyKind::StandaloneDaeWing => "dae-wing",
        }
    }

    fn source_contract_shape(&self) -> &'static str {
        match self.kind {
            ProductChainTopologyKind::Daed2Wing => "engine-default-direct",
            ProductChainTopologyKind::StandaloneDaeWing => {
                "runtime-service-port-or-engine-default-direct"
            }
        }
    }

    pub(super) fn as_json(&self, dae_wing_repo: &Path, daed_repo: &Path) -> Value {
        json!({
            "chain": self.chain_name(),
            "daed_repo": path_string(daed_repo),
            "wing_repo": path_string(dae_wing_repo),
            "dae_core_repo": path_string(&self.dae_core_repo),
            "standalone_dae_wing_repo_used": self.kind == ProductChainTopologyKind::StandaloneDaeWing,
            "daed2_wing_repo_used": self.kind == ProductChainTopologyKind::Daed2Wing,
            "source_contract_shape": self.source_contract_shape(),
            "web_api_base_path": "/api",
        })
    }
}

pub(super) fn product_chain_topology(
    options: &ProductChainRecertificationOptions,
) -> ProductChainTopology {
    let daed_wing_repo = options.daed_repo.join("wing");
    let kind = if options.dae_wing_repo == daed_wing_repo {
        ProductChainTopologyKind::Daed2Wing
    } else {
        ProductChainTopologyKind::StandaloneDaeWing
    };
    ProductChainTopology {
        kind,
        dae_core_repo: options.dae_wing_repo.join("dae-core"),
    }
}
