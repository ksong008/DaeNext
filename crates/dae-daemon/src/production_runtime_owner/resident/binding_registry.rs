use super::*;
use std::collections::BTreeSet;

mod monitor;
mod observe;
mod parse;
#[cfg(test)]
mod tests;

pub(super) use monitor::ResidentDatapathBindingMonitor;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResidentTcBindingBackend {
    Tcx,
    TcNetlink,
}

impl ResidentTcBindingBackend {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "tcx" => Ok(Self::Tcx),
            "tc_netlink" => Ok(Self::TcNetlink),
            other => Err(format!(
                "resident binding registry does not admit backend {other:?} as a native TC binding"
            )),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Tcx => "tcx",
            Self::TcNetlink => "tc_netlink",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResidentDatapathBindingRole {
    PeerIngress,
    CoreLanIngress,
    HostIngress,
    LanIngress,
    LanEgress,
    WanIngress,
    WanEgress,
}

impl ResidentDatapathBindingRole {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "peer_ingress" => Ok(Self::PeerIngress),
            "lan_ingress" => Ok(Self::CoreLanIngress),
            "host_ingress" => Ok(Self::HostIngress),
            "resident_lan_ingress" => Ok(Self::LanIngress),
            "lan_egress" => Ok(Self::LanEgress),
            "wan_ingress" => Ok(Self::WanIngress),
            "wan_egress" => Ok(Self::WanEgress),
            other => Err(format!(
                "resident binding registry received unknown functional role {other:?}"
            )),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::PeerIngress => "peer-ingress",
            Self::CoreLanIngress => "core-lan-ingress",
            Self::HostIngress => "host-ingress",
            Self::LanIngress => "lan-ingress",
            Self::LanEgress => "lan-egress",
            Self::WanIngress => "wan-ingress",
            Self::WanEgress => "wan-egress",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResidentTcBinding {
    role: ResidentDatapathBindingRole,
    backend: ResidentTcBindingBackend,
    interface: String,
    ifindex: u32,
    netns: Option<String>,
    direction: dae_ebpf_support::TcAttachDirection,
    program_id: u32,
    program_name: String,
    program_tag: String,
    priority: u16,
    handle: u32,
    tcx_order: String,
    tcx_anchor_relation: Option<String>,
    tcx_anchor_program_id: Option<u32>,
    foreign_program_order_before: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResidentCgroupBinding {
    role: String,
    cgroup_path: PathBuf,
    attach_type: u32,
    program_id: u32,
    program_name: String,
    program_tag: String,
    attach_mode: String,
    foreign_program_ids_before: BTreeSet<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentDatapathBindingRegistry {
    generation: u64,
    owner_process_id: u32,
    tc: Vec<ResidentTcBinding>,
    cgroup: Vec<ResidentCgroupBinding>,
}

impl ResidentDatapathBindingRegistry {
    pub(super) fn empty(generation: u64) -> Self {
        Self {
            generation,
            owner_process_id: std::process::id(),
            tc: Vec::new(),
            cgroup: Vec::new(),
        }
    }

    pub(super) fn from_startup_steps(generation: u64, steps: &[Value]) -> Result<Self, String> {
        parse::registry_from_startup_steps(generation, steps)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.tc.is_empty() && self.cgroup.is_empty()
    }

    pub(super) fn active_postflight(&self) -> Value {
        observe::active_postflight(self)
    }

    pub(super) fn cleanup_postflight(&self) -> Value {
        observe::cleanup_postflight(self)
    }

    pub(super) fn to_value(&self) -> Value {
        json!({
            "schemaVersion": 1,
            "generation": self.generation,
            "ownershipToken": {
                "processId": self.owner_process_id,
                "generation": self.generation,
            },
            "bindingCount": self.tc.len() + self.cgroup.len(),
            "tcBindings": self.tc.iter().map(tc_binding_value).collect::<Vec<_>>(),
            "cgroupBindings": self.cgroup.iter().map(cgroup_binding_value).collect::<Vec<_>>(),
        })
    }
}

fn tc_binding_value(binding: &ResidentTcBinding) -> Value {
    json!({
        "role": binding.role.as_str(),
        "backend": binding.backend.as_str(),
        "interface": binding.interface,
        "ifindex": binding.ifindex,
        "netns": binding.netns,
        "direction": binding.direction.as_str(),
        "programId": binding.program_id,
        "programName": binding.program_name,
        "programTag": binding.program_tag,
        "priority": binding.priority,
        "handle": binding.handle,
        "tcxOrder": binding.tcx_order,
        "tcxAnchor": binding.tcx_anchor_relation.as_ref().map(|relation| json!({
            "relation": relation,
            "programId": binding.tcx_anchor_program_id,
        })),
        "foreignProgramOrderBefore": binding.foreign_program_order_before,
    })
}

fn cgroup_binding_value(binding: &ResidentCgroupBinding) -> Value {
    json!({
        "role": binding.role,
        "backend": "cgroup-bpf-link",
        "cgroupPath": path_string(&binding.cgroup_path),
        "attachType": binding.attach_type,
        "programId": binding.program_id,
        "programName": binding.program_name,
        "programTag": binding.program_tag,
        "attachMode": binding.attach_mode,
        "foreignProgramIdsBefore": binding.foreign_program_ids_before,
    })
}
