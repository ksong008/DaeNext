use std::path::{Path, PathBuf};

#[cfg(feature = "native-ebpf")]
use std::collections::BTreeMap;

#[cfg(feature = "native-ebpf")]
use dae_datapath::{ACTIVE_TCP_LAN_FILTER_PREF, ACTIVE_TCP_LAN_HOST_IFACE};
use dae_ebpf_support::{
    AttachBackend, DaeParamInput, NativeBackendAdmissionEvidence, NativeBackendOptInDecision,
    NativeBackendOptInRequest, build_dae_param, native_backend_admission_report,
    native_backend_opt_in_decision, write_param_aware_object,
};
#[cfg(feature = "native-ebpf")]
use dae_ebpf_support::{
    TcAttachDirection, TcAttachTarget, TcBpfAttachSpec, TcNativeAttachSpec, tc_handle,
};
use serde_json::{Value, json};

use super::ProductionRuntimeOwnerOptions;
use super::command::{mac_string, path_string};
#[cfg(feature = "native-ebpf")]
use super::{FILTER_PREF, PRODUCTION_HOST_IFACE, PRODUCTION_NETNS, PRODUCTION_PEER_IFACE};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner) enum NativeEbpfAttachRole {
    PeerIngress,
    LanIngress,
    HostIngress,
}

impl NativeEbpfAttachRole {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PeerIngress => "peer_ingress",
            Self::LanIngress => "lan_ingress",
            Self::HostIngress => "host_ingress",
        }
    }

    const fn decision_step_name(self) -> &'static str {
        match self {
            Self::PeerIngress => "native-ebpf-peer-opt-in-decision",
            Self::LanIngress => "native-ebpf-lan-opt-in-decision",
            Self::HostIngress => "native-ebpf-host-opt-in-decision",
        }
    }

    const fn attach_step_name(self) -> &'static str {
        match self {
            Self::PeerIngress => "attach-production-dae0peer-native-ebpf-program",
            Self::LanIngress => "attach-lan-ingress-native-ebpf-program",
            Self::HostIngress => "attach-production-dae0-native-ebpf-program",
        }
    }
}

#[derive(Default)]
pub(in crate::production_runtime_owner) struct NativeEbpfRuntimeState {
    peer_attached: bool,
    lan_attached: bool,
    host_attached: bool,
    #[cfg(feature = "native-ebpf")]
    loaded: Option<dae_ebpf_support::AyaUserspaceLoadedObject>,
    #[cfg(feature = "native-ebpf")]
    loaded_map_ids: BTreeMap<String, u32>,
    #[cfg(feature = "native-ebpf")]
    pin_root: Option<PathBuf>,
}

impl std::fmt::Debug for NativeEbpfRuntimeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("NativeEbpfRuntimeState");
        debug
            .field("peer_attached", &self.peer_attached)
            .field("lan_attached", &self.lan_attached)
            .field("host_attached", &self.host_attached);
        #[cfg(feature = "native-ebpf")]
        debug
            .field("loaded", &self.loaded.is_some())
            .field("loaded_map_ids", &self.loaded_map_ids)
            .field("pin_root", &self.pin_root);
        debug.finish()
    }
}

impl NativeEbpfRuntimeState {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn peer_attached(&self) -> bool {
        self.peer_attached
    }

    pub(super) fn host_attached(&self) -> bool {
        self.host_attached
    }

    pub(in crate::production_runtime_owner) fn lan_attached(&self) -> bool {
        self.lan_attached
    }

    pub(in crate::production_runtime_owner) fn loaded_map_id(&self, name: &str) -> Option<u32> {
        #[cfg(feature = "native-ebpf")]
        {
            self.loaded_map_ids.get(name).copied()
        }
        #[cfg(not(feature = "native-ebpf"))]
        {
            let _ = name;
            None
        }
    }

    pub(super) fn reset(&mut self) {
        #[cfg(feature = "native-ebpf")]
        {
            self.loaded.take();
            self.loaded_map_ids.clear();
            if let Some(pin_root) = self.pin_root.take() {
                let _ = std::fs::remove_dir_all(pin_root);
            }
        }
        self.peer_attached = false;
        self.lan_attached = false;
        self.host_attached = false;
    }

    pub(in crate::production_runtime_owner) fn attach_program(
        &mut self,
        steps: &mut Vec<Value>,
        options: &ProductionRuntimeOwnerOptions,
        param_object: &Path,
        role: NativeEbpfAttachRole,
    ) -> Option<bool> {
        let decision = native_backend_runtime_decision(options);
        steps.push(json!({
            "name": role.decision_step_name(),
            "status": "pass",
            "role": role.as_str(),
            "decision": native_backend_opt_in_decision_json(&decision),
        }));
        if !decision.attempt_native_backend {
            return None;
        }
        let backend = decision.selected_backend?;
        match self.try_attach_program(options, param_object, role, backend) {
            Ok(report) => {
                match role {
                    NativeEbpfAttachRole::PeerIngress => self.peer_attached = true,
                    NativeEbpfAttachRole::LanIngress => self.lan_attached = true,
                    NativeEbpfAttachRole::HostIngress => self.host_attached = true,
                }
                steps.push(json!({
                    "name": role.attach_step_name(),
                    "status": "pass",
                    "role": role.as_str(),
                    "backend": backend.as_str(),
                    "native_attach": report,
                    "fallback_required": true,
                    "fallback_used": false,
                }));
                Some(true)
            }
            Err(err) => {
                steps.push(json!({
                    "name": role.attach_step_name(),
                    "status": "fail",
                    "role": role.as_str(),
                    "backend": backend.as_str(),
                    "stderr": err,
                    "fallback_required": true,
                    "fallback_used": true,
                }));
                Some(false)
            }
        }
    }

    pub(in crate::production_runtime_owner) fn attach_resident_lan_program(
        &mut self,
        steps: &mut Vec<Value>,
        options: &ProductionRuntimeOwnerOptions,
        param_object: &Path,
        iface: &str,
    ) -> Option<bool> {
        let decision = native_backend_runtime_decision(options);
        steps.push(json!({
            "name": format!("native-ebpf-resident-lan-opt-in-decision-{iface}"),
            "status": "pass",
            "role": "resident_lan_ingress",
            "interface": iface,
            "decision": native_backend_opt_in_decision_json(&decision),
        }));
        if !decision.attempt_native_backend {
            return None;
        }
        let backend = decision.selected_backend?;
        match self.try_attach_resident_lan_program(param_object, iface, backend) {
            Ok(report) => {
                self.lan_attached = true;
                steps.push(json!({
                    "name": format!("attach-resident-lan-ingress-native-ebpf-program-{iface}"),
                    "status": "pass",
                    "role": "resident_lan_ingress",
                    "interface": iface,
                    "backend": backend.as_str(),
                    "native_attach": report,
                    "fallback_required": true,
                    "fallback_used": false,
                }));
                Some(true)
            }
            Err(err) => {
                steps.push(json!({
                    "name": format!("attach-resident-lan-ingress-native-ebpf-program-{iface}"),
                    "status": "fail",
                    "role": "resident_lan_ingress",
                    "interface": iface,
                    "backend": backend.as_str(),
                    "stderr": err,
                    "fallback_required": true,
                    "fallback_used": true,
                }));
                Some(false)
            }
        }
    }

    #[cfg(not(feature = "native-ebpf"))]
    fn try_attach_program(
        &mut self,
        _options: &ProductionRuntimeOwnerOptions,
        _param_object: &Path,
        _role: NativeEbpfAttachRole,
        _backend: AttachBackend,
    ) -> Result<Value, String> {
        Err("native eBPF runtime feature is not compiled".to_owned())
    }

    #[cfg(feature = "native-ebpf")]
    fn try_attach_program(
        &mut self,
        _options: &ProductionRuntimeOwnerOptions,
        param_object: &Path,
        role: NativeEbpfAttachRole,
        backend: AttachBackend,
    ) -> Result<Value, String> {
        let spec = native_attach_spec(role, param_object);
        self.try_attach_spec(param_object, spec, backend)
    }

    #[cfg(not(feature = "native-ebpf"))]
    fn try_attach_resident_lan_program(
        &mut self,
        _param_object: &Path,
        _iface: &str,
        _backend: AttachBackend,
    ) -> Result<Value, String> {
        Err("native eBPF runtime feature is not compiled".to_owned())
    }

    #[cfg(feature = "native-ebpf")]
    fn try_attach_resident_lan_program(
        &mut self,
        param_object: &Path,
        iface: &str,
        backend: AttachBackend,
    ) -> Result<Value, String> {
        let object = path_string(param_object);
        let spec = TcBpfAttachSpec::new(
            TcAttachTarget::host(iface.to_owned(), TcAttachDirection::Ingress),
            ACTIVE_TCP_LAN_FILTER_PREF,
            object,
            "classifier/lan_ingress_l2",
        )
        .native_attach_spec("tproxy_lan_ingress_l2", 2, tc_handle(0x2023, 0b100));
        self.try_attach_spec(param_object, spec, backend)
    }

    #[cfg(feature = "native-ebpf")]
    fn try_attach_spec(
        &mut self,
        param_object: &Path,
        spec: TcNativeAttachSpec,
        backend: AttachBackend,
    ) -> Result<Value, String> {
        let loaded = self.ensure_loaded(param_object)?;
        let report = dae_ebpf_support::load_attach_aya_sched_classifier(loaded, &spec, backend)?;
        Ok(json!({
            "program_name": report.program_name,
            "iface": report.iface,
            "netns": report.netns,
            "netns_entered": report.netns_entered,
            "direction": report.direction.as_str(),
            "priority": report.priority,
            "handle": report.handle,
            "clsact_added_or_present": report.clsact_added_or_present,
            "loaded": report.loaded,
            "attached": report.attached,
            "detached": report.detached,
            "link_lifetime_owned_by_backend": report.link_lifetime_owned_by_backend,
        }))
    }

    #[cfg(feature = "native-ebpf")]
    fn ensure_loaded(
        &mut self,
        param_object: &Path,
    ) -> Result<&mut dae_ebpf_support::AyaUserspaceLoadedObject, String> {
        if self.loaded.is_none() {
            let pin_root = dae_ebpf_support::default_bpffs_mount()
                .map_err(|err| format!("native eBPF bpffs mount detection failed: {err}"))?
                .join(format!(
                    "dae-native-runtime-{}-{}",
                    std::process::id(),
                    self.pin_root.is_some() as u8
                ));
            std::fs::create_dir_all(&pin_root)
                .map_err(|err| format!("native eBPF pin root create failed: {err}"))?;
            let before_map_ids = dae_ebpf_support::map_ids()
                .map_err(|err| format!("native eBPF before-load map snapshot failed: {err}"))?;
            let loaded = dae_ebpf_support::load_aya_userspace_object(
                dae_ebpf_support::AyaUserspaceLoaderOptions {
                    object: param_object,
                    param: None,
                    map_pin_path: Some(&pin_root),
                    allow_unsupported_maps: true,
                    max_entries_overrides: &[],
                    prepin_lpm_array_map: true,
                },
            )?;
            self.loaded_map_ids = collect_loaded_map_ids(&before_map_ids)?;
            self.pin_root = Some(pin_root);
            self.loaded = Some(loaded);
        }
        self.loaded
            .as_mut()
            .ok_or_else(|| "native eBPF loader state was not initialized".to_owned())
    }
}

#[cfg(feature = "native-ebpf")]
fn collect_loaded_map_ids(before_map_ids: &[u32]) -> Result<BTreeMap<String, u32>, String> {
    use std::os::fd::AsRawFd;

    let current = dae_ebpf_support::map_ids()
        .map_err(|err| format!("native eBPF after-load map snapshot failed: {err}"))?;
    let mut loaded_map_ids = BTreeMap::new();
    for id in current
        .into_iter()
        .filter(|id| !before_map_ids.contains(id))
    {
        let fd = dae_ebpf_support::open_map_fd(id)
            .map_err(|err| format!("native eBPF open loaded map id {id} failed: {err}"))?;
        let info = dae_ebpf_support::map_info(fd.as_raw_fd())
            .map_err(|err| format!("native eBPF inspect loaded map id {id} failed: {err}"))?;
        loaded_map_ids.entry(info.name).or_insert(info.id);
    }
    Ok(loaded_map_ids)
}

impl Drop for NativeEbpfRuntimeState {
    fn drop(&mut self) {
        self.reset();
    }
}

pub(super) fn prepare_native_param_object(
    options: &ProductionRuntimeOwnerOptions,
    fallback_param_object: &Path,
    native_param_object: &Path,
    dae0_ifindex: u32,
    dae0peer_mac: [u8; 6],
) -> (PathBuf, Value) {
    if !options.native_ebpf_opt_in {
        return (
            fallback_param_object.to_path_buf(),
            json!({
                "status": "skipped",
                "reason": "native eBPF opt-in is disabled",
                "selected_param_object": path_string(fallback_param_object),
                "fallback_param_object": path_string(fallback_param_object),
            }),
        );
    }
    let Some(native_object) = options.native_ebpf_object.as_ref() else {
        return (
            fallback_param_object.to_path_buf(),
            json!({
                "status": "skipped",
                "reason": "native eBPF object is not configured; native attach may fail closed before tc command fallback",
                "selected_param_object": path_string(fallback_param_object),
                "fallback_param_object": path_string(fallback_param_object),
            }),
        );
    };
    let param = build_dae_param(DaeParamInput {
        tproxy_port: options.tproxy_port,
        control_plane_pid: std::process::id(),
        dae0_ifindex,
        dae_netns_id: options.dae_netns_id,
        dae0peer_mac,
        has_bpf_get_current_task: true,
    });
    match write_param_aware_object(native_object, native_param_object, param) {
        Ok(report) => (
            native_param_object.to_path_buf(),
            json!({
                "status": "pass",
                "path": path_string(native_param_object),
                "source_object": path_string(native_object),
                "fallback_param_object": path_string(fallback_param_object),
                "rewritten_param_matches": report.rewritten_param_matches,
                "previous_param_was_zero": report.previous_param_was_zero,
                "source_len": report.source_len,
                "output_len": report.output_len,
                "param": {
                    "tproxy_port": param.tproxy_port,
                    "control_plane_pid": param.control_plane_pid,
                    "dae0_ifindex": param.dae0_ifindex,
                    "dae_netns_id": param.dae_netns_id,
                    "dae0peer_mac": mac_string(param.dae0peer_mac),
                    "has_bpf_get_current_task": param.has_bpf_get_current_task,
                },
                "location": {
                    "symbol": report.location.symbol,
                    "section": report.location.section,
                    "symbol_size": report.location.symbol_size,
                    "file_offset": report.location.file_offset,
                },
            }),
        ),
        Err(err) => (
            native_param_object.to_path_buf(),
            json!({
                "status": "fail",
                "path": path_string(native_param_object),
                "source_object": path_string(native_object),
                "fallback_param_object": path_string(fallback_param_object),
                "error": err.to_string(),
            }),
        ),
    }
}

pub(super) fn native_backend_runtime_decision(
    options: &ProductionRuntimeOwnerOptions,
) -> NativeBackendOptInDecision {
    let admission = native_backend_admission_report(
        if options.native_ebpf_completed_a3_admission {
            NativeBackendAdmissionEvidence::completed_a3_local()
        } else {
            NativeBackendAdmissionEvidence::report_only()
        },
        !options.native_ebpf_completed_a3_admission,
    );
    native_backend_opt_in_decision(NativeBackendOptInRequest {
        opt_in_enabled: options.native_ebpf_opt_in,
        requested_backend: options.native_ebpf_backend,
        admission_report: admission,
        native_loader_available: cfg!(feature = "native-ebpf"),
        tc_command_fallback_available: true,
    })
}

pub(super) fn native_backend_opt_in_decision_json(report: &NativeBackendOptInDecision) -> Value {
    json!({
        "schema": report.schema,
        "opt_in_enabled": report.opt_in_enabled,
        "requested_backend": report.requested_backend.as_str(),
        "admission_admitted": report.admission_admitted,
        "native_loader_available": report.native_loader_available,
        "attempt_native_backend": report.attempt_native_backend,
        "selected_backend": attach_backend_json(report.selected_backend),
        "native_backend_candidate": attach_backend_json(report.native_backend_candidate),
        "fallback_backend": attach_backend_json(report.fallback_backend),
        "fallback_required": report.fallback_required,
        "fallback_preserved": report.fallback_preserved,
        "default_enable_allowed": report.default_enable_allowed,
        "reason": report.reason.as_str(),
    })
}

fn attach_backend_json(backend: Option<AttachBackend>) -> Value {
    backend
        .map(|backend| json!(backend.as_str()))
        .unwrap_or(Value::Null)
}

#[cfg(feature = "native-ebpf")]
fn native_attach_spec(role: NativeEbpfAttachRole, param_object: &Path) -> TcNativeAttachSpec {
    let object = path_string(param_object);
    match role {
        NativeEbpfAttachRole::PeerIngress => TcBpfAttachSpec::new(
            TcAttachTarget::netns(
                PRODUCTION_NETNS,
                PRODUCTION_PEER_IFACE,
                TcAttachDirection::Ingress,
            ),
            FILTER_PREF,
            object,
            "classifier/dae0peer_ingress",
        )
        .native_attach_spec("tproxy_dae0peer_ingress", 0, tc_handle(0x2022, 0b010)),
        NativeEbpfAttachRole::LanIngress => TcBpfAttachSpec::new(
            TcAttachTarget::host(ACTIVE_TCP_LAN_HOST_IFACE, TcAttachDirection::Ingress),
            ACTIVE_TCP_LAN_FILTER_PREF,
            object,
            "classifier/lan_ingress_l2",
        )
        .native_attach_spec("tproxy_lan_ingress_l2", 2, tc_handle(0x2023, 0b100)),
        NativeEbpfAttachRole::HostIngress => TcBpfAttachSpec::new(
            TcAttachTarget::host(PRODUCTION_HOST_IFACE, TcAttachDirection::Ingress),
            FILTER_PREF,
            object,
            "classifier/dae0_ingress",
        )
        .native_attach_spec("tproxy_dae0_ingress", 0, tc_handle(0x2022, 0b010)),
    }
}
