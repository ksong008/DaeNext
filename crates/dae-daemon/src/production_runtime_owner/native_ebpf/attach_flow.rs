use super::*;
impl NativeEbpfRuntimeState {
    pub(in crate::production_runtime_owner) fn attach_program(
        &mut self,
        steps: &mut Vec<Value>,
        options: &ProductionRuntimeOwnerOptions,
        param_object: &Path,
        role: NativeEbpfAttachRole,
    ) -> Option<bool> {
        let decision = native_backend_runtime_decision_for_options(options);
        steps.push(json!({
            "name": role.decision_step_name(),
            "status": "pass",
            "role": role.as_str(),
            "decision": native_backend_runtime_decision_json(&decision),
        }));
        if !decision.attempt_native_backend {
            return None;
        }
        let requested_backend = decision.selected_backend?;
        let backend = native_backend_for_role(role, requested_backend);
        match self.try_attach_program(options, param_object, role, backend) {
            Ok(report) => {
                let actual_backend = actual_attach_backend(&report, backend);
                let backend_switch_used = attach_backend_switch_used(&report);
                match role {
                    NativeEbpfAttachRole::PeerIngress => self.peer_attached = true,
                    NativeEbpfAttachRole::LanIngress => self.lan_attached = true,
                    NativeEbpfAttachRole::HostIngress => self.host_attached = true,
                }
                steps.push(json!({
                    "name": role.attach_step_name(),
                    "status": "pass",
                    "role": role.as_str(),
                    "requested_backend": requested_backend.as_str(),
                    "effective_backend": backend.as_str(),
                    "backend": actual_backend.as_str(),
                    "native_attach": report,
                    "command_backend_required": true,
                    "actual_command_backend_required": backend_switch_used,
                    "backend_switch_used": backend_switch_used,
                    "native_attach_required": true,
                    "native_attach_admitted": true,
                    "native_attach_attempted": true,
                    "native_attach_succeeded": true,
                    "restore_available": true,
                }));
                Some(true)
            }
            Err(err) => {
                steps.push(json!({
                    "name": role.attach_step_name(),
                    "status": "fail",
                    "role": role.as_str(),
                    "backend": backend.as_str(),
                    "requested_backend": requested_backend.as_str(),
                    "stderr": err,
                    "command_backend_required": true,
                    "actual_command_backend_required": false,
                    "backend_switch_used": false,
                    "native_attach_required": true,
                    "native_attach_admitted": true,
                    "native_attach_attempted": true,
                    "native_attach_succeeded": false,
                    "restore_available": true,
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
        link_layer: TcAttachLayer,
    ) -> Option<NativeAttachOutcome> {
        let decision = native_backend_runtime_decision_for_options(options);
        steps.push(json!({
            "name": format!("native-ebpf-resident-lan-runtime-decision-{iface}"),
            "status": "pass",
            "role": "resident_lan_ingress",
            "interface": iface,
            "link_layer": link_layer.suffix(),
            "decision": native_backend_runtime_decision_json(&decision),
        }));
        if !decision.attempt_native_backend {
            return None;
        }
        let backend = decision.selected_backend?;
        match self.try_attach_resident_lan_program(param_object, iface, link_layer, backend) {
            Ok(report) => {
                let actual_backend = actual_attach_backend(&report, backend);
                let backend_switch_used = attach_backend_switch_used(&report);
                self.lan_attached = true;
                steps.push(json!({
                    "name": format!("attach-resident-lan-ingress-native-ebpf-program-{iface}"),
                    "status": "pass",
                    "role": "resident_lan_ingress",
                    "interface": iface,
                    "link_layer": link_layer.suffix(),
                    "requested_backend": backend.as_str(),
                    "backend": actual_backend.as_str(),
                    "native_attach": report,
                    "command_backend_required": true,
                    "actual_command_backend_required": backend_switch_used,
                    "backend_switch_used": backend_switch_used,
                    "native_attach_required": true,
                    "native_attach_admitted": true,
                    "native_attach_attempted": true,
                    "native_attach_succeeded": true,
                    "restore_available": true,
                }));
                Some(NativeAttachOutcome {
                    ok: true,
                    backend: actual_backend,
                    backend_switch_used,
                })
            }
            Err(err) => {
                steps.push(json!({
                    "name": format!("attach-resident-lan-ingress-native-ebpf-program-{iface}"),
                    "status": "fail",
                    "role": "resident_lan_ingress",
                    "interface": iface,
                    "link_layer": link_layer.suffix(),
                    "backend": backend.as_str(),
                    "stderr": err,
                    "command_backend_required": true,
                    "actual_command_backend_required": false,
                    "backend_switch_used": false,
                    "native_attach_required": true,
                    "native_attach_admitted": true,
                    "native_attach_attempted": true,
                    "native_attach_succeeded": false,
                    "restore_available": true,
                }));
                Some(NativeAttachOutcome {
                    ok: false,
                    backend,
                    backend_switch_used: false,
                })
            }
        }
    }

    pub(in crate::production_runtime_owner) fn attach_interface_program(
        &mut self,
        steps: &mut Vec<Value>,
        options: &ProductionRuntimeOwnerOptions,
        param_object: &Path,
        iface: &str,
        role: NativeInterfaceAttachRole,
        link_layer: TcAttachLayer,
    ) -> Option<NativeAttachOutcome> {
        let decision = native_backend_runtime_decision_for_options(options);
        steps.push(json!({
            "name": format!("native-ebpf-resident-{}-runtime-decision-{iface}", role.as_str()),
            "status": "pass",
            "role": role.as_str(),
            "interface": iface,
            "link_layer": link_layer.suffix(),
            "decision": native_backend_runtime_decision_json(&decision),
        }));
        if !decision.attempt_native_backend {
            return None;
        }
        let backend = decision.selected_backend?;
        match self.try_attach_interface_program(param_object, iface, role, link_layer, backend) {
            Ok(report) => {
                let actual_backend = actual_attach_backend(&report, backend);
                let backend_switch_used = attach_backend_switch_used(&report);
                steps.push(json!({
                    "name": format!("attach-resident-{}-native-ebpf-program-{iface}", role.as_str()),
                    "status": "pass",
                    "role": role.as_str(),
                    "interface": iface,
                    "link_layer": link_layer.suffix(),
                    "requested_backend": backend.as_str(),
                    "backend": actual_backend.as_str(),
                    "native_attach": report,
                    "command_backend_required": true,
                    "actual_command_backend_required": backend_switch_used,
                    "backend_switch_used": backend_switch_used,
                    "native_attach_required": true,
                    "native_attach_admitted": true,
                    "native_attach_attempted": true,
                    "native_attach_succeeded": true,
                    "restore_available": true,
                }));
                Some(NativeAttachOutcome {
                    ok: true,
                    backend: actual_backend,
                    backend_switch_used,
                })
            }
            Err(err) => {
                steps.push(json!({
                    "name": format!("attach-resident-{}-native-ebpf-program-{iface}", role.as_str()),
                    "status": "fail",
                    "role": role.as_str(),
                    "interface": iface,
                    "link_layer": link_layer.suffix(),
                    "backend": backend.as_str(),
                    "stderr": err,
                    "command_backend_required": true,
                    "actual_command_backend_required": false,
                    "backend_switch_used": false,
                    "native_attach_required": true,
                    "native_attach_admitted": true,
                    "native_attach_attempted": true,
                    "native_attach_succeeded": false,
                    "restore_available": true,
                }));
                Some(NativeAttachOutcome {
                    ok: false,
                    backend,
                    backend_switch_used: false,
                })
            }
        }
    }

    pub(in crate::production_runtime_owner) fn attach_cgroup_programs(
        &mut self,
        steps: &mut Vec<Value>,
        options: &ProductionRuntimeOwnerOptions,
        param_object: &Path,
    ) -> Option<bool> {
        let decision = native_backend_runtime_decision_for_options(options);
        steps.push(json!({
            "name": "native-ebpf-cgroup-runtime-decision",
            "status": "pass",
            "role": "cgroup_pname_monitor",
            "decision": native_backend_runtime_decision_json(&decision),
        }));
        if !decision.attempt_native_backend {
            return None;
        }
        match self.try_attach_cgroup_programs(param_object) {
            Ok((preflight, reports)) => {
                self.cgroup_attached = true;
                steps.push(json!({
                    "name": "attach-native-ebpf-cgroup-programs",
                    "status": "pass",
                    "role": "cgroup_pname_monitor",
                    "backend": "aya",
                    "preflight": preflight,
                    "programs": reports,
                    "command_backend_required": true,
                    "actual_command_backend_required": false,
                    "backend_switch_used": false,
                    "native_attach_required": true,
                    "native_attach_admitted": true,
                    "native_attach_attempted": true,
                    "native_attach_succeeded": true,
                    "restore_available": true,
                }));
                Some(true)
            }
            Err(err) => {
                steps.push(json!({
                    "name": "attach-native-ebpf-cgroup-programs",
                    "status": "fail",
                    "role": "cgroup_pname_monitor",
                    "backend": "aya",
                    "stderr": err,
                    "command_backend_required": true,
                    "actual_command_backend_required": false,
                    "backend_switch_used": false,
                    "native_attach_required": true,
                    "native_attach_admitted": true,
                    "native_attach_attempted": true,
                    "native_attach_succeeded": false,
                    "restore_available": true,
                }));
                Some(false)
            }
        }
    }
}
