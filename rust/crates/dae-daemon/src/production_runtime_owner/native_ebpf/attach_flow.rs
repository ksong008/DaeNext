use super::*;
impl NativeEbpfRuntimeState {
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
        let requested_backend = decision.selected_backend?;
        let backend = native_backend_for_role(role, requested_backend);
        match self.try_attach_program(options, param_object, role, backend) {
            Ok(report) => {
                let actual_backend = actual_attach_backend(&report, backend);
                let fallback_used = attach_fallback_used(&report);
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
                    "fallback_required": true,
                    "fallback_required_legacy": true,
                    "actual_fallback_required": fallback_used,
                    "fallback_used": fallback_used,
                    "native_attach_required": true,
                    "native_attach_admitted": true,
                    "native_attach_attempted": true,
                    "native_attach_succeeded": true,
                    "rollback_available": true,
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
                    "fallback_required": true,
                    "fallback_required_legacy": true,
                    "actual_fallback_required": false,
                    "fallback_used": false,
                    "native_attach_required": true,
                    "native_attach_admitted": true,
                    "native_attach_attempted": true,
                    "native_attach_succeeded": false,
                    "rollback_available": true,
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
        let decision = native_backend_runtime_decision(options);
        steps.push(json!({
            "name": format!("native-ebpf-resident-lan-opt-in-decision-{iface}"),
            "status": "pass",
            "role": "resident_lan_ingress",
            "interface": iface,
            "link_layer": link_layer.suffix(),
            "decision": native_backend_opt_in_decision_json(&decision),
        }));
        if !decision.attempt_native_backend {
            return None;
        }
        let backend = decision.selected_backend?;
        match self.try_attach_resident_lan_program(param_object, iface, link_layer, backend) {
            Ok(report) => {
                let actual_backend = actual_attach_backend(&report, backend);
                let fallback_used = attach_fallback_used(&report);
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
                    "fallback_required": true,
                    "fallback_required_legacy": true,
                    "actual_fallback_required": fallback_used,
                    "fallback_used": fallback_used,
                    "native_attach_required": true,
                    "native_attach_admitted": true,
                    "native_attach_attempted": true,
                    "native_attach_succeeded": true,
                    "rollback_available": true,
                }));
                Some(NativeAttachOutcome {
                    ok: true,
                    backend: actual_backend,
                    fallback_used,
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
                    "fallback_required": true,
                    "fallback_required_legacy": true,
                    "actual_fallback_required": false,
                    "fallback_used": false,
                    "native_attach_required": true,
                    "native_attach_admitted": true,
                    "native_attach_attempted": true,
                    "native_attach_succeeded": false,
                    "rollback_available": true,
                }));
                Some(NativeAttachOutcome {
                    ok: false,
                    backend,
                    fallback_used: false,
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
        let decision = native_backend_runtime_decision(options);
        steps.push(json!({
            "name": format!("native-ebpf-resident-{}-opt-in-decision-{iface}", role.as_str()),
            "status": "pass",
            "role": role.as_str(),
            "interface": iface,
            "link_layer": link_layer.suffix(),
            "decision": native_backend_opt_in_decision_json(&decision),
        }));
        if !decision.attempt_native_backend {
            return None;
        }
        let backend = decision.selected_backend?;
        match self.try_attach_interface_program(param_object, iface, role, link_layer, backend) {
            Ok(report) => {
                let actual_backend = actual_attach_backend(&report, backend);
                let fallback_used = attach_fallback_used(&report);
                steps.push(json!({
                    "name": format!("attach-resident-{}-native-ebpf-program-{iface}", role.as_str()),
                    "status": "pass",
                    "role": role.as_str(),
                    "interface": iface,
                    "link_layer": link_layer.suffix(),
                    "requested_backend": backend.as_str(),
                    "backend": actual_backend.as_str(),
                    "native_attach": report,
                    "fallback_required": true,
                    "fallback_required_legacy": true,
                    "actual_fallback_required": fallback_used,
                    "fallback_used": fallback_used,
                    "native_attach_required": true,
                    "native_attach_admitted": true,
                    "native_attach_attempted": true,
                    "native_attach_succeeded": true,
                    "rollback_available": true,
                }));
                Some(NativeAttachOutcome {
                    ok: true,
                    backend: actual_backend,
                    fallback_used,
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
                    "fallback_required": true,
                    "fallback_required_legacy": true,
                    "actual_fallback_required": false,
                    "fallback_used": false,
                    "native_attach_required": true,
                    "native_attach_admitted": true,
                    "native_attach_attempted": true,
                    "native_attach_succeeded": false,
                    "rollback_available": true,
                }));
                Some(NativeAttachOutcome {
                    ok: false,
                    backend,
                    fallback_used: false,
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
        let decision = native_backend_runtime_decision(options);
        steps.push(json!({
            "name": "native-ebpf-cgroup-opt-in-decision",
            "status": "pass",
            "role": "cgroup_pname_monitor",
            "decision": native_backend_opt_in_decision_json(&decision),
        }));
        if !decision.attempt_native_backend {
            return None;
        }
        match self.try_attach_cgroup_programs(param_object) {
            Ok(reports) => {
                self.cgroup_attached = true;
                steps.push(json!({
                    "name": "attach-native-ebpf-cgroup-programs",
                    "status": "pass",
                    "role": "cgroup_pname_monitor",
                    "backend": "aya",
                    "programs": reports,
                    "fallback_required": true,
                    "fallback_required_legacy": true,
                    "actual_fallback_required": false,
                    "fallback_used": false,
                    "native_attach_required": true,
                    "native_attach_admitted": true,
                    "native_attach_attempted": true,
                    "native_attach_succeeded": true,
                    "rollback_available": true,
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
                    "fallback_required": true,
                    "fallback_required_legacy": true,
                    "actual_fallback_required": false,
                    "fallback_used": false,
                    "native_attach_required": true,
                    "native_attach_admitted": true,
                    "native_attach_attempted": true,
                    "native_attach_succeeded": false,
                    "rollback_available": true,
                }));
                Some(false)
            }
        }
    }
}
