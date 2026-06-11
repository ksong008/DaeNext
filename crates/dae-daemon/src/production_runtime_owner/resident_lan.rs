use std::path::Path;

use dae_config::Config;
use dae_datapath::{ACTIVE_TCP_LAN_FILTER_PREF, ACTIVE_TCP_LAN_SECTION};
use dae_ebpf_support::{
    TcAttachDirection, TcAttachLayer, TcAttachTarget, TcBpfAttachSpec, TcCommandSpec,
};
use serde_json::{Value, json};

use super::ProductionRuntimeOwnerOptions;
use super::command::{CommandSpec, path_string, run_observation_step, run_step};
use super::native_ebpf::NativeEbpfRuntimeState;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ResidentLanAttachResult {
    pub ok: bool,
    pub native_attached: bool,
    pub backend: &'static str,
    pub command_backend_used: bool,
    pub native_backend_attempted: bool,
    pub native_backend: Option<&'static str>,
    pub link_layer: TcAttachLayer,
}

pub(super) fn configured_lan_ifaces(config: &Config) -> Vec<String> {
    let mut ifaces = Vec::new();
    for iface in config.global.lan_interface.iter().flatten() {
        let iface = iface.trim();
        if iface.is_empty() || ifaces.iter().any(|seen| seen == iface) {
            continue;
        }
        ifaces.push(iface.to_owned());
    }
    ifaces
}

pub(super) fn attach_resident_lan_program(
    steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
    iface: &str,
    link_layer: TcAttachLayer,
    param_object: &Path,
    native_param_object: &Path,
    native_runtime: &mut NativeEbpfRuntimeState,
) -> ResidentLanAttachResult {
    let target = lan_attach_target(iface);
    let attach = TcBpfAttachSpec::new(
        target.clone(),
        ACTIVE_TCP_LAN_FILTER_PREF,
        path_string(param_object),
        format!("tc/lan_ingress_{}", link_layer.suffix()),
    );
    let native_attach = native_runtime.attach_resident_lan_program(
        steps,
        options,
        native_param_object,
        iface,
        link_layer,
    );
    if let Some(outcome) = native_attach {
        return ResidentLanAttachResult {
            ok: outcome.ok,
            native_attached: outcome.ok,
            backend: outcome.backend.as_str(),
            command_backend_used: false,
            native_backend_attempted: true,
            native_backend: Some(outcome.backend.as_str()),
            link_layer,
        };
    }
    let _ = run_observation_step(
        steps,
        &format!("delete-existing-resident-lan-ingress-filter-{iface}"),
        command_spec(target.filter_del_command(ACTIVE_TCP_LAN_FILTER_PREF)),
    );

    let mut ok = true;
    ok &= run_step(
        steps,
        &format!("replace-resident-lan-clsact-qdisc-{iface}"),
        CommandSpec::new("tc", ["qdisc", "replace", "dev", iface, "clsact"]),
    );
    ok &= run_step(
        steps,
        &format!("attach-resident-lan-ingress-param-aware-ebpf-program-{iface}"),
        command_spec(attach.filter_add_command()),
    );
    ResidentLanAttachResult {
        ok,
        native_attached: false,
        backend: "tc_command",
        command_backend_used: true,
        native_backend_attempted: false,
        native_backend: None,
        link_layer,
    }
}

pub(super) fn show_resident_lan_program(steps: &mut Vec<Value>, iface: &str) -> Value {
    run_observation_step(
        steps,
        &format!("show-resident-lan-ingress-param-aware-ebpf-program-filter-{iface}"),
        command_spec(lan_attach_target(iface).filter_show_command(false)),
    )
}

pub(super) fn cleanup_resident_lan_programs(
    steps: &mut Vec<Value>,
    ifaces: &[String],
    native_lan_ifaces: &[String],
) {
    for iface in ifaces {
        if native_lan_ifaces
            .iter()
            .any(|native_iface| native_iface == iface)
        {
            steps.push(json!({
                "name": format!("delete-resident-lan-ingress-param-aware-ebpf-program-filter-{iface}"),
                "status": "skipped",
                "reason": "native Aya link lifetime detached the resident LAN ingress filter before tc command cleanup",
            }));
        } else {
            let _ = run_observation_step(
                steps,
                &format!("delete-resident-lan-ingress-param-aware-ebpf-program-filter-{iface}"),
                command_spec(
                    lan_attach_target(iface).filter_del_command(ACTIVE_TCP_LAN_FILTER_PREF),
                ),
            );
        }
    }
}

pub(super) fn lan_start_plan_json(
    ifaces: &[String],
    native_ebpf_requested: bool,
    resident_lan_attach: &[Value],
) -> Value {
    json!({
        "enabled": !ifaces.is_empty(),
        "interfaces": ifaces,
        "section": ACTIVE_TCP_LAN_SECTION,
        "pref": ACTIVE_TCP_LAN_FILTER_PREF,
        "backend": if native_ebpf_requested {
            "native-aya-with-tc-command"
        } else {
            "tc-command"
        },
        "backend_scope": "plan",
        "actual_backend_source": "resident_lan_attach[].backend",
        "actual_backends": actual_lan_backends(resident_lan_attach),
        "qdisc_policy": "tc qdisc replace clsact; cleanup deletes only dae resident filter, not the whole clsact qdisc",
    })
}

fn actual_lan_backends(resident_lan_attach: &[Value]) -> Vec<Value> {
    resident_lan_attach
        .iter()
        .map(|attach| {
            json!({
                "interface": attach.get("interface").cloned().unwrap_or(Value::Null),
                "backend": attach.get("backend").cloned().unwrap_or(Value::Null),
                "command_backend_used": attach.get("command_backend_used").cloned().unwrap_or(Value::Null),
                "native_attached": attach.get("native_attached").cloned().unwrap_or(Value::Null),
            })
        })
        .collect()
}

fn lan_attach_target(iface: &str) -> TcAttachTarget {
    TcAttachTarget::host(iface, TcAttachDirection::Ingress)
}

fn command_spec(command: TcCommandSpec) -> CommandSpec {
    CommandSpec::new(command.program, command.args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_start_plan_separates_plan_backend_from_actual_backend() {
        let attach = vec![json!({
            "interface": "daerust0",
            "backend": "tcx",
            "command_backend_used": false,
            "native_attached": true,
        })];

        let plan = lan_start_plan_json(&["daerust0".to_owned()], true, &attach);

        assert_eq!(plan["backend"], json!("native-aya-with-tc-command"));
        assert_eq!(plan["backend_scope"], json!("plan"));
        assert_eq!(
            plan["actual_backend_source"],
            json!("resident_lan_attach[].backend")
        );
        assert_eq!(plan["actual_backends"][0]["backend"], json!("tcx"));
        assert_eq!(plan["actual_backends"][0]["interface"], json!("daerust0"));
        assert_eq!(plan["actual_backends"][0]["native_attached"], json!(true));
    }
}
