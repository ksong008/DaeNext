use std::path::Path;

use dae_config::Config;
use dae_datapath::{ACTIVE_TCP_LAN_FILTER_PREF, ACTIVE_TCP_LAN_SECTION};
use dae_ebpf_support::{TcAttachDirection, TcAttachTarget, TcBpfAttachSpec, TcCommandSpec};
use serde_json::{Value, json};

use super::command::{CommandSpec, path_string, run_observation_step, run_step};

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
    iface: &str,
    param_object: &Path,
) -> bool {
    let target = lan_attach_target(iface);
    let attach = TcBpfAttachSpec::new(
        target.clone(),
        ACTIVE_TCP_LAN_FILTER_PREF,
        path_string(param_object),
        ACTIVE_TCP_LAN_SECTION,
    );
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
    ok
}

pub(super) fn show_resident_lan_program(steps: &mut Vec<Value>, iface: &str) -> Value {
    run_observation_step(
        steps,
        &format!("show-resident-lan-ingress-param-aware-ebpf-program-filter-{iface}"),
        command_spec(lan_attach_target(iface).filter_show_command(false)),
    )
}

pub(super) fn cleanup_resident_lan_programs(steps: &mut Vec<Value>, ifaces: &[String]) {
    for iface in ifaces {
        let _ = run_observation_step(
            steps,
            &format!("delete-resident-lan-ingress-param-aware-ebpf-program-filter-{iface}"),
            command_spec(lan_attach_target(iface).filter_del_command(ACTIVE_TCP_LAN_FILTER_PREF)),
        );
    }
}

pub(super) fn lan_start_plan_json(ifaces: &[String]) -> Value {
    json!({
        "enabled": !ifaces.is_empty(),
        "interfaces": ifaces,
        "section": ACTIVE_TCP_LAN_SECTION,
        "pref": ACTIVE_TCP_LAN_FILTER_PREF,
        "backend": "tc-command-fallback",
        "qdisc_policy": "tc qdisc replace clsact; cleanup deletes only dae resident filter, not the whole clsact qdisc",
    })
}

fn lan_attach_target(iface: &str) -> TcAttachTarget {
    TcAttachTarget::host(iface, TcAttachDirection::Ingress)
}

fn command_spec(command: TcCommandSpec) -> CommandSpec {
    CommandSpec::new(command.program, command.args)
}
