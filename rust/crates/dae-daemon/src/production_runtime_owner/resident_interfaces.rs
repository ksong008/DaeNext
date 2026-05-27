use std::fs;
use std::path::Path;

use dae_config::Config;
use dae_ebpf_support::TcAttachLayer;
use serde_json::{Value, json};

use super::ProductionRuntimeOwnerOptions;
use super::native_ebpf::{NativeEbpfRuntimeState, NativeInterfaceAttachRole};

pub(super) fn configured_wan_ifaces(config: &Config) -> Vec<String> {
    let mut ifaces = Vec::new();
    for iface in config.global.wan_interface.iter().flatten() {
        let iface = iface.trim();
        if iface.is_empty() || ifaces.iter().any(|seen| seen == iface) {
            continue;
        }
        ifaces.push(iface.to_owned());
    }
    ifaces
}

pub(super) fn interface_link_layer(iface: &str) -> Result<TcAttachLayer, String> {
    let value = fs::read_to_string(format!("/sys/class/net/{iface}/type"))
        .map_err(|err| format!("failed to read interface type for {iface}: {err}"))?;
    let arphrd = value
        .trim()
        .parse::<u16>()
        .map_err(|err| format!("failed to parse interface type for {iface}: {err}"))?;
    Ok(link_layer_from_arphrd(arphrd))
}

fn link_layer_from_arphrd(arphrd: u16) -> TcAttachLayer {
    match arphrd {
        512 | 768 | 65_534 => TcAttachLayer::L3,
        _ => TcAttachLayer::L2,
    }
}

pub(super) fn attach_resident_lan_egress_program(
    steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
    native_param_object: &Path,
    native_runtime: &mut NativeEbpfRuntimeState,
    iface: &str,
    link_layer: TcAttachLayer,
) -> (bool, Value) {
    match native_runtime.attach_interface_program(
        steps,
        options,
        native_param_object,
        iface,
        NativeInterfaceAttachRole::LanEgress,
        link_layer,
    ) {
        Some(outcome) => (
            outcome.ok,
            json!({
                "status": if outcome.ok { "pass" } else { "fail" },
                "backend": outcome.backend.as_str(),
                "fallback_used": outcome.fallback_used,
                "native_attached": outcome.ok,
            }),
        ),
        None => (
            false,
            json!({
                "status": "fail",
                "error": "native LAN ingress was attached but native LAN egress attach was not attempted",
            }),
        ),
    }
}

pub(super) fn attach_resident_wan_programs(
    steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
    native_param_object: &Path,
    native_runtime: &mut NativeEbpfRuntimeState,
    wan_ifaces: &[String],
    previous_ok: bool,
) -> (bool, Vec<Value>) {
    let mut ok = previous_ok;
    let mut report = Vec::new();
    for iface in wan_ifaces {
        if !ok {
            report.push(json!({
                "interface": iface,
                "status": "skipped",
                "reason": "previous resident runtime step did not pass",
            }));
            continue;
        }
        let link_layer = match interface_link_layer(iface) {
            Ok(layer) => layer,
            Err(err) => {
                ok = false;
                report.push(json!({
                    "interface": iface,
                    "status": "fail",
                    "error": err,
                }));
                continue;
            }
        };
        let mut directions = Vec::new();
        let mut iface_ok = true;
        for role in [
            NativeInterfaceAttachRole::WanIngress,
            NativeInterfaceAttachRole::WanEgress,
        ] {
            match native_runtime.attach_interface_program(
                steps,
                options,
                native_param_object,
                iface,
                role,
                link_layer,
            ) {
                Some(outcome) => {
                    iface_ok &= outcome.ok;
                    directions.push(json!({
                        "role": role.as_str(),
                        "status": if outcome.ok { "pass" } else { "fail" },
                        "backend": outcome.backend.as_str(),
                        "fallback_used": outcome.fallback_used,
                    }));
                }
                None => {
                    iface_ok = false;
                    directions.push(json!({
                        "role": role.as_str(),
                        "status": "fail",
                        "error": "native Aya WAN attach was not attempted; Go BPF WAN fallback is not used by Rust resident",
                    }));
                }
            }
        }
        ok &= iface_ok;
        report.push(json!({
            "interface": iface,
            "link_layer": link_layer.suffix(),
            "status": if iface_ok { "pass" } else { "fail" },
            "directions": directions,
        }));
    }
    (ok, report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_layer_detection_matches_go_l2_l3_program_selection() {
        assert_eq!(link_layer_from_arphrd(1), TcAttachLayer::L2);
        assert_eq!(link_layer_from_arphrd(512), TcAttachLayer::L3);
        assert_eq!(link_layer_from_arphrd(768), TcAttachLayer::L3);
        assert_eq!(link_layer_from_arphrd(65_534), TcAttachLayer::L3);
        assert_eq!(link_layer_from_arphrd(772), TcAttachLayer::L2);
    }
}
