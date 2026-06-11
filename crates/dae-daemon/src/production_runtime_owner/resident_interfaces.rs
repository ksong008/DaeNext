use std::fs;
use std::path::Path;
use std::process::Command;

use dae_config::Config;
use dae_ebpf_support::TcAttachLayer;
use serde_json::{Value, json};

use super::ProductionRuntimeOwnerOptions;
use super::command::{CommandSpec, run_step};
use super::native_ebpf::{NativeEbpfRuntimeState, NativeInterfaceAttachRole};

pub(super) fn configured_wan_ifaces(config: &Config) -> Result<Vec<String>, String> {
    let mut resolved_auto = None;
    let values = config.global.wan_interface.iter().flatten();
    configured_wan_ifaces_from_values(values, || {
        if resolved_auto.is_none() {
            resolved_auto = Some(default_route_wan_ifaces()?);
        }
        Ok(resolved_auto.clone().unwrap_or_default())
    })
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

pub(super) fn configure_resident_lan_kernel_parameters(
    steps: &mut Vec<Value>,
    iface: &str,
) -> Value {
    let ipv4_send_redirects_ok = run_step(
        steps,
        &format!("set-resident-lan-{iface}-ipv4-send-redirects-off"),
        CommandSpec::new(
            "sysctl",
            ["-w", &format!("net.ipv4.conf.{iface}.send_redirects=0")],
        ),
    );
    let ipv4_forwarding_ok = run_step(
        steps,
        &format!("set-resident-lan-{iface}-ipv4-forwarding-on"),
        CommandSpec::new(
            "sysctl",
            ["-w", &format!("net.ipv4.conf.{iface}.forwarding=1")],
        ),
    );
    let ipv6_forwarding_ok = run_step(
        steps,
        &format!("set-resident-lan-{iface}-ipv6-forwarding-on"),
        CommandSpec::new(
            "sysctl",
            ["-w", &format!("net.ipv6.conf.{iface}.forwarding=1")],
        ),
    );
    json!({
        "name": format!("resident-lan-kernel-parameters-{iface}"),
        "status": if ipv4_send_redirects_ok && ipv4_forwarding_ok && ipv6_forwarding_ok { "pass" } else { "warn" },
        "interface": iface,
        "ipv4_send_redirects_off": ipv4_send_redirects_ok,
        "ipv4_forwarding_on": ipv4_forwarding_ok,
        "ipv6_forwarding_on": ipv6_forwarding_ok,
        "source_parity": "native bindLan autoConfigKernelParameter SetSendRedirects(iface, 0) and SetForwarding(iface, 1)",
    })
}

fn link_layer_from_arphrd(arphrd: u16) -> TcAttachLayer {
    match arphrd {
        512 | 768 | 65_534 => TcAttachLayer::L3,
        _ => TcAttachLayer::L2,
    }
}

fn configured_wan_ifaces_from_values<'a>(
    values: impl IntoIterator<Item = &'a String>,
    mut resolve_auto: impl FnMut() -> Result<Vec<String>, String>,
) -> Result<Vec<String>, String> {
    let mut ifaces = Vec::new();
    for iface in values {
        let iface = iface.trim();
        if iface.is_empty() {
            continue;
        }
        if iface.eq_ignore_ascii_case("auto") {
            let auto_ifaces = resolve_auto()?;
            if auto_ifaces.is_empty() {
                return Err(
                    "wan_interface auto could not resolve any default route interface".to_owned(),
                );
            }
            for auto_iface in auto_ifaces {
                push_unique_iface(&mut ifaces, auto_iface.trim());
            }
            continue;
        }
        push_unique_iface(&mut ifaces, iface);
    }
    Ok(ifaces)
}

fn default_route_wan_ifaces() -> Result<Vec<String>, String> {
    let mut ifaces = Vec::new();
    let mut errors = Vec::new();
    for family in ["-4", "-6"] {
        match default_route_ifaces_from_ip(family) {
            Ok(route_ifaces) => {
                for iface in route_ifaces {
                    push_unique_iface(&mut ifaces, &iface);
                }
            }
            Err(err) => errors.push(err),
        }
    }
    if !ifaces.is_empty() {
        return Ok(ifaces);
    }
    if errors.is_empty() {
        Err("wan_interface auto found no default route in ip route output".to_owned())
    } else {
        Err(format!(
            "wan_interface auto could not resolve default route interface: {}",
            errors.join("; ")
        ))
    }
}

fn default_route_ifaces_from_ip(family: &str) -> Result<Vec<String>, String> {
    let output = Command::new("ip")
        .args([family, "-o", "route", "show", "default"])
        .output()
        .map_err(|err| format!("failed to run ip {family} route show default: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(format!(
            "ip {family} route show default exited with status {}{}",
            output.status,
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        ));
    }
    Ok(parse_default_route_ifaces(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

fn parse_default_route_ifaces(output: &str) -> Vec<String> {
    let mut ifaces = Vec::new();
    for line in output.lines() {
        let mut tokens = line.split_whitespace();
        while let Some(token) = tokens.next() {
            if token != "dev" {
                continue;
            }
            if let Some(iface) = tokens.next() {
                push_unique_iface(&mut ifaces, iface);
            }
            break;
        }
    }
    ifaces
}

fn push_unique_iface(ifaces: &mut Vec<String>, iface: &str) {
    let iface = iface.trim();
    if !iface.is_empty() && !ifaces.iter().any(|seen| seen == iface) {
        ifaces.push(iface.to_owned());
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
                "backend_switch_used": outcome.backend_switch_used,
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
                        "backend_switch_used": outcome.backend_switch_used,
                    }));
                }
                None => {
                    iface_ok = false;
                    directions.push(json!({
                        "role": role.as_str(),
                        "status": "fail",
                        "error": "native Aya WAN attach was not attempted; non-native WAN backend is not used by Rust resident",
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
    fn link_layer_detection_matches_compatible_l2_l3_program_selection() {
        assert_eq!(link_layer_from_arphrd(1), TcAttachLayer::L2);
        assert_eq!(link_layer_from_arphrd(512), TcAttachLayer::L3);
        assert_eq!(link_layer_from_arphrd(768), TcAttachLayer::L3);
        assert_eq!(link_layer_from_arphrd(65_534), TcAttachLayer::L3);
        assert_eq!(link_layer_from_arphrd(772), TcAttachLayer::L2);
    }

    #[test]
    fn default_route_parser_extracts_ipv4_and_ipv6_devices() {
        let output = "\
default via 192.0.2.1 dev wan_primary proto dhcp src 192.0.2.10 metric 100
default dev wan_tunnel scope link metric 200
default via fe80::1 dev wan_ipv6 proto ra metric 1024 expires 1771sec pref medium
";
        assert_eq!(
            parse_default_route_ifaces(output),
            ["wan_primary", "wan_tunnel", "wan_ipv6"]
        );
    }

    #[test]
    fn wan_interface_auto_expands_to_default_route_devices() {
        let configured = vec![
            "auto".to_owned(),
            "wan_manual".to_owned(),
            "wan_primary".to_owned(),
            "auto".to_owned(),
        ];
        let resolved = configured_wan_ifaces_from_values(configured.iter(), || {
            Ok(vec!["wan_primary".to_owned(), "wan_secondary".to_owned()])
        })
        .unwrap();
        assert_eq!(resolved, ["wan_primary", "wan_secondary", "wan_manual"]);
    }

    #[test]
    fn explicit_wan_interface_names_pass_through_without_auto_resolution() {
        let configured = vec![
            "wan_manual".to_owned(),
            "wan_backup".to_owned(),
            "wan_manual".to_owned(),
        ];
        let resolved = configured_wan_ifaces_from_values(configured.iter(), || {
            panic!("explicit WAN interface names must not resolve auto")
        })
        .unwrap();
        assert_eq!(resolved, ["wan_manual", "wan_backup"]);
    }

    #[test]
    fn wan_interface_auto_requires_a_default_route_device() {
        let configured = vec!["auto".to_owned()];
        let err =
            configured_wan_ifaces_from_values(configured.iter(), || Ok(Vec::new())).unwrap_err();
        assert!(err.contains("wan_interface auto"));
    }
}
