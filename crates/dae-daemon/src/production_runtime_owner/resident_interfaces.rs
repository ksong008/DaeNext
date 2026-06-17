use std::fs;
use std::path::Path;
use std::process::Command;

use dae_config::Config;
use dae_ebpf_support::{FeatureGateReport, TcAttachLayer, kernel::current_kernel_version};
use serde_json::{Value, json};

use super::ProductionRuntimeOwnerOptions;
use super::command::{CommandSpec, push_check, run_step};
use super::native_ebpf::{NativeEbpfRuntimeState, NativeInterfaceAttachRole};

pub(crate) fn configured_wan_ifaces(config: &Config) -> Result<Vec<String>, String> {
    let mut resolved_auto = None;
    let values = config.global.wan_interface.iter().flatten();
    configured_wan_ifaces_from_values(values, || {
        if resolved_auto.is_none() {
            resolved_auto = Some(default_route_wan_ifaces()?);
        }
        Ok(resolved_auto.clone().unwrap_or_default())
    })
}

pub(crate) fn resident_interface_validation_checks(
    lan_ifaces: &[String],
    wan_ifaces: &[String],
) -> Vec<Value> {
    let mut checks = Vec::new();
    let lan_present = !lan_ifaces.iter().all(|iface| iface.trim().is_empty());
    push_check(
        &mut checks,
        "resident-lan-interface-configured",
        lan_present,
        json!({"lan_interfaces": lan_ifaces}),
        "global.lan_interface must specify at least one existing LAN interface",
    );

    for iface in lan_ifaces {
        let iface = iface.trim();
        let blocker = format!(
            "global.lan_interface must name an existing LAN interface and cannot use auto, got {iface:?}"
        );
        push_check(
            &mut checks,
            &format!("resident-lan-interface-valid-{iface}"),
            !iface.is_empty()
                && !iface.eq_ignore_ascii_case("auto")
                && iface_exists_in_sysfs(iface),
            json!({
                "interface": iface,
                "configured": !iface.is_empty(),
                "auto_allowed": false,
                "exists": iface_exists_in_sysfs(iface),
                "role": "lan",
            }),
            &blocker,
        );
    }

    for iface in wan_ifaces {
        let iface = iface.trim();
        let exists = iface_exists_in_sysfs(iface);
        let is_loopback = iface == "lo";
        let blocker = format!(
            "global.wan_interface must resolve to existing non-loopback WAN interface, got {iface:?}"
        );
        push_check(
            &mut checks,
            &format!("resident-wan-interface-valid-{iface}"),
            !iface.is_empty() && exists && !is_loopback,
            json!({
                "interface": iface,
                "configured": !iface.is_empty(),
                "auto_resolved": true,
                "exists": exists,
                "loopback": is_loopback,
                "role": "wan",
            }),
            &blocker,
        );
    }

    checks
}

pub(crate) fn validate_resident_runtime_interfaces(
    lan_ifaces: &[String],
    wan_ifaces: &[String],
    prefix: &str,
) -> Result<(), String> {
    let blockers = resident_interface_validation_checks(lan_ifaces, wan_ifaces)
        .into_iter()
        .filter(|check| check["status"].as_str() != Some("pass"))
        .filter_map(|check| check["blocker"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    if blockers.is_empty() {
        Ok(())
    } else {
        Err(format!("{prefix}: {}", blockers.join("; ")))
    }
}

fn iface_exists_in_sysfs(iface: &str) -> bool {
    !iface.is_empty() && Path::new("/sys/class/net").join(iface).exists()
}

pub(crate) fn resident_kernel_feature_checks(
    lan_ifaces: &[String],
    wan_ifaces: &[String],
) -> Vec<Value> {
    let mut checks = Vec::new();
    let lan_configured = !lan_ifaces.is_empty();
    let wan_configured = !wan_ifaces.is_empty();
    match current_kernel_version() {
        Ok(version) => {
            let report = FeatureGateReport::new(version, lan_configured, wan_configured);
            let missing = report.missing.clone();
            push_check(
                &mut checks,
                "resident-kernel-feature-gate",
                report.allowed(),
                json!({
                    "kernel_version": version.display_string(),
                    "kernel_code": version.kernel_code(),
                    "lan_configured": lan_configured,
                    "wan_configured": wan_configured,
                    "missing_features": missing,
                    "required_features": [
                        "basic",
                        "checksum",
                        "bpf_loop",
                        "sk_assign_for_lan",
                        "bpf_timer_for_wan"
                    ],
                }),
                "resident kernel is missing required eBPF features",
            );
        }
        Err(err) => push_check(
            &mut checks,
            "resident-kernel-feature-gate",
            false,
            json!({
                "error": err.to_string(),
                "lan_configured": lan_configured,
                "wan_configured": wan_configured,
            }),
            "resident kernel version could not be determined",
        ),
    }
    checks
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

pub(super) fn configure_resident_kernel_parameters(
    steps: &mut Vec<Value>,
    auto_config: bool,
    lan_ifaces: &[String],
    wan_ifaces: &[String],
) -> Value {
    if !auto_config {
        return json!({
            "name": "resident-kernel-parameters",
            "status": "skipped",
            "auto_config_kernel_parameter": false,
            "reason": "global.auto_config_kernel_parameter is false",
            "lan_interfaces": lan_ifaces,
            "wan_interfaces": wan_ifaces,
        });
    }

    let ipv4_forwarding_ok = run_step(
        steps,
        "set-resident-global-ipv4-forwarding-on",
        CommandSpec::new("sysctl", ["-w", "net.ipv4.ip_forward=1"]),
    );
    let ipv6_forwarding_ok = run_step(
        steps,
        "set-resident-global-ipv6-forwarding-on",
        CommandSpec::new("sysctl", ["-w", "net.ipv6.conf.all.forwarding=1"]),
    );
    let lan_reports = lan_ifaces
        .iter()
        .map(|iface| configure_resident_lan_kernel_parameters(steps, iface))
        .collect::<Vec<_>>();
    let wan_reports = wan_ifaces
        .iter()
        .map(|iface| configure_resident_wan_accept_ra(steps, iface, !lan_ifaces.is_empty()))
        .collect::<Vec<_>>();
    let lan_ok = lan_reports
        .iter()
        .all(|report| report["status"].as_str() == Some("pass"));
    let wan_ok = wan_reports
        .iter()
        .all(|report| matches!(report["status"].as_str(), Some("pass") | Some("skipped")));
    json!({
        "name": "resident-kernel-parameters",
        "status": if ipv4_forwarding_ok && ipv6_forwarding_ok && lan_ok && wan_ok { "pass" } else { "warn" },
        "auto_config_kernel_parameter": true,
        "global": {
            "ipv4_forwarding_on": ipv4_forwarding_ok,
            "ipv6_forwarding_on": ipv6_forwarding_ok,
        },
        "lan": lan_reports,
        "wan": wan_reports,
        "source_parity": "native NewControlPlane AutoConfigKernelParameter SetIpv4forward(1), setForwarding(all, ipv6, 1), bindLan per-interface forwarding/send_redirects, and WAN accept_ra workaround",
    })
}

fn configure_resident_lan_kernel_parameters(steps: &mut Vec<Value>, iface: &str) -> Value {
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

fn configure_resident_wan_accept_ra(
    steps: &mut Vec<Value>,
    iface: &str,
    lan_configured: bool,
) -> Value {
    if !lan_configured {
        return json!({
            "name": format!("resident-wan-accept-ra-{iface}"),
            "status": "skipped",
            "interface": iface,
            "reason": "LAN is not configured; native accept_ra workaround is not required",
        });
    }
    let read = super::command::run_observation_step(
        steps,
        &format!("read-resident-wan-{iface}-ipv6-accept-ra"),
        CommandSpec::new(
            "sysctl",
            ["-n", &format!("net.ipv6.conf.{iface}.accept_ra")],
        ),
    );
    let current = read["stdout"]
        .as_str()
        .unwrap_or_default()
        .trim()
        .to_owned();
    if read["status"].as_str() != Some("pass") {
        return json!({
            "name": format!("resident-wan-accept-ra-{iface}"),
            "status": "warn",
            "interface": iface,
            "read": read,
            "reason": "failed to read WAN accept_ra before native workaround",
        });
    }
    if current != "1" {
        return json!({
            "name": format!("resident-wan-accept-ra-{iface}"),
            "status": "skipped",
            "interface": iface,
            "current": current,
            "reason": "native workaround only changes accept_ra from 1 to 2",
        });
    }
    let set_ok = run_step(
        steps,
        &format!("set-resident-wan-{iface}-ipv6-accept-ra-2"),
        CommandSpec::new(
            "sysctl",
            ["-w", &format!("net.ipv6.conf.{iface}.accept_ra=2")],
        ),
    );
    json!({
        "name": format!("resident-wan-accept-ra-{iface}"),
        "status": if set_ok { "pass" } else { "warn" },
        "interface": iface,
        "previous": current,
        "set_to": 2,
        "source_parity": "native LAN+WAN autoConfigKernelParameter accept_ra workaround",
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
        let configured = [
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
        let configured = [
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
        let configured = ["auto".to_owned()];
        let err =
            configured_wan_ifaces_from_values(configured.iter(), || Ok(Vec::new())).unwrap_err();
        assert!(err.contains("wan_interface auto"));
    }

    #[test]
    fn resident_interface_validation_rejects_missing_lan() {
        let checks = resident_interface_validation_checks(&[], &[]);
        assert_eq!(checks[0]["status"], json!("fail"));
        assert_eq!(
            checks[0]["blocker"],
            json!("global.lan_interface must specify at least one existing LAN interface")
        );
    }

    #[test]
    fn resident_interface_validation_rejects_lan_auto() {
        let checks = resident_interface_validation_checks(&["auto".to_owned()], &[]);
        assert!(checks.iter().any(|check| {
            check["name"].as_str() == Some("resident-lan-interface-valid-auto")
                && check["status"].as_str() == Some("fail")
        }));
    }

    #[test]
    fn resident_interface_validation_rejects_wan_loopback() {
        let checks = resident_interface_validation_checks(&["lo".to_owned()], &["lo".to_owned()]);
        assert!(checks.iter().any(|check| {
            check["name"].as_str() == Some("resident-wan-interface-valid-lo")
                && check["status"].as_str() == Some("fail")
        }));
    }
}
