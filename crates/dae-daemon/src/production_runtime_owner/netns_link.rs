use serde_json::{Value, json};

use super::topology_netlink;

const NETNS_LINK_ENV: &str = "NETNS_LINK";
const NETNS_LINK_LEGACY_ENV: &str = "DAE_NETNS_LINK";
const NETNS_LINK_AUTO_POLICY: &str = "netkit_l2_scrub_none_then_compat_netkit_l2_then_veth";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetnsLinkMode {
    #[default]
    Auto,
    Veth,
    Netkit,
}

impl NetnsLinkMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Veth => "veth",
            Self::Netkit => "netkit",
        }
    }
}

pub fn parse_netns_link_mode(raw: &str) -> Result<NetnsLinkMode, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "auto" => Ok(NetnsLinkMode::Auto),
        "veth" => Ok(NetnsLinkMode::Veth),
        "netkit" => Ok(NetnsLinkMode::Netkit),
        _ => Err(format!(
            "invalid netns link mode {raw:?}, want auto, netkit, or veth"
        )),
    }
}

pub(super) fn resolve_netns_link_mode_from_env() -> Result<NetnsLinkMode, String> {
    std::env::var(NETNS_LINK_ENV)
        .or_else(|_| std::env::var(NETNS_LINK_LEGACY_ENV))
        .map(|raw| parse_netns_link_mode(&raw))
        .unwrap_or(Ok(NetnsLinkMode::Auto))
}

pub(super) fn netns_link_env_name() -> &'static str {
    NETNS_LINK_ENV
}

pub(super) fn setup_link_pair_with_auto_selection(
    steps: &mut Vec<Value>,
    scope: &str,
    host_iface: &str,
    peer_iface: &str,
    requested: NetnsLinkMode,
    setup_with: impl Fn(&mut Vec<Value>, NetnsLinkMode) -> bool,
    cleanup_failed_attempt: impl Fn(&mut Vec<Value>),
) -> bool {
    match requested {
        NetnsLinkMode::Veth | NetnsLinkMode::Netkit => {
            let ok = setup_with(steps, requested);
            push_selection_step(steps, scope, requested, requested, false, None, ok);
            ok
        }
        NetnsLinkMode::Auto => {
            let netkit_ok = setup_with(steps, NetnsLinkMode::Netkit);
            if netkit_ok {
                push_selection_step(
                    steps,
                    scope,
                    requested,
                    NetnsLinkMode::Netkit,
                    false,
                    None,
                    true,
                );
                return true;
            }

            cleanup_failed_attempt(steps);
            let veth_ok = setup_with(steps, NetnsLinkMode::Veth);
            push_selection_step(
                steps,
                scope,
                requested,
                NetnsLinkMode::Veth,
                true,
                Some("netkit_setup_failed"),
                veth_ok,
            );
            if !veth_ok {
                steps.push(json!({
                    "name": format!("{scope}-netns-link-auto-alternative-failed"),
                    "status": "fail",
                    "requested": requested.as_str(),
                    "host_iface": host_iface,
                    "peer_iface": peer_iface,
                    "reason": "netkit setup failed and veth alternative setup also failed",
                }));
            }
            veth_ok
        }
    }
}

pub(super) fn create_link_pair(
    steps: &mut Vec<Value>,
    step_scope: &str,
    host_iface: &str,
    peer_iface: &str,
    mode: NetnsLinkMode,
) -> bool {
    match mode {
        NetnsLinkMode::Veth => {
            topology_netlink::step(steps, &format!("create-{step_scope}-veth-pair"), || {
                topology_netlink::create_pair(host_iface, peer_iface, false, false)?;
                Ok(json!({"host": host_iface, "peer": peer_iface}))
            })["status"]
                == "pass"
        }
        NetnsLinkMode::Netkit => create_netkit_link_pair(steps, step_scope, host_iface, peer_iface),
        NetnsLinkMode::Auto => unreachable!("auto mode must be resolved before creating a link"),
    }
}

fn create_netkit_link_pair(
    steps: &mut Vec<Value>,
    step_scope: &str,
    host_iface: &str,
    peer_iface: &str,
) -> bool {
    let modern = topology_netlink::step(steps, &format!("create-{step_scope}-netkit-pair"), || {
        topology_netlink::create_pair(host_iface, peer_iface, true, true)?;
        Ok(json!({"host": host_iface, "peer": peer_iface, "scrub": "none"}))
    });
    if modern["status"] == "pass" {
        return true;
    }
    if !matches!(modern["errno"].as_i64(), Some(errno) if matches!(errno as i32, libc::EINVAL | libc::EOPNOTSUPP))
    {
        return false;
    }
    topology_netlink::step(
        steps,
        &format!("create-{step_scope}-netkit-pair-legacy-no-scrub"),
        || {
            topology_netlink::create_pair(host_iface, peer_iface, true, false)?;
            Ok(json!({"host": host_iface, "peer": peer_iface, "scrub": "kernel-default"}))
        },
    )["status"]
        == "pass"
}

pub(super) fn cleanup_partial_link_setup(
    steps: &mut Vec<Value>,
    step_scope: &str,
    netns: Option<&str>,
    host_iface: &str,
    peer_iface: &str,
) {
    if let Some(netns) = netns {
        topology_netlink::step(
            steps,
            &format!("cleanup-{step_scope}-netns-after-netkit-failure"),
            || {
                topology_netlink::delete_namespace(netns)?;
                Ok(json!({"netns": netns}))
            },
        );
    }
    for iface in [host_iface, peer_iface] {
        topology_netlink::step(
            steps,
            &format!("cleanup-{step_scope}-{iface}-after-netkit-failure"),
            || {
                topology_netlink::delete_link(iface)?;
                Ok(json!({"interface": iface}))
            },
        );
    }
}

fn push_selection_step(
    steps: &mut Vec<Value>,
    scope: &str,
    requested: NetnsLinkMode,
    selected: NetnsLinkMode,
    alternative_used: bool,
    alternative_reason: Option<&str>,
    ok: bool,
) {
    steps.push(json!({
        "name": format!("select-{scope}-netns-link-mode"),
        "status": if ok { "pass" } else { "fail" },
        "env": NETNS_LINK_ENV,
        "requested": requested.as_str(),
        "selected": selected.as_str(),
        "alternative_used": alternative_used,
        "alternative_reason": alternative_reason,
        "auto_policy": NETNS_LINK_AUTO_POLICY,
    }));
}

#[cfg(test)]
mod tests {
    use super::{NetnsLinkMode, parse_netns_link_mode};

    #[test]
    fn parses_compatible_netns_link_modes() {
        assert_eq!(parse_netns_link_mode("").unwrap(), NetnsLinkMode::Auto);
        assert_eq!(
            parse_netns_link_mode(" auto ").unwrap(),
            NetnsLinkMode::Auto
        );
        assert_eq!(parse_netns_link_mode("VETH").unwrap(), NetnsLinkMode::Veth);
        assert_eq!(
            parse_netns_link_mode("netkit").unwrap(),
            NetnsLinkMode::Netkit
        );
        assert!(parse_netns_link_mode("tcx").is_err());
    }
}
