use serde_json::{Value, json};

use super::command::{CommandSpec, run_step};

const NETNS_LINK_ENV: &str = "DAE_NETNS_LINK";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetnsLinkMode {
    Auto,
    Veth,
    Netkit,
}

impl Default for NetnsLinkMode {
    fn default() -> Self {
        Self::Auto
    }
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
            "invalid {NETNS_LINK_ENV}={raw:?}, want auto, netkit, or veth"
        )),
    }
}

pub(super) fn resolve_netns_link_mode_from_env() -> Result<NetnsLinkMode, String> {
    std::env::var(NETNS_LINK_ENV)
        .map(|raw| parse_netns_link_mode(&raw))
        .unwrap_or(Ok(NetnsLinkMode::Auto))
}

pub(super) fn netns_link_env_name() -> &'static str {
    NETNS_LINK_ENV
}

pub(super) fn setup_link_pair_with_auto_fallback(
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
                    "name": format!("{scope}-netns-link-auto-fallback-failed"),
                    "status": "fail",
                    "requested": requested.as_str(),
                    "host_iface": host_iface,
                    "peer_iface": peer_iface,
                    "reason": "netkit setup failed and veth fallback setup also failed",
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
        NetnsLinkMode::Veth => run_step(
            steps,
            &format!("create-{step_scope}-veth-pair"),
            CommandSpec::new(
                "ip",
                [
                    "link", "add", host_iface, "type", "veth", "peer", "name", peer_iface,
                ],
            ),
        ),
        NetnsLinkMode::Netkit => run_step(
            steps,
            &format!("create-{step_scope}-netkit-pair"),
            CommandSpec::new(
                "ip",
                [
                    "link", "add", host_iface, "type", "netkit", "mode", "l2", "scrub", "none",
                    "peer", "scrub", "none", "name", peer_iface,
                ],
            ),
        ),
        NetnsLinkMode::Auto => unreachable!("auto mode must be resolved before creating a link"),
    }
}

pub(super) fn cleanup_partial_link_setup(
    steps: &mut Vec<Value>,
    step_scope: &str,
    netns: Option<&str>,
    host_iface: &str,
    peer_iface: &str,
) {
    if let Some(netns) = netns {
        let _ = run_step(
            steps,
            &format!("cleanup-{step_scope}-netns-after-netkit-failure"),
            CommandSpec::new("ip", ["netns", "del", netns]),
        );
    }
    for iface in [host_iface, peer_iface] {
        let _ = run_step(
            steps,
            &format!("cleanup-{step_scope}-{iface}-after-netkit-failure"),
            CommandSpec::new("ip", ["link", "del", iface]),
        );
    }
}

fn push_selection_step(
    steps: &mut Vec<Value>,
    scope: &str,
    requested: NetnsLinkMode,
    selected: NetnsLinkMode,
    fallback_used: bool,
    fallback_reason: Option<&str>,
    ok: bool,
) {
    steps.push(json!({
        "name": format!("select-{scope}-netns-link-mode"),
        "status": if ok { "pass" } else { "fail" },
        "env": NETNS_LINK_ENV,
        "requested": requested.as_str(),
        "selected": selected.as_str(),
        "fallback_used": fallback_used,
        "fallback_reason": fallback_reason,
        "auto_policy": "netkit_l2_scrub_none_then_veth",
    }));
}

#[cfg(test)]
mod tests {
    use super::{NetnsLinkMode, parse_netns_link_mode};

    #[test]
    fn parses_go_compatible_netns_link_modes() {
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
