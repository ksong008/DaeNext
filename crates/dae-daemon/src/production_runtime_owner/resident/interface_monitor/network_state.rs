use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::Path;

use dae_config::Config;
use serde_json::{Value, json};

mod ipv4_addresses;
mod procfs;
#[cfg(test)]
mod tests;

use ipv4_addresses::ipv4_interface_addresses;
use procfs::{
    parse_ipv4_default_routes, parse_ipv6_default_routes, parse_ipv6_interface_addresses,
    read_optional_proc_file,
};

const PROC_IPV4_ROUTE: &str = "/proc/net/route";
const PROC_IPV6_ROUTE: &str = "/proc/net/ipv6_route";
const PROC_IPV6_ADDRESS: &str = "/proc/net/if_inet6";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum NetworkFamily {
    Ipv4,
    Ipv6,
}

impl NetworkFamily {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct DefaultRouteFingerprint {
    pub(super) family: NetworkFamily,
    pub(super) interface: String,
    pub(super) gateway: IpAddr,
    pub(super) metric: u32,
}

impl DefaultRouteFingerprint {
    fn to_json(&self) -> Value {
        json!({
            "family": self.family.as_str(),
            "interface": self.interface,
            "gateway": self.gateway.to_string(),
            "metric": self.metric,
        })
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct InterfaceAddressFingerprint {
    pub(super) family: NetworkFamily,
    pub(super) address: IpAddr,
    pub(super) prefix_len: u8,
    pub(super) peer: Option<IpAddr>,
    pub(super) scope: u8,
}

impl InterfaceAddressFingerprint {
    fn to_json(&self) -> Value {
        json!({
            "family": self.family.as_str(),
            "address": self.address.to_string(),
            "prefixLength": self.prefix_len,
            "peer": self.peer.map(|peer| peer.to_string()),
            "scope": self.scope,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct WanMonitorPolicy {
    pub(super) auto_enabled: bool,
    pub(super) explicit_ifaces: BTreeSet<String>,
    pub(super) initial_resolved_ifaces: BTreeSet<String>,
}

impl WanMonitorPolicy {
    pub(super) fn from_config(config: &Config, resolved_wan_ifaces: &[String]) -> Self {
        let mut auto_enabled = false;
        let mut explicit_ifaces = BTreeSet::new();
        for iface in config.global.wan_interface.iter().flatten() {
            let iface = iface.trim();
            if iface.is_empty() {
                continue;
            }
            if iface.eq_ignore_ascii_case("auto") {
                auto_enabled = true;
            } else {
                explicit_ifaces.insert(iface.to_owned());
            }
        }
        let initial_resolved_ifaces = resolved_wan_ifaces
            .iter()
            .map(|iface| iface.trim())
            .filter(|iface| !iface.is_empty())
            .map(str::to_owned)
            .collect();
        Self {
            auto_enabled,
            explicit_ifaces,
            initial_resolved_ifaces,
        }
    }

    pub(super) fn current_required_ifaces(&self, state: &WanNetworkState) -> BTreeSet<String> {
        let mut ifaces = if self.auto_enabled {
            state.auto_route_ifaces.iter().cloned().collect()
        } else {
            self.initial_resolved_ifaces.clone()
        };
        ifaces.extend(self.explicit_ifaces.iter().cloned());
        ifaces
    }

    fn monitoring_enabled(&self) -> bool {
        self.auto_enabled
            || !self.explicit_ifaces.is_empty()
            || !self.initial_resolved_ifaces.is_empty()
    }

    pub(super) fn initial_auto_ifaces(&self) -> BTreeSet<String> {
        if !self.auto_enabled {
            return BTreeSet::new();
        }
        self.initial_resolved_ifaces
            .difference(&self.explicit_ifaces)
            .cloned()
            .collect()
    }

    pub(super) fn auto_route_set_changed_from_initial(
        &self,
        current_auto_ifaces: &BTreeSet<String>,
    ) -> bool {
        let known_initial_auto_ifaces = self.initial_auto_ifaces();
        !known_initial_auto_ifaces.is_subset(current_auto_ifaces)
            || current_auto_ifaces
                .iter()
                .any(|iface| !self.initial_resolved_ifaces.contains(iface))
    }

    fn observed_ifaces(&self, routes: &[DefaultRouteFingerprint]) -> BTreeSet<String> {
        let mut ifaces = self.initial_resolved_ifaces.clone();
        ifaces.extend(self.explicit_ifaces.iter().cloned());
        if self.auto_enabled {
            ifaces.extend(routes.iter().map(|route| route.interface.clone()));
        }
        ifaces
    }

    fn route_is_relevant(&self, route: &DefaultRouteFingerprint) -> bool {
        self.auto_enabled
            || self.initial_resolved_ifaces.contains(&route.interface)
            || self.explicit_ifaces.contains(&route.interface)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct WanNetworkState {
    pub(super) routes: Vec<DefaultRouteFingerprint>,
    pub(super) addresses: BTreeMap<String, Vec<InterfaceAddressFingerprint>>,
    pub(super) auto_route_ifaces: Vec<String>,
    pub(super) errors: Vec<String>,
}

impl WanNetworkState {
    fn empty_verified() -> Self {
        Self {
            routes: Vec::new(),
            addresses: BTreeMap::new(),
            auto_route_ifaces: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub(super) fn verified(&self) -> bool {
        self.errors.is_empty()
    }

    pub(super) fn to_json(&self) -> Value {
        let addresses = self
            .addresses
            .iter()
            .map(|(iface, addresses)| {
                (
                    iface.clone(),
                    Value::Array(
                        addresses
                            .iter()
                            .map(InterfaceAddressFingerprint::to_json)
                            .collect(),
                    ),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        json!({
            "status": if self.verified() { "pass" } else { "unverified" },
            "autoRouteInterfaces": self.auto_route_ifaces,
            "defaultRoutes": self.routes.iter().map(DefaultRouteFingerprint::to_json).collect::<Vec<_>>(),
            "addresses": addresses,
            "errors": self.errors,
        })
    }
}

pub(super) fn observe_wan_network_state(policy: &WanMonitorPolicy) -> WanNetworkState {
    if !policy.monitoring_enabled() {
        return WanNetworkState::empty_verified();
    }
    observe_wan_network_state_from_paths(
        policy,
        Path::new(PROC_IPV4_ROUTE),
        Path::new(PROC_IPV6_ROUTE),
        Path::new(PROC_IPV6_ADDRESS),
    )
}

fn observe_wan_network_state_from_paths(
    policy: &WanMonitorPolicy,
    ipv4_route_path: &Path,
    ipv6_route_path: &Path,
    ipv6_address_path: &Path,
) -> WanNetworkState {
    let mut errors = Vec::new();
    let mut routes = Vec::new();
    read_routes(
        ipv4_route_path,
        parse_ipv4_default_routes,
        &mut routes,
        &mut errors,
    );
    read_routes(
        ipv6_route_path,
        parse_ipv6_default_routes,
        &mut routes,
        &mut errors,
    );
    routes.retain(|route| route.interface != "lo" && policy.route_is_relevant(route));
    routes.sort();
    routes.dedup();

    let auto_route_ifaces = if policy.auto_enabled {
        routes
            .iter()
            .map(|route| route.interface.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    } else {
        Vec::new()
    };
    let observed_ifaces = policy.observed_ifaces(&routes);
    let mut addresses = observed_ifaces
        .iter()
        .map(|iface| (iface.clone(), Vec::new()))
        .collect::<BTreeMap<_, _>>();

    if !observed_ifaces.is_empty() {
        match ipv4_interface_addresses(&observed_ifaces) {
            Ok(values) => merge_addresses(&mut addresses, values),
            Err(err) => errors.push(format!("read IPv4 interface addresses: {err}")),
        }
    }
    match read_optional_proc_file(ipv6_address_path) {
        Ok(content) => match parse_ipv6_interface_addresses(&content, &observed_ifaces) {
            Ok(values) => merge_addresses(&mut addresses, values),
            Err(err) => errors.push(format!("parse {}: {err}", ipv6_address_path.display())),
        },
        Err(err) => errors.push(format!("read {}: {err}", ipv6_address_path.display())),
    }
    for values in addresses.values_mut() {
        values.sort();
        values.dedup();
    }

    WanNetworkState {
        routes,
        addresses,
        auto_route_ifaces,
        errors,
    }
}

fn read_routes(
    path: &Path,
    parse: fn(&str) -> Result<Vec<DefaultRouteFingerprint>, String>,
    routes: &mut Vec<DefaultRouteFingerprint>,
    errors: &mut Vec<String>,
) {
    match read_optional_proc_file(path) {
        Ok(content) => match parse(&content) {
            Ok(parsed) => routes.extend(parsed),
            Err(err) => errors.push(format!("parse {}: {err}", path.display())),
        },
        Err(err) => errors.push(format!("read {}: {err}", path.display())),
    }
}

fn merge_addresses(
    target: &mut BTreeMap<String, Vec<InterfaceAddressFingerprint>>,
    values: BTreeMap<String, Vec<InterfaceAddressFingerprint>>,
) {
    for (iface, mut values) in values {
        target.entry(iface).or_default().append(&mut values);
    }
}
