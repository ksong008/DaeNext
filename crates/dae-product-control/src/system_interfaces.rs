use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::process::Command;

use serde_json::{Map, Value, json};

fn interface_address_entry(addr: &Value, only_global_scope: bool) -> Option<(String, Value)> {
    let scope = addr["scope"].as_str();
    if only_global_scope && scope.is_some_and(|value| value != "global") {
        return None;
    }
    let local = addr["local"].as_str()?.to_owned();
    let prefixlen = addr["prefixlen"].as_u64().unwrap_or(0);
    let family = addr["family"]
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| inferred_address_family(&local).to_owned());
    let display = format!("{local}/{prefixlen}");
    let mut detail = Map::new();
    detail.insert("family".to_owned(), json!(family));
    detail.insert("local".to_owned(), json!(local));
    detail.insert("prefixlen".to_owned(), json!(prefixlen));
    if let Some(scope) = scope.filter(|value| !value.is_empty()) {
        detail.insert("scope".to_owned(), json!(scope));
    }
    Some((display, Value::Object(detail)))
}

fn inferred_address_family(local: &str) -> &'static str {
    match local.parse::<IpAddr>() {
        Ok(addr) if addr.is_ipv6() => "inet6",
        _ => "inet",
    }
}

pub fn list_system_interfaces(up: Option<bool>, only_global_scope: bool) -> io::Result<Vec<Value>> {
    let routes_by_iface = default_routes_by_iface();
    match ip_address_interfaces(up, only_global_scope, &routes_by_iface) {
        Ok(items) => Ok(items),
        Err(_) => sysfs_interfaces(up, &routes_by_iface),
    }
}

pub fn ip_address_interfaces(
    up: Option<bool>,
    only_global_scope: bool,
    routes_by_iface: &HashMap<String, Vec<Value>>,
) -> io::Result<Vec<Value>> {
    let output = Command::new("ip")
        .args(["-j", "address", "show"])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("ip address query failed"));
    }
    let interfaces = serde_json::from_slice::<Value>(&output.stdout)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let mut items = Vec::new();
    for iface in interfaces.as_array().into_iter().flatten() {
        let name = iface["ifname"].as_str().unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let flags = iface["flags"].as_array().cloned().unwrap_or_default();
        let iface_up = flags
            .iter()
            .filter_map(Value::as_str)
            .any(|flag| flag.eq_ignore_ascii_case("UP"));
        if up.is_some_and(|wanted| wanted != iface_up) {
            continue;
        }
        let mut addresses = Vec::new();
        let mut address_details = Vec::new();
        for addr in iface["addr_info"].as_array().into_iter().flatten() {
            let Some((display, detail)) = interface_address_entry(addr, only_global_scope) else {
                continue;
            };
            addresses.push(display);
            address_details.push(detail);
        }
        let mut item = Map::new();
        item.insert("name".to_owned(), json!(name));
        item.insert("index".to_owned(), iface["ifindex"].clone());
        item.insert("up".to_owned(), json!(iface_up));
        item.insert("addresses".to_owned(), json!(addresses));
        item.insert("addressDetails".to_owned(), json!(address_details));
        if let Some(routes) = routes_by_iface
            .get(name)
            .filter(|routes| !routes.is_empty())
        {
            item.insert("defaultRoutes".to_owned(), json!(routes));
        }
        items.push(Value::Object(item));
    }
    Ok(items)
}

pub fn default_routes_by_iface() -> HashMap<String, Vec<Value>> {
    let mut out = HashMap::<String, Vec<Value>>::new();
    collect_default_routes(&mut out, "4", &["-j", "route", "show", "default"]);
    collect_default_routes(&mut out, "6", &["-j", "-6", "route", "show", "default"]);
    out
}

pub fn collect_default_routes(
    out: &mut HashMap<String, Vec<Value>>,
    ip_version: &str,
    args: &[&str],
) {
    let Ok(output) = Command::new("ip").args(args).output() else {
        return;
    };
    if !output.status.success() {
        return;
    }
    let Ok(routes) = serde_json::from_slice::<Value>(&output.stdout) else {
        return;
    };
    for route in routes.as_array().into_iter().flatten() {
        let Some(dev) = route["dev"].as_str().filter(|value| !value.is_empty()) else {
            continue;
        };
        let mut item = Map::new();
        item.insert("ipVersion".to_owned(), json!(ip_version));
        if let Some(gateway) = route["gateway"].as_str() {
            item.insert("gateway".to_owned(), json!(gateway));
        }
        if let Some(source) = route["prefsrc"].as_str().or_else(|| route["src"].as_str()) {
            item.insert("source".to_owned(), json!(source));
        }
        out.entry(dev.to_owned())
            .or_default()
            .push(Value::Object(item));
    }
}

pub fn sysfs_interfaces(
    up: Option<bool>,
    routes_by_iface: &HashMap<String, Vec<Value>>,
) -> io::Result<Vec<Value>> {
    let mut items = Vec::new();
    for entry in fs::read_dir("/sys/class/net")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let base = entry.path();
        let index = fs::read_to_string(base.join("ifindex"))
            .ok()
            .and_then(|value| value.trim().parse::<i64>().ok())
            .unwrap_or(0);
        let iface_up = fs::read_to_string(base.join("operstate"))
            .map(|value| matches!(value.trim(), "up" | "unknown"))
            .unwrap_or(false);
        if up.is_some_and(|wanted| wanted != iface_up) {
            continue;
        }
        let mut item = Map::new();
        item.insert("name".to_owned(), json!(name));
        item.insert("index".to_owned(), json!(index));
        item.insert("up".to_owned(), json!(iface_up));
        item.insert("addresses".to_owned(), json!([]));
        item.insert("addressDetails".to_owned(), json!([]));
        if let Some(routes) = routes_by_iface
            .get(&name)
            .filter(|routes| !routes.is_empty())
        {
            item.insert("defaultRoutes".to_owned(), json!(routes));
        }
        items.push(Value::Object(item));
    }
    items.sort_by(|left, right| {
        left["index"]
            .as_i64()
            .unwrap_or(i64::MAX)
            .cmp(&right["index"].as_i64().unwrap_or(i64::MAX))
    });
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_address_entry_preserves_ipv6_details() {
        let (display, detail) = interface_address_entry(
            &json!({
                "family": "inet6",
                "local": "2001:db8::1",
                "prefixlen": 64,
                "scope": "global",
            }),
            true,
        )
        .unwrap();

        assert_eq!(display, "2001:db8::1/64");
        assert_eq!(
            detail,
            json!({
                "family": "inet6",
                "local": "2001:db8::1",
                "prefixlen": 64,
                "scope": "global",
            })
        );
    }

    #[test]
    fn interface_address_entry_filters_non_global_scope_when_requested() {
        assert!(
            interface_address_entry(
                &json!({
                    "family": "inet6",
                    "local": "fe80::1",
                    "prefixlen": 64,
                    "scope": "link",
                }),
                true,
            )
            .is_none()
        );
    }

    #[test]
    fn interface_address_entry_keeps_missing_scope_for_legacy_ip_output() {
        let (display, detail) = interface_address_entry(
            &json!({
                "local": "192.0.2.10",
                "prefixlen": 24,
            }),
            true,
        )
        .unwrap();

        assert_eq!(display, "192.0.2.10/24");
        assert_eq!(
            detail,
            json!({
                "family": "inet",
                "local": "192.0.2.10",
                "prefixlen": 24,
            })
        );
    }
}
