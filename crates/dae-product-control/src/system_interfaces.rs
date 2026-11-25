use std::collections::HashMap;
use std::fs;
use std::io;

use serde_json::{Map, Value, json};

mod lan;
#[cfg(target_os = "linux")]
mod netlink;

pub fn list_system_interfaces(up: Option<bool>, only_global_scope: bool) -> io::Result<Vec<Value>> {
    #[cfg(target_os = "linux")]
    let native = netlink::interfaces(only_global_scope);
    #[cfg(not(target_os = "linux"))]
    let native = {
        let _ = only_global_scope;
        Err(io::Error::from(io::ErrorKind::Unsupported))
    };
    let mut items = native.or_else(|_| sysfs_interfaces(None, &HashMap::new()))?;
    lan::annotate_lan_recommendations(&mut items);
    items.retain(|item| up.is_none_or(|wanted| item["up"].as_bool() == Some(wanted)));
    Ok(items)
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
