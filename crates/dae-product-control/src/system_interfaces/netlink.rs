use std::collections::BTreeMap;
use std::ffi::CStr;
use std::io;

use dae_netutil::rtnetlink::{address_attr, default_routes, dump, find_attr, malformed, read_u32};
use serde_json::{Value, json};

struct Interface {
    name: String,
    up: bool,
    addresses: Vec<String>,
    details: Vec<Value>,
    routes: Vec<Value>,
}

pub(super) fn interfaces(only_global_scope: bool) -> io::Result<Vec<Value>> {
    let mut links = BTreeMap::new();
    dump(libc::RTM_GETLINK, &[0; 16], libc::RTM_NEWLINK, |data| {
        let header = data.get(..16).ok_or_else(malformed)?;
        let index = read_u32(&header[4..8])?;
        let flags = read_u32(&header[8..12])?;
        let name = find_attr(&data[16..], libc::IFLA_IFNAME)?.ok_or_else(malformed)?;
        let name = CStr::from_bytes_with_nul(name)
            .map_err(|_| malformed())?
            .to_string_lossy()
            .into_owned();
        links.insert(
            index,
            Interface {
                name,
                up: flags & libc::IFF_UP as u32 != 0,
                addresses: Vec::new(),
                details: Vec::new(),
                routes: Vec::new(),
            },
        );
        Ok(())
    })?;

    dump(libc::RTM_GETADDR, &[0; 8], libc::RTM_NEWADDR, |data| {
        let header = data.get(..8).ok_or_else(malformed)?;
        let family = header[0];
        let family_name = match i32::from(family) {
            libc::AF_INET => "inet",
            libc::AF_INET6 => "inet6",
            _ => return Ok(()),
        };
        let scope = header[3];
        if only_global_scope && scope != libc::RT_SCOPE_UNIVERSE {
            return Ok(());
        }
        let index = read_u32(&header[4..8])?;
        let Some(link) = links.get_mut(&index) else {
            return Ok(());
        };
        let attrs = &data[8..];
        let address = match address_attr(attrs, libc::IFA_LOCAL, family)? {
            local @ Some(_) => local,
            None => address_attr(attrs, libc::IFA_ADDRESS, family)?,
        };
        if let Some(address) = address {
            let prefix = header[1];
            link.addresses.push(format!("{address}/{prefix}"));
            link.details.push(json!({
                "family": family_name,
                "local": address,
                "prefixlen": prefix,
                "scope": scope_name(scope),
            }));
        }
        Ok(())
    })?;

    for (family, version) in [(libc::AF_INET, "4"), (libc::AF_INET6, "6")] {
        let Ok(routes) = default_routes(family as u8) else {
            continue;
        };
        for route in routes {
            let Some(link) = links.get_mut(&route.ifindex) else {
                continue;
            };
            let mut item = json!({"ipVersion": version});
            if let Some(gateway) = route.gateway {
                item["gateway"] = json!(gateway);
            }
            if let Some(source) = route.preferred_source {
                item["source"] = json!(source);
            }
            link.routes.push(item);
        }
    }

    Ok(links
        .into_iter()
        .map(|(index, link)| {
            let mut item = json!({
                "name": link.name,
                "index": index,
                "up": link.up,
                "addresses": link.addresses,
                "addressDetails": link.details,
            });
            if !link.routes.is_empty() {
                item["defaultRoutes"] = json!(link.routes);
            }
            item
        })
        .collect())
}

fn scope_name(scope: u8) -> String {
    match scope {
        libc::RT_SCOPE_UNIVERSE => "global",
        libc::RT_SCOPE_SITE => "site",
        libc::RT_SCOPE_LINK => "link",
        libc::RT_SCOPE_HOST => "host",
        libc::RT_SCOPE_NOWHERE => "nowhere",
        _ => return scope.to_string(),
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_loopback_addresses_and_applies_global_scope_filter() {
        for only_global in [false, true] {
            let links = interfaces(only_global).unwrap();
            let loopback = links.iter().find(|link| link["name"] == "lo").unwrap();
            let details = loopback["addressDetails"].as_array().unwrap();
            let ipv4 = details
                .iter()
                .find(|address| address["local"] == "127.0.0.1");
            if only_global {
                assert!(ipv4.is_none());
            } else {
                assert_eq!(
                    ipv4.unwrap(),
                    &json!({
                        "family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"
                    })
                );
            }
        }
    }
}
