use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;

#[test]
fn origin_form_template_expands_ipv4_and_builds_request_uri() {
    let template = MasqueUriTemplate::parse(
        "/.well-known/masque/udp/{target_host}/{target_port}/?mode=packet",
    )
    .unwrap();
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)), 5353);
    assert_eq!(
        template.expand(target).unwrap(),
        "/.well-known/masque/udp/192.0.2.9/5353/?mode=packet"
    );
    assert_eq!(
        template
            .expand_request_uri(target, "proxy.example:8443")
            .unwrap()
            .to_string(),
        "https://proxy.example:8443/.well-known/masque/udp/192.0.2.9/5353/?mode=packet"
    );
}

#[test]
fn ipv6_target_host_is_uri_template_percent_encoded() {
    let template = MasqueUriTemplate::parse("/udp/{target_host}/{target_port}/").unwrap();
    let target = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
    assert_eq!(template.expand(target).unwrap(), "/udp/%3A%3A1/443/");
}

#[test]
fn absolute_https_template_is_preserved() {
    let template = MasqueUriTemplate::parse(
        "https://virtual.example/tunnel?host={target_host}&port={target_port}",
    )
    .unwrap();
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
    assert_eq!(
        template
            .expand_request_uri(target, "ignored.example:443")
            .unwrap()
            .to_string(),
        "https://virtual.example/tunnel?host=127.0.0.1&port=53"
    );
}

#[test]
fn malformed_or_ambiguous_templates_are_rejected() {
    for template in [
        "",
        "/udp/{target_host}/",
        "/udp/{target_host}/{target_host}/{target_port}/",
        "/udp/{target_host}/{target_port}/{unknown}/",
        "/udp/{target_host}/{target_port}/#fragment",
        "http://proxy.example/udp/{target_host}/{target_port}/",
        "relative/{target_host}/{target_port}",
        "/udp/{target_host}/{target_port}/\n",
    ] {
        assert!(MasqueUriTemplate::parse(template).is_err(), "{template:?}");
    }
}
