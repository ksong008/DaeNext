use super::*;

fn encoded_template() -> &'static str {
    "%2F.well-known%2Fmasque%2Fudp%2F%7Btarget_host%7D%2F%7Btarget_port%7D%2F"
}

#[test]
fn explicit_h2_basic_shape_parses_without_inference() {
    let raw = format!(
        "masque://user:p%40ss@proxy.example:8443?transport=h2&auth=basic&template={}&sni=masque.example&allowInsecure=0#edge",
        encoded_template()
    );
    let link = MasqueLink::parse(&raw).unwrap();
    assert_eq!(link.transport, MasqueTransport::H2);
    assert_eq!(link.transport.alpn(), "h2");
    assert_eq!(link.sni, "masque.example");
    assert_eq!(link.address(), "proxy.example:8443");
    assert_eq!(link.name, "edge");
    assert_eq!(
        link.authentication,
        MasqueAuthentication::Basic {
            username: "user".to_owned(),
            password: "p@ss".to_owned(),
        }
    );
    assert_eq!(
        link.target_template,
        "/.well-known/masque/udp/{target_host}/{target_port}/"
    );
}

#[test]
fn explicit_h3_no_auth_shape_parses() {
    let raw = format!(
        "masque://[2001:db8::1]:9443?transport=h3&auth=none&template={}",
        encoded_template()
    );
    let link = MasqueLink::parse(&raw).unwrap();
    assert_eq!(link.transport, MasqueTransport::H3);
    assert_eq!(link.transport.alpn(), "h3");
    assert_eq!(link.address(), "[2001:db8::1]:9443");
    assert_eq!(link.authentication, MasqueAuthentication::None);
}

#[test]
fn ordinary_http_and_implicit_shapes_are_rejected() {
    for raw in [
        "https://proxy.example:443/?transport=h2&auth=none&template=%7Btarget_host%7D%2F%7Btarget_port%7D",
        "masque://proxy.example:443?auth=none&template=%7Btarget_host%7D%2F%7Btarget_port%7D",
        "masque://proxy.example:443?transport=h2&auth=none",
        "masque://proxy.example:443?transport=h1&auth=none&template=%7Btarget_host%7D%2F%7Btarget_port%7D",
    ] {
        assert!(MasqueLink::parse(raw).is_err(), "{raw}");
    }
}

#[test]
fn authentication_and_query_typos_fail_closed() {
    let template = encoded_template();
    for raw in [
        format!("masque://user@proxy.example:443?transport=h2&auth=none&template={template}"),
        format!("masque://proxy.example:443?transport=h2&auth=basic&template={template}"),
        format!(
            "masque://proxy.example:443?transport=h2&auth=none&template={template}&fallback=h3"
        ),
        format!(
            "masque://proxy.example:443?transport=h2&transport=h3&auth=none&template={template}"
        ),
    ] {
        assert!(MasqueLink::parse(&raw).is_err(), "{raw}");
    }
}

#[test]
fn generic_link_parser_reports_explicit_connect_udp_identity() {
    let raw = format!(
        "masque://proxy.example:9443?transport=h3&auth=none&template={}#edge",
        encoded_template()
    );
    let parsed = crate::parse_link_chain(&raw).unwrap();
    assert_eq!(parsed.property_protocol, "connect-udp");
    assert_eq!(parsed.property_address, "proxy.example:9443");
    assert_eq!(parsed.property_name, "edge");
    assert_eq!(parsed.nodes.len(), 1);
    assert_eq!(parsed.nodes[0].scheme, "masque");
    assert!(parsed.nodes[0].parent_dialer_non_nil);
}
