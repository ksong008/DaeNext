use super::*;

#[test]
fn effective_so_mark_defaults_to_control_plane_mark() {
    assert_eq!(
        effective_so_mark_from_dae(0),
        RESIDENT_CONTROL_PLANE_SO_MARK
    );
}

#[test]
fn effective_so_mark_preserves_user_mark() {
    assert_eq!(effective_so_mark_from_dae(17_185), 17_185);
}

#[test]
fn proxy_plan_defaults_zero_mark_to_control_plane_mark() {
    let link = socks5_endpoint_fixture_url(FixtureEndpoint::Primary);
    let config_source = r#"
    global {
        lan_interface: daerust0
    }
    node {
        proxy_node: '__LINK__'
    }
    group {
        proxy {
            filter: name(proxy_node)
            policy: fixed(0)
        }
    }
    routing {
        fallback: proxy
    }
    "#;
    let config = parse_config(&config_source.replace("__LINK__", &link));
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let proxy = plan
        .default_proxy_group()
        .unwrap()
        .select_proxy_for_tcp()
        .unwrap();
    assert_eq!(proxy.mark, RESIDENT_CONTROL_PLANE_SO_MARK);
}

#[test]
fn proxy_plan_preserves_user_mark() {
    let link = socks5_endpoint_fixture_url(FixtureEndpoint::Primary);
    let config_source = r#"
    global {
        lan_interface: daerust0
        so_mark_from_dae: 17185
    }
    node {
        proxy_node: '__LINK__'
    }
    group {
        proxy {
            filter: name(proxy_node)
            policy: fixed(0)
        }
    }
    routing {
        fallback: proxy
    }
    "#;
    let config = parse_config(&config_source.replace("__LINK__", &link));
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let proxy = plan
        .default_proxy_group()
        .unwrap()
        .select_proxy_for_tcp()
        .unwrap();
    assert_eq!(proxy.mark, 17_185);
}
