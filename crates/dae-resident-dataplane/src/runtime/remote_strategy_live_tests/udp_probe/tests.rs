use dae_runtime_control::OwnerGeneration;

use super::*;

#[test]
fn xhttp_udp_live_probe_owns_stream_up_and_packet_up_carriers() {
    for mode in ["stream-up", "packet-up"] {
        let config = xhttp_h3_config(mode);
        let proxy = Arc::new(
            plan::build_resident_proxy_plan_for_node(
                &config,
                "proxy".to_owned(),
                format!("xhttp_h3_{mode}"),
                xhttp_h3_link(mode),
            )
            .unwrap_or_else(|error| panic!("build xHTTP H3 {mode} probe plan: {error}")),
        );
        assert!(
            proxy.xhttp_xmux.is_some(),
            "{mode} must admit official xmux"
        );

        let binding = one_shot_udp_probe_binding(proxy)
            .unwrap_or_else(|error| panic!("bind xHTTP H3 {mode} UDP probe: {error}"));

        assert_eq!(binding.runtime_generation(), OwnerGeneration::new(0));
        assert_eq!(
            binding.xhttp_reuse_policy(),
            plan::ResidentXhttpReusePolicy::NoPersistentReuse
        );
        assert!(binding.persistent_xhttp_xmux().is_none());
        assert!(binding.persistent_xhttp_download_xmux().is_none());
    }
}

fn xhttp_h3_config(mode: &str) -> Config {
    let input = format!(
        r#"
global {{
  lan_interface: daerust0
  allow_insecure: false
  so_mark_from_dae: 0
  mptcp: false
}}
node {{
  xhttp_h3_{mode}: '{}'
}}
group {{
  proxy {{
    filter: name(xhttp_h3_{mode})
    policy: fixed(0)
  }}
}}
routing {{
  fallback: proxy
}}
dns {{}}
"#,
        xhttp_h3_link(mode)
    );
    let sections = dae_config::parser::parse_config(&input)
        .unwrap_or_else(|error| panic!("parse xHTTP H3 {mode} probe config: {error}"));
    dae_config::schema::build_config(&sections)
        .unwrap_or_else(|error| panic!("build xHTTP H3 {mode} probe config: {error}"))
}

fn xhttp_h3_link(mode: &str) -> String {
    format!(
        "vless://00000000-0000-4000-8000-000000000001@127.0.0.1:443?type=xhttp&security=tls&sni=xhttp.invalid&allowInsecure=1&alpn=h3&fp=chrome&path=%2Fprobe&mode={mode}#xhttp-h3-{mode}"
    )
}
