use dae_outbound::parse_link_chain;
use url::Url;

pub(super) fn reject_requested_udp_passthrough(source: &str, node_tag: &str) -> Result<(), String> {
    let Ok(parsed) = parse_link_chain(source) else {
        // Preserve the protocol builder's existing parse error for malformed
        // sources. This guard owns only the admitted passthrough option.
        return Ok(());
    };
    if !parsed
        .nodes
        .iter()
        .any(|node| source_node_requests_udp_passthrough(&node.raw))
    {
        return Ok(());
    }

    Err(format!(
        "resident dataplane does not admit {}=true for node {node_tag}; requested UDP passthrough has no resident executor and remains fail-closed",
        dae_outbound::shared_transport::contract::UDP_PASSTHROUGH_KEY,
    ))
}

fn source_node_requests_udp_passthrough(source: &str) -> bool {
    Url::parse(source).is_ok_and(|url| {
        url.query_pairs().any(|(key, value)| {
            key == dae_outbound::shared_transport::contract::UDP_PASSTHROUGH_KEY
                && value.eq_ignore_ascii_case("true")
        })
    })
}
