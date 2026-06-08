pub(super) fn build_resident_proxy_plan_for_node(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    build_proxy_plan(config, group_name, node_tag, link)
}

pub(super) fn resident_node_link_shapes(config: &Config) -> Vec<ResidentNodeLinkShape> {
    tagged_node_links(config)
        .into_iter()
        .map(|(tag, link)| ResidentNodeLinkShape {
            tag,
            scheme: link_scheme(&link).unwrap_or_default(),
            link,
        })
        .collect()
}
