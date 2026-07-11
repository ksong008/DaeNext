use super::*;

#[derive(Clone, Debug)]
pub(super) struct PreparedSubscriptionNode {
    pub(super) stored_link: String,
    pub(super) parsed: ParsedNodeLink,
}

pub(super) fn prepare_subscription_nodes(links: &[String]) -> Vec<PreparedSubscriptionNode> {
    links
        .iter()
        .map(|link| {
            let parsed = parse_node_link(link, None);
            let stored_link = parsed
                .normalized_link
                .clone()
                .unwrap_or_else(|| link.clone());
            PreparedSubscriptionNode {
                stored_link,
                parsed,
            }
        })
        .collect()
}
