use super::*;
use dae_product_control::subscription::parse_node_link;
pub(super) use dae_product_control::subscription::{
    PreparedSubscriptionNode, PreparedSubscriptionNodes, PreparedSubscriptionRefresh,
    RejectedSubscriptionNode,
};

pub(super) fn prepare_subscription_refresh(
    content: &content::SubscriptionContentReport,
) -> PreparedSubscriptionRefresh {
    PreparedSubscriptionRefresh {
        content_kind: content.kind,
        source_node_count: content.source_node_count,
        invalid_source_count: content.invalid_source_count,
        empty: content.empty,
        nodes: prepare_subscription_nodes(&content.links),
        persist_content: false,
    }
}

pub(super) fn prepare_subscription_nodes(links: &[String]) -> PreparedSubscriptionNodes {
    let admissions = resident_node_source_admissions(links);
    let mut prepared = PreparedSubscriptionNodes {
        admitted: Vec::with_capacity(links.len()),
        invalid: Vec::new(),
        not_admitted: Vec::new(),
    };
    for (link, admission) in links.iter().zip(admissions) {
        match admission {
            ResidentNodeSourceAdmission::Admitted => {
                let parsed = parse_node_link(link, None);
                let stored_link = parsed
                    .normalized_link
                    .clone()
                    .unwrap_or_else(|| link.to_string());
                prepared.admitted.push(PreparedSubscriptionNode {
                    stored_link,
                    parsed,
                });
            }
            ResidentNodeSourceAdmission::Invalid { reason } => {
                prepared.invalid.push(RejectedSubscriptionNode {
                    link: link.to_string(),
                    reason,
                });
            }
            ResidentNodeSourceAdmission::NotAdmitted { reason } => {
                prepared.not_admitted.push(RejectedSubscriptionNode {
                    link: link.to_string(),
                    reason,
                });
            }
        }
    }
    prepared
}
