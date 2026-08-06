use super::*;

#[derive(Clone, Debug)]
pub(super) struct PreparedSubscriptionNode {
    pub(super) stored_link: String,
    pub(super) parsed: ParsedNodeLink,
}

#[derive(Clone, Debug)]
pub(super) struct RejectedSubscriptionNode {
    pub(super) link: String,
    pub(super) reason: String,
}

#[derive(Clone, Debug, Default)]
pub(super) struct PreparedSubscriptionNodes {
    pub(super) admitted: Vec<PreparedSubscriptionNode>,
    pub(super) invalid: Vec<RejectedSubscriptionNode>,
    pub(super) not_admitted: Vec<RejectedSubscriptionNode>,
}

#[derive(Clone, Debug)]
pub(super) struct PreparedSubscriptionRefresh {
    pub(super) content_kind: content::SubscriptionContentKind,
    pub(super) source_node_count: usize,
    pub(super) invalid_source_count: usize,
    pub(super) empty: bool,
    pub(super) nodes: PreparedSubscriptionNodes,
    pub(super) persist_content: bool,
}

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
