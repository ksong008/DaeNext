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
