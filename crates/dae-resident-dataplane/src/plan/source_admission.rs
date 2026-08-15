use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResidentNodeSourceAdmission {
    Admitted,
    Invalid { reason: String },
    NotAdmitted { reason: String },
}

pub fn resident_node_source_admissions(links: &[String]) -> Vec<ResidentNodeSourceAdmission> {
    let config = source_admission_config();
    links
        .iter()
        .enumerate()
        .map(|(index, link)| resident_node_source_admission(&config, index, link))
        .collect()
}

fn resident_node_source_admission(
    config: &Config,
    index: usize,
    link: &str,
) -> ResidentNodeSourceAdmission {
    let link = link.trim();
    if link.is_empty() {
        return ResidentNodeSourceAdmission::Invalid {
            reason: "node source is empty".to_owned(),
        };
    }
    if let Err(err) = parse_link_chain(link) {
        return ResidentNodeSourceAdmission::Invalid {
            reason: format!("parse node source: {err}"),
        };
    }
    match build_resident_proxy_plan_for_node(
        config,
        "__subscription_source_admission".to_owned(),
        format!("__subscription_source_{index}"),
        link.to_owned(),
    ) {
        Ok(_) => ResidentNodeSourceAdmission::Admitted,
        Err(reason) => ResidentNodeSourceAdmission::NotAdmitted { reason },
    }
}

fn source_admission_config() -> Config {
    Config {
        global: Default::default(),
        subscription: Vec::new(),
        node: Vec::new(),
        group: Vec::new(),
        routing: Default::default(),
        dns: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_admission_uses_the_real_resident_builder() {
        let links = vec![
            "socks://127.0.0.1:1080#valid".to_owned(),
            "missing-scheme".to_owned(),
            "unknown://127.0.0.1:1#unsupported".to_owned(),
        ];

        let results = resident_node_source_admissions(&links);

        assert_eq!(results[0], ResidentNodeSourceAdmission::Admitted);
        assert!(matches!(
            results[1],
            ResidentNodeSourceAdmission::Invalid { .. }
        ));
        assert!(matches!(
            results[2],
            ResidentNodeSourceAdmission::NotAdmitted { .. }
        ));
    }
}
