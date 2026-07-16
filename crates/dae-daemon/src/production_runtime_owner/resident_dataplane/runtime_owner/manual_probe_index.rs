use super::*;

#[derive(Debug)]
pub(crate) struct ResidentManualProbeIndex {
    plans: BTreeMap<String, Result<plan::ResidentProxyProbePlan, String>>,
    links_by_hash: BTreeMap<String, Vec<String>>,
}

impl ResidentManualProbeIndex {
    pub(crate) fn new(
        plans: BTreeMap<String, Result<plan::ResidentProxyProbePlan, String>>,
    ) -> Self {
        let mut links_by_hash = BTreeMap::<String, Vec<String>>::new();
        for (link, candidate) in &plans {
            let Ok(candidate) = candidate else {
                continue;
            };
            links_by_hash
                .entry(candidate.link_hash.clone())
                .or_default()
                .push(link.clone());
        }
        Self {
            plans,
            links_by_hash,
        }
    }

    pub(crate) fn plans(&self) -> &BTreeMap<String, Result<plan::ResidentProxyProbePlan, String>> {
        &self.plans
    }

    pub(crate) fn links_for_hash(&self, link_hash: &str) -> Option<&[String]> {
        self.links_by_hash.get(link_hash).map(Vec::as_slice)
    }
}
