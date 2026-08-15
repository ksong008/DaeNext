use super::*;

#[derive(Debug)]
pub(crate) struct ResidentManualProbeIndex {
    config: Option<Arc<Config>>,
    reload_generation: u64,
    plans_by_identity: Mutex<BTreeMap<String, Result<plan::ResidentProxyProbePlan, String>>>,
    links_by_hash: Mutex<BTreeMap<String, Vec<String>>>,
}

impl ResidentManualProbeIndex {
    pub(crate) fn lazy(config: Arc<Config>, reload_generation: u64) -> Self {
        Self {
            config: Some(config),
            reload_generation,
            plans_by_identity: Mutex::new(BTreeMap::new()),
            links_by_hash: Mutex::new(BTreeMap::new()),
        }
    }

    #[cfg(test)]
    pub(crate) fn new(
        plans: BTreeMap<String, Result<plan::ResidentProxyProbePlan, String>>,
    ) -> Self {
        let index = Self {
            config: None,
            reload_generation: 0,
            plans_by_identity: Mutex::new(BTreeMap::new()),
            links_by_hash: Mutex::new(BTreeMap::new()),
        };
        for (link, plan) in plans {
            index.cache_plan(&link, plan);
        }
        index
    }

    pub(crate) fn plans_for_links(
        &self,
        links: &[String],
    ) -> BTreeMap<String, Result<plan::ResidentProxyProbePlan, String>> {
        let mut plans = BTreeMap::new();
        for link in links.iter().filter(|link| !link.is_empty()) {
            plans
                .entry(link.clone())
                .or_insert_with(|| self.plan_for_link(link));
        }
        plans
    }

    pub(crate) fn links_for_hash(&self, link_hash: &str) -> Option<Vec<String>> {
        self.links_by_hash
            .lock()
            .ok()
            .and_then(|links| links.get(link_hash).cloned())
    }

    pub(crate) fn cached_plan_count(&self) -> usize {
        self.plans_by_identity
            .lock()
            .map(|plans| plans.len())
            .unwrap_or(0)
    }

    fn plan_for_link(&self, link: &str) -> Result<plan::ResidentProxyProbePlan, String> {
        let identity = execution_link_hash(link);
        if let Some(cached) = self
            .plans_by_identity
            .lock()
            .ok()
            .and_then(|plans| plans.get(&identity).cloned())
        {
            return cached;
        }
        let mut built = match self.config.as_ref() {
            Some(config) => {
                plan::build_resident_manual_probe_plans_for_helper(config, &[link.to_owned()])
                    .remove(link)
                    .unwrap_or_else(
                        || Err("manual probe candidate was not materialized".to_owned()),
                    )
            }
            None => Err("manual probe candidate is unavailable in this runtime".to_owned()),
        };
        if let Ok(candidate) = built.as_mut()
            && let Err(error) = candidate.apply_runtime_generation(self.reload_generation)
        {
            built = Err(error);
        }
        self.cache_plan(link, built.clone());
        built
    }

    fn cache_plan(&self, link: &str, plan: Result<plan::ResidentProxyProbePlan, String>) {
        let identity = execution_link_hash(link);
        if let Ok(mut plans) = self.plans_by_identity.lock() {
            plans.entry(identity).or_insert_with(|| plan.clone());
        }
        let Ok(candidate) = plan else {
            return;
        };
        if let Ok(mut links_by_hash) = self.links_by_hash.lock() {
            let links = links_by_hash
                .entry(candidate.link_hash.as_ref().clone())
                .or_default();
            if !links.iter().any(|existing| existing == link) {
                links.push(link.to_owned());
            }
        }
    }
}
