use dae_config::{Param, RoutingRule};

pub trait ResidentDnsGeodata: Send + Sync {
    fn expand_request_qname_rules(&self, rules: &[RoutingRule])
    -> Result<Vec<RoutingRule>, String>;

    fn expand_response_qname_rules(
        &self,
        rules: &[RoutingRule],
    ) -> Result<Vec<RoutingRule>, String>;

    fn expand_response_ip_params(&self, params: &[Param]) -> Result<Vec<Param>, String>;

    fn shared_domain_set(
        &self,
        key: &str,
        values: Vec<String>,
    ) -> Result<dae_routing::SharedDomainSet, String>;
}
