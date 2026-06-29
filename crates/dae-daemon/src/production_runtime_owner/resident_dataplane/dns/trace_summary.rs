use super::*;

#[derive(Clone, Debug)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentDnsTraceSummary {
    pub(in crate::production_runtime_owner::resident_dataplane) qname: String,
    pub(in crate::production_runtime_owner::resident_dataplane) qtype: u16,
    pub(in crate::production_runtime_owner::resident_dataplane) qclass: u16,
    pub(in crate::production_runtime_owner::resident_dataplane) cache: String,
    pub(in crate::production_runtime_owner::resident_dataplane) request_routing: String,
    pub(in crate::production_runtime_owner::resident_dataplane) response_routing: String,
    pub(in crate::production_runtime_owner::resident_dataplane) upstream: Option<String>,
    pub(in crate::production_runtime_owner::resident_dataplane) upstream_scheme:
        Option<&'static str>,
    pub(in crate::production_runtime_owner::resident_dataplane) upstream_chain: Vec<String>,
    pub(in crate::production_runtime_owner::resident_dataplane) reroutes: usize,
    pub(in crate::production_runtime_owner::resident_dataplane) fallback: bool,
    pub(in crate::production_runtime_owner::resident_dataplane) rcode: Option<u16>,
    pub(in crate::production_runtime_owner::resident_dataplane) reason: String,
}

impl ResidentDnsTraceSummary {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn from_request(
        plan: &ResidentDnsPlan,
        request: &DnsPacketView<'_>,
    ) -> Result<Self, String> {
        let question = request
            .questions()
            .next()
            .ok_or_else(|| "DNS request has no question".to_owned())?;
        let qname = question
            .qname_to_canonical_string()
            .map_err(|err| format!("read DNS request qname for trace: {err}"))?;
        Ok(Self {
            qname,
            qtype: question.qtype(),
            qclass: question.qclass(),
            cache: DNS_TRACE_CACHE_UNRESOLVED.to_owned(),
            request_routing: DNS_TRACE_ROUTING_UNRESOLVED.to_owned(),
            response_routing: DNS_TRACE_ROUTING_UNRESOLVED.to_owned(),
            upstream: None,
            upstream_scheme: None,
            upstream_chain: Vec::new(),
            reroutes: 0,
            fallback: plan.request_matcher.is_none(),
            rcode: None,
            reason: String::new(),
        })
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn set_request_action(
        &mut self,
        action: &ResidentDnsRequestAction,
    ) {
        self.request_routing = dns_request_action_name(action).to_owned();
        if let ResidentDnsRequestAction::Upstream(upstream) = action {
            self.set_upstream(upstream);
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn set_response_action(
        &mut self,
        action: &ResidentDnsResponseAction,
    ) {
        self.response_routing = dns_response_action_name(action).to_owned();
        if let ResidentDnsResponseAction::Upstream(upstream) = action {
            self.set_upstream(upstream);
        }
    }

    fn set_upstream(&mut self, upstream: &ResidentDnsUpstream) {
        self.upstream = Some(upstream.tag.clone());
        self.upstream_scheme = Some(upstream.scheme.as_str());
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn push_upstream_attempt(
        &mut self,
        upstream: &ResidentDnsUpstream,
    ) {
        self.set_upstream(upstream);
        self.upstream_chain.push(upstream.tag.clone());
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn push_asis_attempt(
        &mut self,
    ) {
        self.upstream = Some("asis".to_owned());
        self.upstream_scheme = Some("udp");
        self.upstream_chain.push("asis".to_owned());
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn finish(
        mut self,
        response: Vec<u8>,
        reason: &str,
    ) -> ResidentDnsQueryResult {
        self.rcode = dns_response_rcode(&response);
        self.reason = reason.to_owned();
        ResidentDnsQueryResult {
            response,
            trace: self,
        }
    }
}
