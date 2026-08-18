use std::cell::RefCell;
use std::future::Future;
use std::time::Instant;

use super::*;

tokio::task_local! {
    static DNS_TRANSPORT_TRACE: RefCell<Vec<ResidentDnsTransportTrace>>;
}

#[derive(Clone, Debug)]
pub struct ResidentDnsTraceSummary {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    pub cache: String,
    pub request_routing: String,
    pub response_routing: String,
    pub upstream: Option<String>,
    pub upstream_scheme: Option<&'static str>,
    pub upstream_chain: Vec<String>,
    pub reroutes: usize,
    pub fallback: bool,
    pub rcode: Option<u16>,
    pub reason: String,
    pub total_ms: u64,
    pub cache_ms: u64,
    pub routing_ms: u64,
    pub upstream_ms: u64,
    pub transport_attempts: Vec<ResidentDnsTransportTrace>,
    started_at: Instant,
    upstream_started_at: Option<Instant>,
}

impl ResidentDnsTraceSummary {
    #[cfg(all(test, feature = "dns-runtime-tests"))]
    pub fn new_for_test(qname: String, qtype: u16, qclass: u16) -> Self {
        Self {
            qname,
            qtype,
            qclass,
            cache: DNS_TRACE_CACHE_UNRESOLVED.to_owned(),
            request_routing: DNS_TRACE_ROUTING_UNRESOLVED.to_owned(),
            response_routing: DNS_TRACE_ROUTING_UNRESOLVED.to_owned(),
            upstream: None,
            upstream_scheme: None,
            upstream_chain: Vec::new(),
            reroutes: 0,
            fallback: false,
            rcode: None,
            reason: String::new(),
            total_ms: 0,
            cache_ms: 0,
            routing_ms: 0,
            upstream_ms: 0,
            transport_attempts: Vec::new(),
            started_at: Instant::now(),
            upstream_started_at: None,
        }
    }

    pub fn from_request(
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
            total_ms: 0,
            cache_ms: 0,
            routing_ms: 0,
            upstream_ms: 0,
            transport_attempts: Vec::new(),
            started_at: Instant::now(),
            upstream_started_at: None,
        })
    }

    pub fn set_request_action(&mut self, action: &ResidentDnsRequestAction) {
        self.request_routing = dns_request_action_name(action).to_owned();
        if let ResidentDnsRequestAction::Upstream(upstream) = action {
            self.set_upstream(upstream);
        }
    }

    pub fn set_response_action(&mut self, action: &ResidentDnsResponseAction) {
        self.response_routing = dns_response_action_name(action).to_owned();
        if let ResidentDnsResponseAction::Upstream(upstream) = action {
            self.set_upstream(upstream);
        }
    }

    fn set_upstream(&mut self, upstream: &ResidentDnsUpstream) {
        self.upstream = Some(upstream.tag.clone());
        self.upstream_scheme = Some(upstream.scheme.as_str());
    }

    pub fn add_cache_elapsed(&mut self, started_at: Instant) {
        self.cache_ms = self.cache_ms.saturating_add(elapsed_ms(started_at));
    }

    pub fn add_routing_elapsed(&mut self, started_at: Instant) {
        self.routing_ms = self.routing_ms.saturating_add(elapsed_ms(started_at));
    }

    pub fn push_upstream_attempt(&mut self, upstream: &ResidentDnsUpstream) {
        self.finish_upstream_attempt();
        self.set_upstream(upstream);
        self.upstream_chain.push(upstream.tag.clone());
        self.upstream_started_at = Some(Instant::now());
    }

    pub fn push_asis_attempt(&mut self) {
        self.upstream = Some("asis".to_owned());
        self.upstream_scheme = Some("udp");
        self.upstream_chain.push("asis".to_owned());
    }

    pub fn finish(mut self, response: Vec<u8>, reason: &str) -> ResidentDnsQueryResult {
        self.finish_upstream_attempt();
        self.total_ms = elapsed_ms(self.started_at);
        self.rcode = dns_response_rcode(&response);
        self.reason = reason.to_owned();
        ResidentDnsQueryResult {
            response,
            trace: self,
        }
    }

    fn finish_upstream_attempt(&mut self) {
        if let Some(started) = self.upstream_started_at.take() {
            self.upstream_ms = self.upstream_ms.saturating_add(elapsed_ms(started));
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResidentDnsTransportTrace {
    pub upstream: String,
    pub scheme: &'static str,
    pub target: String,
    pub target_family: &'static str,
    pub l4proto: &'static str,
    pub route: &'static str,
    pub elapsed_ms: u64,
    pub outcome: &'static str,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ResidentDnsTransportTraceInput {
    pub upstream: String,
    pub scheme: &'static str,
    pub target: SocketAddr,
    pub l4proto: L4Proto,
    pub route: &'static str,
    pub started_at: Instant,
    pub error: Option<String>,
}

pub async fn capture_dns_transport_trace_async<F, T>(
    future: F,
) -> (T, Vec<ResidentDnsTransportTrace>)
where
    F: Future<Output = T>,
{
    DNS_TRANSPORT_TRACE
        .scope(RefCell::new(Vec::new()), async {
            let output = future.await;
            let attempts = DNS_TRANSPORT_TRACE.with(|trace| trace.borrow().clone());
            (output, attempts)
        })
        .await
}

pub fn record_dns_transport_trace(input: ResidentDnsTransportTraceInput) {
    let attempt = ResidentDnsTransportTrace {
        upstream: input.upstream,
        scheme: input.scheme,
        target: input.target.to_string(),
        target_family: if input.target.is_ipv6() {
            DNS_TRANSPORT_TARGET_FAMILY_IPV6
        } else {
            DNS_TRANSPORT_TARGET_FAMILY_IPV4
        },
        l4proto: input.l4proto.as_str(),
        route: input.route,
        elapsed_ms: elapsed_ms(input.started_at),
        outcome: if input.error.is_some() {
            DNS_TRANSPORT_OUTCOME_ERROR
        } else {
            DNS_TRANSPORT_OUTCOME_SUCCESS
        },
        error: input.error,
    };
    let _ = DNS_TRANSPORT_TRACE.try_with(|trace| trace.borrow_mut().push(attempt));
}

fn elapsed_ms(started_at: Instant) -> u64 {
    started_at.elapsed().as_millis().min(u64::MAX as u128) as u64
}
