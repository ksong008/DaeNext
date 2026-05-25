pub mod active;
pub mod cache;
pub mod cache_key;
pub mod doh;
pub mod error;
pub mod message;
pub mod netutils;
pub mod resolve;
pub mod upstream;

pub use active::{
    ACTIVE_DNS_DEFAULT_QNAME, ACTIVE_DNS_DEFAULT_TARGET_IP, ACTIVE_DNS_DEFAULT_TARGET_PORT,
    ACTIVE_DNS_DEFAULT_UPSTREAM_IP, ACTIVE_DNS_DEFAULT_UPSTREAM_PORT, ACTIVE_DNS_QCLASS_IN,
    ACTIVE_DNS_QTYPE_A, ActiveDnsCacheContract, active_dns_cache_contract,
    active_dns_question_matches, build_active_dns_a_response,
};
pub use cache::{DnsCacheEntry, DnsCacheStats, DnsCacheStore, effective_deadline_from_ttl};
pub use cache_key::{DnsCacheKey, canonical_name, parse_dns_cache_key};
pub use doh::{
    DOH_GET_MAX_ENCODED_QUERY_BYTES, DOH_MEDIA_TYPE, DohRequest, DohValidationCounters,
    build_doh_request, validate_doh_response,
};
pub use error::DnsError;
pub use message::{
    DnsAnswer, DnsMessage, DnsQuestion, dns_data_with_zero_id, parse_message,
    restore_packed_response_request_id, validate_dns_response_for_request,
};
pub use netutils::{
    UdpForwardError, UdpForwardOutcome, forward_udp_with_retry, read_tcp_dns_response,
};
pub use resolve::guard_synthetic_asis_lookup;
pub use upstream::{Upstream, UpstreamResolver, UpstreamResolverStats};
