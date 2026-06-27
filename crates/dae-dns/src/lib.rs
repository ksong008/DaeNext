pub mod active;
pub mod cache;
pub mod cache_key;
pub mod doh;
pub mod error;
pub mod hot_path;
pub mod message;
pub mod netutils;
pub mod resolve;
pub mod routing;
pub mod upstream;

pub const DNS_DEFAULT_PORT: u16 = 53;

pub use active::{
    ACTIVE_DNS_DEFAULT_QNAME, ACTIVE_DNS_DEFAULT_TARGET_PORT, ACTIVE_DNS_DEFAULT_UPSTREAM_IP,
    ACTIVE_DNS_DEFAULT_UPSTREAM_PORT, ACTIVE_DNS_QCLASS_IN, ACTIVE_DNS_QTYPE_A,
    ActiveDnsCacheContract, active_dns_cache_contract, active_dns_packet_question_matches,
    active_dns_question_matches, build_active_dns_a_response,
};
pub use cache::{DnsCacheEntry, DnsCacheStats, DnsCacheStore, effective_deadline_from_ttl};
pub use cache_key::{
    DnsCacheKey, DnsCacheKeyView, canonical_name, canonical_name_eq_ignore_ascii_case,
    canonical_name_lowercase, parse_dns_cache_key, parse_dns_cache_key_view,
};
pub use doh::{
    DOH_GET_MAX_ENCODED_QUERY_BYTES, DOH_MEDIA_TYPE, DohRequest, DohValidationCounters,
    build_doh_request, validate_doh_response,
};
pub use error::{DnsError, DnsValidationError};
pub use hot_path::{
    DnsPacketCacheHit, DnsResponseCachePlan, build_response_cache_plan_from_packet,
    cache_plan_question, restore_cached_response_for_packet_question,
};
pub use message::{
    DnsAnswer, DnsMessage, DnsPacketAnswerIter, DnsPacketAnswerView, DnsPacketNameView,
    DnsPacketQuestionIter, DnsPacketQuestionView, DnsPacketView, DnsQuestion,
    dns_data_with_zero_id, parse_message, restore_packed_response_request_id,
    restore_packed_response_request_id_into, validate_dns_packet_response_for_request,
    validate_dns_packet_response_for_request_fast, validate_dns_response_for_request,
    validate_dns_response_for_request_fast,
};
pub use netutils::{
    UdpForwardError, UdpForwardOutcome, forward_udp_with_retry, read_tcp_dns_response,
};
pub use resolve::guard_synthetic_asis_lookup;
pub use routing::{
    DnsDomainSet, DnsRequestMatchKind, DnsRequestMatchSpec, DnsRequestOutboundIndex,
    DnsResponseMatchKind, DnsResponseMatchSpec, DnsResponseOutboundIndex, RequestMatcher,
    ResponseMatcher,
};
pub use upstream::{Upstream, UpstreamResolver, UpstreamResolverStats};
