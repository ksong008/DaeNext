use std::hint::black_box;

use dae_dns::{
    DnsCacheEntry, DnsCacheKey, DnsCacheKeyView, DnsCacheStore, DnsMessage, DnsPacketAnswerView,
    DnsPacketView, DnsQuestion, DnsRequestOutboundIndex, DnsResponseOutboundIndex, RequestMatcher,
    ResponseMatcher, build_doh_request, build_response_cache_plan_from_packet,
    guard_synthetic_asis_lookup, parse_dns_cache_key_view, parse_message,
    restore_cached_response_for_packet_question, validate_dns_packet_response_for_request_fast,
    validate_dns_response_for_request_fast, validate_doh_response,
};
use serde_json::json;

use crate::{BenchCase, Measurement, measure};

mod cases;
pub(crate) use self::cases::*;
mod routing;
use self::routing::*;
mod cache;
use self::cache::*;
mod doh;
use self::doh::*;
mod validation;
use self::validation::*;
mod packet_answers;
use self::packet_answers::*;
mod fixtures;
use self::fixtures::*;
