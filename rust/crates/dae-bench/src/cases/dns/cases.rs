use super::*;
pub(crate) fn cases() -> Vec<BenchCase> {
    vec![
        BenchCase {
            id: "dns/packed_response_restore",
            default_iters: 100_000,
            run: bench_dns_packed_response_restore,
        },
        BenchCase {
            id: "dns/data_zero_id",
            default_iters: 100_000,
            run: bench_dns_data_zero_id,
        },
        BenchCase {
            id: "dns/cache_key_roundtrip",
            default_iters: 100_000,
            run: bench_dns_cache_key_roundtrip,
        },
        BenchCase {
            id: "dns/cache_ttl_lookup",
            default_iters: 10_000,
            run: bench_dns_cache_ttl_lookup,
        },
        BenchCase {
            id: "dns/request_cache_hit_packet_view",
            default_iters: 100_000,
            run: bench_dns_request_cache_hit_packet_view,
        },
        BenchCase {
            id: "dns/response_cache_plan_packet_view",
            default_iters: 100_000,
            run: bench_dns_response_cache_plan_packet_view,
        },
        BenchCase {
            id: "dns/doh_get_request",
            default_iters: 100_000,
            run: bench_dns_doh_get_request,
        },
        BenchCase {
            id: "dns/doh_post_request",
            default_iters: 10_000,
            run: bench_dns_doh_post_request,
        },
        BenchCase {
            id: "dns/doh_validate_content_type",
            default_iters: 100_000,
            run: bench_dns_doh_validate_content_type,
        },
        BenchCase {
            id: "dns/validation_question_id",
            default_iters: 100_000,
            run: bench_dns_validation_question_id,
        },
        BenchCase {
            id: "dns/packet_view_validate_question_id",
            default_iters: 100_000,
            run: bench_dns_packet_view_validate_question_id,
        },
        BenchCase {
            id: "dns/packet_view_answers_ttl_ip_cname",
            default_iters: 100_000,
            run: bench_dns_packet_view_answers_ttl_ip_cname,
        },
        BenchCase {
            id: "dns/resolve_asis_guard",
            default_iters: 100_000,
            run: bench_dns_resolve_asis_guard,
        },
        BenchCase {
            id: "dns/request_routing_match",
            default_iters: 100_000,
            run: bench_dns_request_routing_match,
        },
        BenchCase {
            id: "dns/response_routing_match",
            default_iters: 100_000,
            run: bench_dns_response_routing_match,
        },
    ]
}
