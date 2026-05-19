use super::*;

pub(super) fn stage43_report() -> Value {
    blocked_static_report(
        "stage43-production-param-listener-admission",
        "stage43",
        "production-name topology plus PARAM-aware object plus transparent listener combined gate",
        "Stage 43 requires Stage 38 production names, Stage 39 transparent listener handoff, and Stage 42 PARAM-aware object load to be re-run as one evidence chain",
        &[
            "combined production-name PARAM-aware transparent-listener smoke is not executed",
            "active tproxy TCP UDP DNS traffic evidence is still missing",
            "outbound true dataplane admission is still incomplete",
            "matched Go default daemon vs true Rust candidate benchmark is still missing",
        ],
        json!({
            "requires": [
                "production-name dae0/dae0peer/daens topology",
                "PARAM-aware object image loaded through tc/libbpf",
                "IP_TRANSPARENT TCP and UDP listener fd handoff into listen_socket_map key 0/1"
            ],
            "combined_prerequisites_admitted": false,
        }),
    )
}

pub(super) fn stage44_report() -> Value {
    blocked_static_report(
        "stage44-active-tcp-tproxy-admission",
        "stage44",
        "active TCP tproxy datapath gate",
        "Stage 44 must prove redirected TCP packets reach the transparent listener and outbound relay with original destination, SO_MARK, and mptcp parity",
        &[
            "active TCP tproxy traffic is not executed",
            "RouteDialTcp reroute and outbound relay evidence is missing",
            "matched TCP latency throughput benchmark is missing",
        ],
        json!({
            "traffic": "tcp",
            "required_evidence": [
                "redirected SYN enters tproxy listener",
                "original destination is observed",
                "routing result and outbound target are recorded",
                "MagicNetwork mark and mptcp are preserved",
                "reply path succeeds"
            ],
            "active_tproxy_tcp_executed": false,
        }),
    )
}

pub(super) fn stage45_report() -> Value {
    blocked_static_report(
        "stage45-active-udp-tproxy-admission",
        "stage45",
        "active UDP tproxy datapath gate",
        "Stage 45 must prove UDP endpoint pool, packet routing, outbound PacketConn, and sendPkt reply parity under the PARAM-aware object",
        &[
            "active UDP tproxy traffic is not executed",
            "UDP endpoint pool live evidence is missing",
            "matched UDP latency loss throughput benchmark is missing",
        ],
        json!({
            "traffic": "udp",
            "required_evidence": [
                "transparent UDP packet enters handlePkt-equivalent path",
                "endpoint pool creates and trims entries",
                "PacketConn WriteTo and ReadFrom semantics are preserved",
                "sendPkt reply path succeeds"
            ],
            "active_tproxy_udp_executed": false,
        }),
    )
}

pub(super) fn stage46_report() -> Value {
    blocked_static_report(
        "stage46-active-dns-tproxy-admission",
        "stage46",
        "transparent DNS UDP/53 and reload cache gate",
        "Stage 46 must prove DNS UDP/53 transparent traffic, DNS upstream routing, cache restore, and domain-routing owner migration under reload",
        &[
            "transparent DNS UDP/53 traffic is not executed",
            "reload DNS cache migration live evidence is missing",
            "domain_routing_map owner migration live evidence is missing",
        ],
        json!({
            "traffic": "dns-udp53",
            "required_evidence": [
                "transparent UDP/53 request enters DNS controller path",
                "DNS upstream MagicNetwork mark and mptcp are preserved",
                "DNS cache hit/miss and restore evidence is recorded",
                "domain routing owner merge/remove survives reload"
            ],
            "active_tproxy_dns_executed": false,
        }),
    )
}

pub(super) fn stage47_report() -> Value {
    blocked_static_report(
        "stage47-outbound-true-dataplane-admission",
        "stage47",
        "outbound true dataplane gate",
        "Stage 47 must prove protocol true dataplane, shared transport, reload cleanup, fallback/rollback, and benchmark evidence before any outbound default replacement",
        &[
            "outbound true dataplane admission is still incomplete",
            "shared transport true dataplane evidence is missing",
            "Go vs Rust protocol benchmark evidence is missing",
        ],
        json!({
            "protocol_batches": [
                "SOCKS5 TCP CONNECT and UDP ASSOCIATE",
                "HTTP CONNECT and passthrough",
                "Shadowsocks AEAD TCP and UDP",
                "shared transports: TLS/uTLS/REALITY/WS/gRPC/xHTTP/Meek/Mux",
                "QUIC/H3 protocols: Hysteria2/TUIC/Juicity"
            ],
            "outbound_true_dataplane_admitted": false,
        }),
    )
}

pub(super) fn stage48_report() -> Value {
    blocked_static_report(
        "stage48-true-daemon-benchmark-admission",
        "stage48",
        "true Rust default daemon lifecycle and matched benchmark gate",
        "Stage 48 must start a true Rust daemon candidate, compare it against Go default daemon on the same host/corpus, and keep product switch denied until every datapath row passes",
        &[
            "true Rust default daemon lifecycle smoke is not executed",
            "matched Go default daemon vs true Rust candidate benchmark is missing",
            "clean dae-wing and daed product-chain recertification is missing",
        ],
        json!({
            "required_benchmarks": [
                "TCP proxy latency and throughput",
                "UDP proxy latency loss throughput",
                "DNS UDP/53 latency and cache behavior",
                "RSS CPU startup time reload time",
                "outbound protocol benchmarks on admitted protocols"
            ],
            "true_rust_default_daemon_admitted": false,
        }),
    )
}

fn blocked_static_report(
    name: &str,
    stage: &str,
    evidence_class: &str,
    decision: &str,
    blockers: &[&str],
    detail: Value,
) -> Value {
    json!({
        "name": name,
        "stage": stage,
        "evidence_class": evidence_class,
        "read_only": true,
        "blocked": false,
        "blockers": [],
        "gate_decision": decision,
        "detail": detail,
        "active_tproxy_traffic_executed": false,
        "outbound_true_dataplane_admitted": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "remaining_blockers": blockers,
    })
}
