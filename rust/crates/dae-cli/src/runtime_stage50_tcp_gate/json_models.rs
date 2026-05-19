use super::*;

pub(super) fn upstream_listener_json(report: &TcpLoopbackListenerReport) -> Value {
    json!({
        "requested_mptcp": report.requested_mptcp,
        "mptcp_socket_created": report.mptcp_socket_created,
        "fallback_used": report.fallback_used,
        "socket_protocol": report.socket_protocol,
        "local_addr": report.local_addr,
    })
}

pub(super) fn tcp_direct_dial_report_json(report: &TcpDirectDialReport) -> Value {
    json!({
        "requested_mark": report.requested_mark,
        "requested_mptcp": report.requested_mptcp,
        "mptcp_socket_attempted": report.mptcp_socket_attempted,
        "mptcp_socket_created": report.mptcp_socket_created,
        "mptcp_connect_fallback_used": report.mptcp_connect_fallback_used,
        "socket_protocol": report.socket_protocol,
        "so_mark": report.so_mark,
        "so_mark_applied": report.so_mark_applied,
        "mptcp_info_available": report.mptcp_info_available,
        "mptcp_fallen_back": report.mptcp_fallen_back,
        "mptcp_protocol_observed": report.mptcp_protocol_observed,
        "peer_addr": report.peer_addr,
        "local_addr": report.local_addr,
    })
}

pub(super) fn udp_direct_report_json(
    report: &UdpDirectSocketReport,
    target: SocketAddrV4,
) -> Value {
    json!({
        "requested_mark": report.requested_mark,
        "so_mark": report.so_mark,
        "so_mark_applied": report.so_mark_applied,
        "peer_addr": report.peer_addr,
        "local_addr": report.local_addr,
        "target": target.to_string(),
    })
}

pub(super) fn stage53_udp_endpoint_model_json(base: &Stage50Options) -> Value {
    json!({
        "status": "model-only",
        "key_model": "client-source-full-cone",
        "target": format!("{}:{}", base.target_ip, base.target_port),
        "nat_timeout_ms": DEFAULT_NAT_TIMEOUT_MS,
        "dns_nat_timeout_ms": DNS_NAT_TIMEOUT_MS,
        "max_retry": MAX_RETRY,
        "pool_max_entries_default": DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES,
        "dns_udp53_excluded": true,
        "live_endpoint_created": false,
    })
}

pub(super) fn stage54_dns_cache_model_json(opts: &Stage54Options) -> Value {
    json!({
        "status": "model-only",
        "qname": opts.qname,
        "qtype": 1,
        "qclass": 1,
        "dns_target": format!("{}:{}", opts.base.target_ip, opts.base.target_port),
        "dns_upstream": format!("{}:{}", opts.upstream_ip, opts.upstream_port),
        "dns_nat_timeout_ms": DNS_NAT_TIMEOUT_MS,
        "cache_max_entries": dae_dns::cache::DNS_CACHE_MAX_ENTRIES,
        "cache_key_includes_qclass": true,
        "packed_response_id_rewrite_required": true,
        "reload_snapshot_required": true,
        "domain_routing_owner_migration_required": true,
        "live_cache_restored": false,
    })
}

pub(super) fn stage_target_addr(base: &Stage50Options) -> Result<SocketAddrV4, String> {
    let ip = base
        .target_ip
        .parse()
        .map_err(|err| format!("invalid target ip {}: {err}", base.target_ip))?;
    Ok(SocketAddrV4::new(ip, base.target_port))
}

pub(super) fn stage54_upstream_addr(opts: &Stage54Options) -> Result<SocketAddrV4, String> {
    let ip = opts
        .upstream_ip
        .parse()
        .map_err(|err| format!("invalid upstream ip {}: {err}", opts.upstream_ip))?;
    Ok(SocketAddrV4::new(ip, opts.upstream_port))
}

pub(super) fn udp_upstream_echo_probe(socket: UdpSocket, iterations: u32) -> Value {
    let local_addr = socket.local_addr().map(|addr| addr.to_string()).ok();
    let mut accepted = 0_u32;
    let mut first_peer = None;
    let mut last_peer = None;
    for _ in 0..iterations {
        let mut buf = [0_u8; 256];
        let (read, peer) = match socket.recv_from(&mut buf) {
            Ok(value) => value,
            Err(err) => {
                return json!({
                    "status": "fail",
                    "local_addr": local_addr,
                    "accepted": accepted,
                    "error": err.to_string(),
                });
            }
        };
        if first_peer.is_none() {
            first_peer = Some(peer.to_string());
        }
        last_peer = Some(peer.to_string());
        if &buf[..read] != STAGE53_UDP_PAYLOAD {
            return json!({
                "status": "fail",
                "local_addr": local_addr,
                "accepted": accepted,
                "error": "unexpected UDP upstream payload",
                "payload": String::from_utf8_lossy(&buf[..read]).to_string(),
            });
        }
        if let Err(err) = socket.send_to(STAGE53_UDP_RESPONSE, peer) {
            return json!({
                "status": "fail",
                "local_addr": local_addr,
                "accepted": accepted,
                "error": format!("write UDP upstream response: {err}"),
            });
        }
        accepted += 1;
    }
    json!({
        "status": "pass",
        "local_addr": local_addr,
        "accepted": accepted,
        "iterations": iterations,
        "first_peer": first_peer,
        "last_peer": last_peer,
    })
}

pub(super) fn dns_upstream_echo_probe(socket: UdpSocket, expected_qname: &str) -> Value {
    let local_addr = socket.local_addr().map(|addr| addr.to_string()).ok();
    let mut buf = [0_u8; 512];
    let (read, peer) = match socket.recv_from(&mut buf) {
        Ok(value) => value,
        Err(err) => {
            return json!({
                "status": "fail",
                "local_addr": local_addr,
                "accepted": 0,
                "error": err.to_string(),
            });
        }
    };
    let request = &buf[..read];
    let req = match parse_message(request) {
        Ok(req) => req,
        Err(err) => {
            return json!({
                "status": "fail",
                "local_addr": local_addr,
                "accepted": 1,
                "error": format!("parse DNS upstream request: {err}"),
            });
        }
    };
    let question_matches = req.questions.first().is_some_and(|question| {
        question.qname == DnsCacheKey::new(expected_qname, question.qtype, question.qclass).qname
            && question.qtype == 1
            && question.qclass == 1
    });
    let response = match build_dns_a_response(request, STAGE54_RESPONSE_IP, STAGE54_RESPONSE_TTL) {
        Ok(response) => response,
        Err(err) => {
            return json!({
                "status": "fail",
                "local_addr": local_addr,
                "accepted": 1,
                "error": err,
            });
        }
    };
    let resp = match parse_message(&response) {
        Ok(resp) => resp,
        Err(err) => {
            return json!({
                "status": "fail",
                "local_addr": local_addr,
                "accepted": 1,
                "error": format!("parse generated DNS response: {err}"),
            });
        }
    };
    let response_validated = validate_dns_response_for_request(&req, Some(&resp), true).is_ok();
    if let Err(err) = socket.send_to(&response, peer) {
        return json!({
            "status": "fail",
            "local_addr": local_addr,
            "accepted": 1,
            "error": format!("write DNS upstream response: {err}"),
        });
    }
    json!({
        "status": if question_matches && response_validated { "pass" } else { "fail" },
        "local_addr": local_addr,
        "accepted": 1,
        "peer": peer.to_string(),
        "qname": req.questions.first().map(|question| question.qname.clone()),
        "qtype": req.questions.first().map(|question| question.qtype),
        "qclass": req.questions.first().map(|question| question.qclass),
        "question_matches": question_matches,
        "response_validated": response_validated,
        "response_ip": STAGE54_RESPONSE_IP_TEXT,
        "ttl": STAGE54_RESPONSE_TTL,
    })
}

pub(super) fn build_dns_a_response(
    query: &[u8],
    ip: Ipv4Addr,
    ttl: u32,
) -> Result<Vec<u8>, String> {
    if query.len() < 12 {
        return Err("DNS query too short".to_owned());
    }
    let question_end = dns_question_end(query)?;
    let mut response = Vec::with_capacity(question_end + 16);
    response.extend_from_slice(&query[0..2]);
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&query[12..question_end]);
    response.extend_from_slice(&0xc00c_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&ttl.to_be_bytes());
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&ip.octets());
    Ok(response)
}

pub(super) fn dns_question_end(packet: &[u8]) -> Result<usize, String> {
    let mut offset = 12;
    loop {
        if offset >= packet.len() {
            return Err("DNS question name exceeded packet".to_owned());
        }
        let len = packet[offset] as usize;
        offset += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            return Err(
                "compressed DNS question names are not accepted in stage54 query".to_owned(),
            );
        }
        offset += len;
    }
    if offset + 4 > packet.len() {
        return Err("DNS question missing qtype/qclass".to_owned());
    }
    Ok(offset + 4)
}

pub(super) fn domain_routing_view_json(view: &dae_control::DomainRoutingView) -> Value {
    json!({
        "step": view.step.as_str(),
        "owners": &view.owners,
        "ips": view.ips.iter().map(|ip| {
            json!({
                "ip": ip.ip.as_str(),
                "owners": &ip.owners,
                "merged": &ip.merged,
                "present": ip.present,
            })
        }).collect::<Vec<_>>(),
    })
}

pub(super) fn stage52_route_plan(opts: &Stage52Options) -> RouteDialTcpPlan {
    let destination = std::net::SocketAddr::V4(SocketAddrV4::new(
        opts.base
            .target_ip
            .parse()
            .unwrap_or_else(|_| DEFAULT_STAGE52_TARGET_IP.parse().unwrap()),
        opts.base.target_port,
    ));
    route_dial_tcp_plan(&RouteDialTcpPlanInput {
        dial_mode: opts.dial_mode,
        initial_outbound: OUTBOUND_USER_DEFINED_MIN,
        destination,
        domain: opts.domain.clone(),
        domain_is_real: opts.domain_is_real,
        initial_mark: 0,
        so_mark_from_dae: opts.base.so_mark,
        mptcp: opts.base.mptcp,
        route_rules: vec![RouteRule {
            kind: "DomainSet".to_owned(),
            outbound: OUTBOUND_USER_DEFINED_MIN,
            mark: opts.base.so_mark,
            must: false,
            matched: true,
        }],
    })
}

pub(super) fn stage52_group_selection_json(plan: &RouteDialTcpPlan) -> (Value, bool) {
    let network_type = if plan.network_type == "tcp6" {
        NetworkType::TCP6
    } else {
        NetworkType::TCP4
    };
    let mut group = DialerGroup::new(
        "stage52-proxy",
        vec![
            Dialer::new("stage52-slow", ""),
            Dialer::new("stage52-fast", ""),
        ],
        vec![Annotation::default(), Annotation::default()],
        SelectionPolicy::MinLastLatency,
        false,
        0,
    );
    group.set_last_latency(0, network_type, 80);
    group.notify_alive(0, network_type, true);
    group.set_last_latency(1, network_type, 20);
    group.notify_alive(1, network_type, true);
    match group.select(network_type, plan.strict_ip_version) {
        Ok(selected) => {
            let dialer_name = group.dialers[selected.index].name.clone();
            let passed = selected.index == 1 && dialer_name == "stage52-fast";
            (
                json!({
                    "status": if passed { "pass" } else { "fail" },
                    "group": group.name,
                    "policy": "min",
                    "network_type": plan.network_type.as_str(),
                    "strict_ip_version": plan.strict_ip_version,
                    "candidate_latencies_ms": [80, 20],
                    "selected_index": selected.index,
                    "selected_dialer": dialer_name,
                    "selected_latency_ms": selected.latency_ms,
                }),
                passed,
            )
        }
        Err(err) => (
            json!({
                "status": "fail",
                "group": group.name,
                "policy": "min",
                "network_type": plan.network_type.as_str(),
                "strict_ip_version": plan.strict_ip_version,
                "error": err.to_string(),
            }),
            false,
        ),
    }
}

pub(super) fn route_dial_plan_json(plan: &RouteDialTcpPlan) -> Value {
    json!({
        "initial_outbound": plan.initial_outbound,
        "final_outbound": plan.final_outbound,
        "userspace_route_executed": plan.userspace_route_executed,
        "userspace_route_result": plan.userspace_route_result.as_ref().map(|result| json!({
            "outbound": result.outbound,
            "mark": result.mark,
            "must": result.must,
            "fallback": result.fallback,
        })),
        "first_choose": choose_dial_target_json(&plan.first_choose),
        "second_choose": plan.second_choose.as_ref().map(choose_dial_target_json),
        "final_dial_target": plan.final_dial_target.as_str(),
        "strict_ip_version": plan.strict_ip_version,
        "network_type": plan.network_type.as_str(),
        "initial_mark": plan.initial_mark,
        "final_mark": plan.final_mark,
        "mark_defaulted_from_so_mark": plan.mark_defaulted_from_so_mark,
        "mptcp": plan.mptcp,
        "magic_network_len": plan.magic_network.len(),
    })
}

pub(super) fn choose_dial_target_json(decision: &dae_datapath::ChooseDialTargetDecision) -> Value {
    json!({
        "requested_mode": decision.requested_mode.as_str(),
        "effective_mode": decision.effective_mode.as_str(),
        "outbound": decision.outbound,
        "destination": decision.destination.to_string(),
        "domain": decision.domain.as_str(),
        "domain_is_real": decision.domain_is_real,
        "dial_target": decision.dial_target.as_str(),
        "should_reroute": decision.should_reroute,
        "dial_ip": decision.dial_ip,
    })
}
