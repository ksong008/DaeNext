use super::*;

pub(super) fn run_client_probe(target: &str) -> Value {
    let script = format!(
        "import socket,sys\ns=socket.create_connection(({target_ip:?},{target_port}),3)\ns.settimeout(3)\ns.sendall(b\"stage50-tcp-ping\")\ndata=s.recv(64)\nprint(data.decode('ascii','replace'))\ns.close()\nsys.exit(0 if data == b\"stage50-tcp-ack\" else 2)\n",
        target_ip = target
            .split(':')
            .next()
            .unwrap_or(DEFAULT_STAGE50_TARGET_IP),
        target_port = target
            .split(':')
            .nth(1)
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(DEFAULT_STAGE50_TARGET_PORT),
    );
    run_observation_command(CommandSpec::new(
        "ip",
        &["netns", "exec", CLIENT_NETNS, "python3", "-c", &script],
    ))
}

pub(super) fn run_client_relay_probe(target: &str, iterations: u32) -> Value {
    let script = format!(
        "import socket,sys\nok=0\nfor i in range({iterations}):\n    s=socket.create_connection(({target_ip:?},{target_port}),3)\n    s.settimeout(3)\n    s.sendall(b\"stage51-tcp-relay-ping\")\n    data=s.recv(64)\n    s.close()\n    if data != b\"stage51-tcp-relay-ack\":\n        print(data.decode('ascii','replace'))\n        sys.exit(2)\n    ok += 1\nprint(f\"stage51-relay-ack-count={{ok}}\")\nsys.exit(0)\n",
        target_ip = target
            .split(':')
            .next()
            .unwrap_or(DEFAULT_STAGE51_TARGET_IP),
        target_port = target
            .split(':')
            .nth(1)
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(DEFAULT_STAGE51_TARGET_PORT),
    );
    run_observation_command(CommandSpec::new(
        "ip",
        &["netns", "exec", CLIENT_NETNS, "python3", "-c", &script],
    ))
}

pub(super) fn run_client_stage52_relay_probe(target: &str, iterations: u32) -> Value {
    let script = format!(
        "import socket,sys\nok=0\nfor i in range({iterations}):\n    s=socket.create_connection(({target_ip:?},{target_port}),3)\n    s.settimeout(3)\n    s.sendall(b\"stage52-route-group-ping\")\n    data=s.recv(64)\n    s.close()\n    if data != b\"stage52-route-group-ack\":\n        print(data.decode('ascii','replace'))\n        sys.exit(2)\n    ok += 1\nprint(f\"stage52-route-group-ack-count={{ok}}\")\nsys.exit(0)\n",
        target_ip = target
            .split(':')
            .next()
            .unwrap_or(DEFAULT_STAGE52_TARGET_IP),
        target_port = target
            .split(':')
            .nth(1)
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(DEFAULT_STAGE52_TARGET_PORT),
    );
    run_observation_command(CommandSpec::new(
        "ip",
        &["netns", "exec", CLIENT_NETNS, "python3", "-c", &script],
    ))
}

pub(super) fn run_client_stage53_udp_probe(target: &str, iterations: u32) -> Value {
    let script = format!(
        "import socket,sys\nok=0\nlast=None\ns=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\ns.settimeout(3)\nfor i in range({iterations}):\n    s.sendto(b\"stage53-udp-tproxy-ping\", ({target_ip:?},{target_port}))\n    data,addr=s.recvfrom(128)\n    last=addr\n    if data != b\"stage53-udp-tproxy-ack\" or addr != ({target_ip:?},{target_port}):\n        print(f\"bad reply data={{data!r}} addr={{addr!r}}\")\n        sys.exit(2)\n    ok += 1\ns.close()\nprint(f\"stage53-udp-ack-count={{ok}} last-peer={{last[0]}}:{{last[1]}}\")\nsys.exit(0)\n",
        target_ip = target
            .split(':')
            .next()
            .unwrap_or(DEFAULT_STAGE53_TARGET_IP),
        target_port = target
            .split(':')
            .nth(1)
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(DEFAULT_STAGE53_TARGET_PORT),
    );
    run_observation_command(CommandSpec::new(
        "ip",
        &["netns", "exec", CLIENT_NETNS, "python3", "-c", &script],
    ))
}

pub(super) fn run_client_stage54_dns_probe(target: &str, qname: &str, iterations: u32) -> Value {
    let script = format!(
        "import socket,sys\nqname={qname:?}\ntarget=({target_ip:?},{target_port})\nanswer_ip=bytes([203,0,113,54])\ndef enc_name(name):\n    out=b''\n    for label in name.rstrip('.').split('.'):\n        raw=label.encode('ascii')\n        out += bytes([len(raw)]) + raw\n    return out + b'\\x00'\ndef query(i):\n    ident=(0x5400+i) & 0xffff\n    return ident.to_bytes(2,'big') + b'\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00' + enc_name(qname) + b'\\x00\\x01\\x00\\x01'\nok=0\nlast=None\ns=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\ns.settimeout(3)\nfor i in range({iterations}):\n    req=query(i)\n    s.sendto(req, target)\n    data,addr=s.recvfrom(512)\n    last=addr\n    if addr != target:\n        print(f'bad peer {{addr!r}}')\n        sys.exit(2)\n    if data[:2] != req[:2] or data[2:4] != b'\\x81\\x80' or answer_ip not in data:\n        print(f'bad dns response {{data.hex()}}')\n        sys.exit(3)\n    ok += 1\ns.close()\nprint(f\"stage54-dns-ack-count={{ok}} last-peer={{last[0]}}:{{last[1]}}\")\nsys.exit(0)\n",
        qname = qname,
        iterations = iterations,
        target_ip = target
            .split(':')
            .next()
            .unwrap_or(DEFAULT_STAGE54_TARGET_IP),
        target_port = target
            .split(':')
            .nth(1)
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(DEFAULT_STAGE54_TARGET_PORT),
    );
    run_observation_command(CommandSpec::new(
        "ip",
        &["netns", "exec", CLIENT_NETNS, "python3", "-c", &script],
    ))
}

pub(super) fn cleanup_stage50(cleanup_steps: &mut Vec<Value>) {
    run_cleanup_step(
        cleanup_steps,
        "delete-production-dae0-param-aware-ebpf-program-filter",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                PRODUCTION_HOST_IFACE,
                "ingress",
                "pref",
                STAGE50_FILTER_PREF,
            ],
        ),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-production-host-clsact-qdisc",
        CommandSpec::new(
            "tc",
            &["qdisc", "del", "dev", PRODUCTION_HOST_IFACE, "clsact"],
        ),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-lan-ingress-param-aware-ebpf-program-filter",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                LAN_HOST_IFACE,
                "ingress",
                "pref",
                STAGE50_LAN_FILTER_PREF,
            ],
        ),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-lan-host-clsact-qdisc",
        CommandSpec::new("tc", &["qdisc", "del", "dev", LAN_HOST_IFACE, "clsact"]),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-production-dae0peer-param-aware-ebpf-program-filter",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "tc",
                "filter",
                "del",
                "dev",
                PRODUCTION_PEER_IFACE,
                "ingress",
                "pref",
                STAGE50_FILTER_PREF,
            ],
        ),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-production-peer-clsact-qdisc",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "tc",
                "qdisc",
                "del",
                "dev",
                PRODUCTION_PEER_IFACE,
                "clsact",
            ],
        ),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-lan-host-link",
        CommandSpec::new("ip", &["link", "del", LAN_HOST_IFACE]),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-production-host-link",
        CommandSpec::new("ip", &["link", "del", PRODUCTION_HOST_IFACE]),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-client-netns",
        CommandSpec::new("ip", &["netns", "del", CLIENT_NETNS]),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-production-netns",
        CommandSpec::new("ip", &["netns", "del", PRODUCTION_NETNS]),
    );
}

pub(super) fn remaining_blockers() -> Vec<&'static str> {
    vec![
        "RouteDialTcp Rust control-plane path is not executed",
        "SO_MARK and MPTCP are not proven on a real outbound socket in this stage",
        "active UDP tproxy traffic evidence is still missing",
        "active DNS UDP/53 and reload DNS cache migration evidence is still missing",
        "outbound true dataplane admission is still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing",
    ]
}

pub(super) fn remaining_blockers_after_stage51() -> Vec<&'static str> {
    vec![
        "Full RouteDialTcp route-table reroute and outbound group selection are not executed in this bounded direct relay stage",
        "active UDP tproxy traffic evidence is still missing",
        "active DNS UDP/53 and reload DNS cache migration evidence is still missing",
        "outbound protocol true dataplane admission is still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing",
    ]
}

pub(super) fn remaining_blockers_after_stage52() -> Vec<&'static str> {
    vec![
        "active UDP tproxy traffic evidence is still missing",
        "active DNS UDP/53 and reload DNS cache migration evidence is still missing",
        "outbound protocol true dataplane admission is still incomplete beyond the bounded direct loopback group relay",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing",
    ]
}

pub(super) fn remaining_blockers_after_stage53() -> Vec<&'static str> {
    vec![
        "active DNS UDP/53 and reload DNS cache migration evidence is still missing",
        "outbound protocol true dataplane admission is still incomplete beyond direct TCP/UDP loopback relays",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing",
    ]
}

pub(super) fn remaining_blockers_after_stage54() -> Vec<&'static str> {
    vec![
        "outbound protocol true dataplane admission is still incomplete beyond direct TCP/UDP/DNS loopback relays",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing",
    ]
}
