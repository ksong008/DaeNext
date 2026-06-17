use std::net::SocketAddr;

use serde_json::Value;

use crate::production_runtime_owner::command::{CommandSpec, run_observation_command};
use crate::production_runtime_owner::live_tcp_probe::CLIENT_NETNS;

pub(super) fn run_client_active_dns_probe(
    target: SocketAddr,
    qname: &str,
    iterations: u32,
) -> Value {
    let target_ip = target.ip().to_string();
    let target_port = target.port();
    let socket_family = if target.is_ipv6() {
        "AF_INET6"
    } else {
        "AF_INET"
    };
    let script = format!(
        "import socket,sys\nqname={qname:?}\ntarget=({target_ip:?},{target_port})\nanswer_ip=bytes([203,0,113,54])\ndef enc_name(name):\n    out=b''\n    for label in name.rstrip('.').split('.'):\n        raw=label.encode('ascii')\n        out += bytes([len(raw)]) + raw\n    return out + b'\\x00'\ndef query(i):\n    ident=(0x5400+i) & 0xffff\n    return ident.to_bytes(2,'big') + b'\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00' + enc_name(qname) + b'\\x00\\x01\\x00\\x01'\nok=0\nlast=None\ns=socket.socket(socket.{socket_family}, socket.SOCK_DGRAM)\ns.settimeout(3)\nfor i in range({iterations}):\n    req=query(i)\n    s.sendto(req, target)\n    data,addr=s.recvfrom(512)\n    last=addr\n    if addr[:2] != target:\n        print(f'bad peer {{addr!r}}')\n        sys.exit(2)\n    if data[:2] != req[:2] or data[2:4] != b'\\x81\\x80' or answer_ip not in data:\n        print(f'bad dns response {{data.hex()}}')\n        sys.exit(3)\n    ok += 1\ns.close()\nprint(f\"active-dns-ack-count={{ok}} last-peer={{last[0]}}:{{last[1]}}\")\nsys.exit(0)\n",
        qname = qname,
        iterations = iterations,
        target_ip = target_ip,
        target_port = target_port,
        socket_family = socket_family,
    );
    run_observation_command(CommandSpec::new(
        "ip",
        ["netns", "exec", CLIENT_NETNS, "python3", "-c", &script],
    ))
}
