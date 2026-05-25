use serde_json::Value;

use super::model::{DEFAULT_ACTIVE_DNS_TARGET_IP, DEFAULT_ACTIVE_DNS_TARGET_PORT};
use crate::production_runtime_owner::active_tcp::CLIENT_NETNS;
use crate::production_runtime_owner::command::{CommandSpec, run_observation_command};

pub(super) fn run_client_active_dns_probe(target: &str, qname: &str, iterations: u32) -> Value {
    let script = format!(
        "import socket,sys\nqname={qname:?}\ntarget=({target_ip:?},{target_port})\nanswer_ip=bytes([203,0,113,54])\ndef enc_name(name):\n    out=b''\n    for label in name.rstrip('.').split('.'):\n        raw=label.encode('ascii')\n        out += bytes([len(raw)]) + raw\n    return out + b'\\x00'\ndef query(i):\n    ident=(0x5400+i) & 0xffff\n    return ident.to_bytes(2,'big') + b'\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00' + enc_name(qname) + b'\\x00\\x01\\x00\\x01'\nok=0\nlast=None\ns=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\ns.settimeout(3)\nfor i in range({iterations}):\n    req=query(i)\n    s.sendto(req, target)\n    data,addr=s.recvfrom(512)\n    last=addr\n    if addr != target:\n        print(f'bad peer {{addr!r}}')\n        sys.exit(2)\n    if data[:2] != req[:2] or data[2:4] != b'\\x81\\x80' or answer_ip not in data:\n        print(f'bad dns response {{data.hex()}}')\n        sys.exit(3)\n    ok += 1\ns.close()\nprint(f\"active-dns-ack-count={{ok}} last-peer={{last[0]}}:{{last[1]}}\")\nsys.exit(0)\n",
        qname = qname,
        iterations = iterations,
        target_ip = target
            .split(':')
            .next()
            .unwrap_or(DEFAULT_ACTIVE_DNS_TARGET_IP),
        target_port = target
            .split(':')
            .nth(1)
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(DEFAULT_ACTIVE_DNS_TARGET_PORT),
    );
    run_observation_command(CommandSpec::new(
        "ip",
        ["netns", "exec", CLIENT_NETNS, "python3", "-c", &script],
    ))
}
