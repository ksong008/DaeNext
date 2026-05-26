#!/usr/bin/env bash
#
# SPDX-License-Identifier: AGPL-3.0-only
#
# Production-host semantic probe for the DAEX resident default daemon.
# It validates the meaning of the live config instead of assuming every flow
# should proxy. In the current production profile, TCP fallback direct is
# expected while udp/19090 must enter the Rust resident UDP worker.

set -euo pipefail

if [[ "${1:-}" == "--help" ]]; then
  cat <<'EOF'
Usage: run_daex_production_semantic_probe.sh

Environment:
  DAE_BINARY=/usr/bin/dae
  DAE_SERVICE=dae.service
  CONFIG_FILE=/etc/dae/config.dae
  EXPECTED_SHA256=sha256-or-empty
  SUMMARY_FILE=/tmp/dae-daex-production-semantic-probe-<time>.json
  EVENT_FILE=/tmp/dae-daemon-resident-runtime-*/resident-production-dataplane-events.jsonl
  UDP_PROXY_HOST=8.8.8.8
  UDP_PROXY_PORT=19090
  UDP_EVENT_WAIT_SECONDS=25
  DNS_SERVER=8.8.8.8
  DNS_QUERY=example.com
  DIRECT_URL=http://api.ipify.org/
  EXPECTED_DIRECT_IP=ip-or-empty
  EXECUTE_RELOAD=0|1
  PROBE_NETNS=netns-or-empty
EOF
  exit 0
fi

if [[ "$(id -u)" != "0" ]]; then
  echo "DAEX production semantic probe requires root on the production host" >&2
  exit 2
fi

summary_file="${SUMMARY_FILE:-/tmp/dae-daex-production-semantic-probe-$(date +%Y%m%d%H%M%S).json}"
mkdir -p "$(dirname "$summary_file")"

python_cmd=(python3)
if [[ -n "${PROBE_NETNS:-}" ]]; then
  python_cmd=(ip netns exec "$PROBE_NETNS" python3)
fi

"${python_cmd[@]}" - "$summary_file" <<'PY'
import glob
import http.client
import json
import os
import random
import re
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

summary_file = Path(sys.argv[1])


def env(name, default=""):
    return os.environ.get(name, default)


def env_bool(name, default=False):
    raw = env(name, "1" if default else "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def env_int(name, default):
    raw = env(name, str(default)).strip()
    try:
        return int(raw)
    except ValueError:
        return default


binary = env("DAE_BINARY", "/usr/bin/dae")
service = env("DAE_SERVICE", "dae.service")
config_file = env("CONFIG_FILE", "/etc/dae/config.dae")
expected_sha256 = env("EXPECTED_SHA256")
event_file_env = env("EVENT_FILE")
udp_host = env("UDP_PROXY_HOST", "8.8.8.8")
udp_port = env_int("UDP_PROXY_PORT", 19090)
udp_wait_seconds = env_int("UDP_EVENT_WAIT_SECONDS", 25)
dns_server = env("DNS_SERVER", "8.8.8.8")
dns_query = env("DNS_QUERY", "example.com")
direct_url = env("DIRECT_URL", "http://api.ipify.org/")
expected_direct_ip = env("EXPECTED_DIRECT_IP")
execute_reload = env_bool("EXECUTE_RELOAD", False)
probe_netns = env("PROBE_NETNS")


def clipped(text, limit=4000):
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + "...<truncated>"


def run(cmd, timeout=15):
    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except Exception as exc:
        return {
            "cmd": cmd,
            "status": "fail",
            "error": str(exc),
            "returncode": None,
            "stdout": "",
            "stderr": "",
        }
    return {
        "cmd": cmd,
        "status": "pass" if completed.returncode == 0 else "fail",
        "returncode": completed.returncode,
        "stdout": clipped(completed.stdout),
        "stderr": clipped(completed.stderr),
    }


def command_passed(result):
    return result.get("returncode") == 0


def sha256_file(path):
    result = run(["sha256sum", path])
    sha = ""
    if command_passed(result):
        sha = result["stdout"].split()[0]
    return {
        "path": path,
        "sha256": sha,
        "expected_sha256": expected_sha256,
        "matches_expected": (not expected_sha256) or sha == expected_sha256,
        "command": result,
    }


def systemctl_state():
    result = run(
        [
            "systemctl",
            "show",
            service,
            "-p",
            "ActiveState",
            "-p",
            "SubState",
            "-p",
            "Result",
            "-p",
            "ExecMainStatus",
            "-p",
            "MainPID",
        ]
    )
    fields = {}
    for line in result.get("stdout", "").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key] = value
    return {
        "service": service,
        "fields": fields,
        "active_running": fields.get("ActiveState") == "active"
        and fields.get("SubState") == "running"
        and fields.get("Result") == "success"
        and fields.get("ExecMainStatus") == "0",
        "command": result,
    }


def config_semantics():
    text = Path(config_file).read_text(encoding="utf-8", errors="replace")
    flat = " ".join(text.split())
    required_pnames = {"NetworkManager", "systemd-resolved", "dnsmasq", "ssh", "sshd"}
    protected_pnames = set()
    for match in re.finditer(r"pname\s*\(([^)]*)\)\s*->\s*must_direct", flat):
        protected_pnames.update(re.findall(r"[A-Za-z0-9_.-]+", match.group(1)))
    udp_rule = re.search(
        r"l4proto\s*\(\s*udp\s*\)\s*&&\s*dport\s*\(\s*19090\s*\)\s*->\s*proxy",
        flat,
    )
    return {
        "config_file": config_file,
        "fallback_direct": bool(re.search(r"fallback\s*:\s*direct\b", flat)),
        "ssh_and_local_services_must_direct": required_pnames.issubset(protected_pnames),
        "protected_pnames": sorted(protected_pnames),
        "required_pnames": sorted(required_pnames),
        "udp_19090_proxy_rule": bool(udp_rule),
    }


def latest_event_file():
    if event_file_env:
        return event_file_env
    candidates = glob.glob(
        "/tmp/dae-daemon-resident-runtime-*/resident-production-dataplane-events.jsonl"
    )
    if not candidates:
        return ""
    return max(candidates, key=lambda item: Path(item).stat().st_mtime)


def resident_start_report(event_file):
    if not event_file:
        return {"status": "fail", "reason": "event file was not found"}
    start_file = Path(event_file).with_name("resident-production-runtime-start.json")
    if not start_file.exists():
        return {
            "status": "fail",
            "start_file": str(start_file),
            "reason": "resident start report was not found",
        }
    try:
        data = json.loads(start_file.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "fail", "start_file": str(start_file), "error": str(exc)}
    connectivity = data.get("resident_outbound_connectivity") or {}
    return {
        "status": "pass" if connectivity.get("status") == "pass" else "fail",
        "start_file": str(start_file),
        "resident_runtime_started": data.get("resident_runtime_started"),
        "resident_outbound_connectivity": connectivity,
    }


def dns_query_packet(name):
    txid = random.randint(1, 65535)
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(label)]) + label.encode("ascii")
        for label in name.rstrip(".").split(".")
    ) + b"\x00"
    question = qname + struct.pack("!HH", 1, 1)
    return txid, header + question


def dns_probe():
    txid, packet = dns_query_packet(dns_query)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    started = time.time()
    try:
        sock.sendto(packet, (dns_server, 53))
        response, peer = sock.recvfrom(2048)
    except Exception as exc:
        return {
            "status": "fail",
            "server": dns_server,
            "query": dns_query,
            "error": str(exc),
        }
    finally:
        sock.close()
    elapsed_ms = round((time.time() - started) * 1000.0, 3)
    if len(response) < 12:
        return {
            "status": "fail",
            "server": dns_server,
            "query": dns_query,
            "response_len": len(response),
            "error": "short DNS response",
        }
    rxid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(
        "!HHHHHH", response[:12]
    )
    rcode = flags & 0x000F
    passed = rxid == txid and rcode == 0 and ancount > 0
    return {
        "status": "pass" if passed else "fail",
        "server": dns_server,
        "query": dns_query,
        "peer": f"{peer[0]}:{peer[1]}",
        "response_len": len(response),
        "elapsed_ms": elapsed_ms,
        "txid_matches": rxid == txid,
        "rcode": rcode,
        "qdcount": qdcount,
        "ancount": ancount,
    }


def read_appended_events(path, offset):
    try:
        with open(path, "rb") as fh:
            fh.seek(offset)
            raw = fh.read(1024 * 1024)
    except Exception as exc:
        return [], str(exc)
    events = []
    for line in raw.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            events.append({"_raw": line})
    return events, ""


def udp_worker_probe(event_file):
    if not event_file or not Path(event_file).exists():
        return {
            "status": "fail",
            "event_file": event_file,
            "reason": "resident UDP event file was not found",
        }
    path = Path(event_file)
    before_size = path.stat().st_size
    target = f"{udp_host}:{udp_port}"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    send_error = ""
    recv_note = "no response expected"
    started = time.time()
    try:
        sock.sendto(b"dae-daex-udp19090-production-probe\n", (udp_host, udp_port))
        try:
            sock.recvfrom(2048)
            recv_note = "received response"
        except socket.timeout:
            pass
    except Exception as exc:
        send_error = str(exc)
    finally:
        sock.close()
    if send_error:
        return {
            "status": "fail",
            "event_file": str(path),
            "target": target,
            "error": send_error,
        }

    matched_event = None
    last_events = []
    read_error = ""
    deadline = time.time() + udp_wait_seconds
    while time.time() <= deadline:
        events, read_error = read_appended_events(path, before_size)
        last_events = events[-5:]
        for event in events:
            event_name = str(event.get("event") or event.get("name") or event.get("_raw") or "")
            original_dst = str(event.get("original_dst") or event.get("target") or "")
            raw = event.get("_raw", "")
            if (
                original_dst == target
                and "udp" in event_name.lower()
            ) or (target in raw and "udp" in raw.lower()):
                matched_event = event
                break
        if matched_event is not None:
            break
        time.sleep(1.0)
    elapsed_ms = round((time.time() - started) * 1000.0, 3)
    return {
        "status": "pass" if matched_event is not None else "fail",
        "event_file": str(path),
        "target": target,
        "before_size": before_size,
        "after_size": path.stat().st_size if path.exists() else None,
        "elapsed_ms": elapsed_ms,
        "recv_note": recv_note,
        "matched_event": matched_event,
        "last_appended_events": last_events,
        "read_error": read_error,
        "expected_result": "packet enters Rust resident UDP worker; remote target may time out",
    }


def tcp_direct_probe():
    parsed = re.match(r"^http://([^/:]+)(?::([0-9]+))?(/.*)?$", direct_url)
    if not parsed:
        return {"status": "skipped", "url": direct_url, "reason": "only http:// URLs are supported"}
    host = parsed.group(1)
    port = int(parsed.group(2) or "80")
    path = parsed.group(3) or "/"
    started = time.time()
    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", path, headers={"User-Agent": "dae-daex-production-semantic-probe"})
        response = conn.getresponse()
        body = response.read(256).decode("utf-8", errors="replace").strip()
    except Exception as exc:
        return {"status": "fail", "url": direct_url, "error": str(exc)}
    finally:
        try:
            conn.close()
        except Exception:
            pass
    elapsed_ms = round((time.time() - started) * 1000.0, 3)
    matches_expected = (not expected_direct_ip) or body == expected_direct_ip
    return {
        "status": "pass" if matches_expected else "fail",
        "url": direct_url,
        "body": body,
        "expected_direct_ip": expected_direct_ip,
        "matches_expected": matches_expected,
        "elapsed_ms": elapsed_ms,
        "semantic": "fallback direct is expected by the live production config",
    }


event_file = latest_event_file()
binary_report = sha256_file(binary)
service_before = systemctl_state()
validate = run([binary, "validate", "-c", config_file], timeout=20)
semantics = config_semantics()
resident_report = resident_start_report(event_file)
dns = dns_probe()
udp = udp_worker_probe(event_file)
tcp_direct = tcp_direct_probe()
reload_report = {"status": "skipped", "execute_reload": False}
service_after_reload = {}
if execute_reload:
    reload_report = run(["systemctl", "reload", service], timeout=20)
    reload_report["execute_reload"] = True
    service_after_reload = systemctl_state()

checks = {
    "binary_sha256_matches_expected": binary_report["matches_expected"],
    "service_active_running_before": service_before["active_running"],
    "config_validate_passed": command_passed(validate),
    "config_fallback_direct": semantics["fallback_direct"],
    "config_pname_protects_ssh_and_local_services": semantics[
        "ssh_and_local_services_must_direct"
    ],
    "config_udp_19090_proxy_rule": semantics["udp_19090_proxy_rule"],
    "resident_outbound_connectivity_passed": resident_report["status"] == "pass",
    "dns_udp_probe_passed": dns["status"] == "pass",
    "udp_19090_entered_resident_worker": udp["status"] == "pass",
}
if expected_direct_ip:
    checks["tcp_fallback_direct_matches_expected_ip"] = tcp_direct["status"] == "pass"
if execute_reload:
    checks["reload_command_passed"] = command_passed(reload_report)
    checks["service_active_running_after_reload"] = service_after_reload.get(
        "active_running"
    ) is True

blockers = [name for name, passed in checks.items() if passed is not True]
summary = {
    "name": "daex-production-semantic-probe",
    "schema": "daex-production-semantic-probe-v1",
    "status": "pass" if not blockers else "blocked",
    "probe_netns": probe_netns,
    "checks": checks,
    "blockers": blockers,
    "binary": binary_report,
    "service_before": service_before,
    "config_validate": validate,
    "config_semantics": semantics,
    "resident_start_report": resident_report,
    "dns_udp_probe": dns,
    "udp_19090_worker_probe": udp,
    "tcp_direct_probe": tcp_direct,
    "reload": reload_report,
    "service_after_reload": service_after_reload,
    "summary_file": str(summary_file),
    "source": [
        "DAEX_RUST_PERFORMANCE_OPTIMIZATION_PLAN_2026-05-24.md:production-semantic-probe",
        "resident production config fallback direct is expected",
        "udp/19090 is the explicit proxy ingress rule",
    ],
}
summary_file.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2, ensure_ascii=False))
if blockers:
    sys.exit(1)
PY
