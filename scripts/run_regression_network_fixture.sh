#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

if [[ "$(id -u)" != "0" ]]; then
  echo "network regression fixture requires root" >&2
  exit 2
fi

for tool in ip tc ping; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "network regression fixture is missing required tool: $tool" >&2
    exit 2
  fi
done

run_id="${RUN_ID:-$$}"
suffix="$(printf '%s' "$run_id" | tr -cd '[:alnum:]' | tail -c 7)"
[[ -n "$suffix" ]] || suffix="$$"
left_ns="d0l-${suffix}"
right_ns="d0r-${suffix}"
left_if="d0l${suffix}"
right_if="d0r${suffix}"
left_vlan="v${suffix}l"
right_vlan="v${suffix}r"
l3_if="t${suffix}"
vlan_id="${FIXTURE_VLAN_ID:-100}"
left_v4="${FIXTURE_LEFT_V4:-198.18.0.1/30}"
right_v4="${FIXTURE_RIGHT_V4:-198.18.0.2/30}"
right_target="${FIXTURE_RIGHT_TARGET:-198.18.0.2}"
left_vlan_v4="${FIXTURE_LEFT_VLAN_V4:-198.18.1.1/30}"
right_vlan_v4="${FIXTURE_RIGHT_VLAN_V4:-198.18.1.2/30}"
right_vlan_target="${FIXTURE_RIGHT_VLAN_TARGET:-198.18.1.2}"
capture_root="${RUN_ROOT:-/tmp/daenext-network-fixture-${suffix}}"
capture_pid=""

case "$capture_root" in
  /tmp/daenext-network-fixture-*) ;;
  *)
    echo "refusing unsafe RUN_ROOT outside /tmp/daenext-network-fixture-*: $capture_root" >&2
    exit 2
    ;;
esac

cleanup() {
  set +e
  if [[ -n "$capture_pid" ]]; then
    kill "$capture_pid" >/dev/null 2>&1 || true
    wait "$capture_pid" >/dev/null 2>&1 || true
  fi
  ip netns del "$left_ns" >/dev/null 2>&1 || true
  ip netns del "$right_ns" >/dev/null 2>&1 || true
  rm -rf "$capture_root"
}
trap cleanup EXIT INT TERM

cleanup
mkdir -p "$capture_root"
ip netns add "$left_ns"
ip netns add "$right_ns"
ip link add "$left_if" type veth peer name "$right_if"
ip link set "$left_if" netns "$left_ns"
ip link set "$right_if" netns "$right_ns"
ip -n "$left_ns" address add "$left_v4" dev "$left_if"
ip -n "$right_ns" address add "$right_v4" dev "$right_if"
ip -n "$left_ns" link set lo up
ip -n "$right_ns" link set lo up
ip -n "$left_ns" link set "$left_if" up
ip -n "$right_ns" link set "$right_if" up

if command -v tcpdump >/dev/null 2>&1; then
  timeout 5 ip netns exec "$right_ns" tcpdump -i "$right_if" -c 1 -nn icmp \
    >"$capture_root/untagged.pcap.txt" 2>&1 &
  capture_pid="$!"
fi
ip netns exec "$left_ns" ping -c 2 -W 1 "$right_target" >/dev/null
if [[ -n "$capture_pid" ]]; then
  wait "$capture_pid"
  capture_pid=""
  rg -q "ICMP echo request" "$capture_root/untagged.pcap.txt"
fi

if ! ip -n "$left_ns" link add link "$left_if" name "$left_vlan" type vlan id "$vlan_id"; then
  echo "failed to create left VLAN $vlan_id" >&2
  exit 1
fi
if ! ip -n "$right_ns" link add link "$right_if" name "$right_vlan" type vlan id "$vlan_id"; then
  echo "failed to create right VLAN $vlan_id" >&2
  exit 1
fi
ip -n "$left_ns" address add "$left_vlan_v4" dev "$left_vlan"
ip -n "$right_ns" address add "$right_vlan_v4" dev "$right_vlan"
ip -n "$left_ns" link set "$left_vlan" up
ip -n "$right_ns" link set "$right_vlan" up
ip netns exec "$left_ns" ping -I "$left_vlan" -c 2 -W 1 "$right_vlan_target" >/dev/null

ip netns exec "$left_ns" tc qdisc add dev "$left_if" clsact
ip netns exec "$left_ns" tc filter add dev "$left_if" egress pref 49100 \
  matchall action pass
ip netns exec "$left_ns" ping -c 2 -W 1 "$right_target" >/dev/null
tc_stats="$(ip netns exec "$left_ns" tc -s filter show dev "$left_if" egress pref 49100)"
if ! rg -q "Sent [1-9][0-9]* bytes [1-9][0-9]* pkt" <<<"$tc_stats"; then
  echo "later-TC counter did not observe fixture traffic" >&2
  printf '%s\n' "$tc_stats" | head -c 4000 >&2
  exit 1
fi

if [[ -e /dev/net/tun ]]; then
  ip netns exec "$left_ns" ip tuntap add dev "$l3_if" mode tun
  first_ifindex="$(ip -n "$left_ns" -o link show "$l3_if" | cut -d: -f1)"
  ip -n "$left_ns" link del "$l3_if"
  ip netns exec "$left_ns" ip tuntap add dev "$l3_if" mode tun
  second_ifindex="$(ip -n "$left_ns" -o link show "$l3_if" | cut -d: -f1)"
  [[ "$first_ifindex" != "$second_ifindex" ]]
fi

if [[ -n "${CGROUP_SCENARIO_DRIVER:-}" ]]; then
  if [[ ! -x "$CGROUP_SCENARIO_DRIVER" ]]; then
    echo "CGROUP_SCENARIO_DRIVER is not executable" >&2
    exit 2
  fi
  for mode in empty multi single; do
    "$CGROUP_SCENARIO_DRIVER" "$mode" "$capture_root/cgroup-$mode"
  done
fi

echo "network regression fixture passed: untagged, VLAN, later-TC, capture, and L3 recreation"
