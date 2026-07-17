#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

pid="${PID:?set PID to the daemon process id}"
label="${LABEL:-observation}"
run_id="${RUN_ID:-$(date +%Y%m%d%H%M%S)-$$}"
output_root="${OUTPUT_ROOT:-/tmp/daenext-process-memory-${pid}-${run_id}}"
report="${REPORT:-$output_root/samples.tsv}"
delays="${SAMPLE_DELAYS_SECONDS:-0 2 5 10 15 30}"

if [[ ! -r "/proc/$pid/status" ]]; then
  printf 'process %s is not readable\n' "$pid" >&2
  exit 1
fi

mkdir -p "$output_root" "$(dirname "$report")"
if [[ ! -e "$report" ]]; then
  printf 'recorded_at\tlabel\tdelay_seconds\trss_kib\trss_anon_kib\trss_file_kib\tvm_data_kib\tthreads\tfds\tsocket_fds\tudp4\tudp6\n' >"$report"
fi

started_at="$(date +%s)"
for delay in $delays; do
  target_time="$((started_at + delay))"
  now="$(date +%s)"
  if (( target_time > now )); then
    sleep "$((target_time - now))"
  fi
  if [[ ! -r "/proc/$pid/status" ]]; then
    printf 'process %s exited before delay %s\n' "$pid" "$delay" >&2
    exit 1
  fi

  status="/proc/$pid/status"
  rss="$(awk '$1 == "VmRSS:" {print $2}' "$status")"
  rss_anon="$(awk '$1 == "RssAnon:" {print $2}' "$status")"
  rss_file="$(awk '$1 == "RssFile:" {print $2}' "$status")"
  vm_data="$(awk '$1 == "VmData:" {print $2}' "$status")"
  threads="$(awk '$1 == "Threads:" {print $2}' "$status")"
  fds="$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)"
  socket_fds="$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 -type l -lname 'socket:*' 2>/dev/null | wc -l)"
  udp4="$(awk 'NR > 1 {count += 1} END {print count + 0}' "/proc/$pid/net/udp")"
  udp6="$(awk 'NR > 1 {count += 1} END {print count + 0}' "/proc/$pid/net/udp6")"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(date --iso-8601=seconds)" "$label" "$delay" "$rss" "$rss_anon" "$rss_file" \
    "$vm_data" "$threads" "$fds" "$socket_fds" "$udp4" "$udp6" >>"$report"
done

printf '%s\n' "$report"
