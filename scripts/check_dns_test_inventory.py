#!/usr/bin/env python3
"""Fail if a feature-gated runtime suite silently disappears from the test graph."""
import argparse
import json
import subprocess
import sys

SUITES = {
    "dae-dns": "name::tests::",
    "dae-resident-udp": "udp::shared_io::tests::",
    "dae-resident-dataplane": "dns_runtime_tests::",
    "dae-resident-dns": "runtime::transport::udp_multiplex::tests::",
}


CRITICAL_TESTS = {
    "dae-resident-udp": [
        "udp::shared_io::tests::partial_stream_send_allows_receiving_but_requires_session_reset_on_cancel",
        "udp::vmess_session::fixed_target_tests::owned_dns_sends_preserve_packet_boundaries_without_returned_scratch",
    ],
    "dae-dns": [
        "hot_path::tests::truncated_responses_never_produce_cache_or_route_owner_plans",
        "name::tests::all_question_and_answer_parsers_reject_overlong_names",
        "name::tests::expanded_name_limits_apply_across_compression_and_scopes",
        "name::tests::compressed_wire_bytes_do_not_consume_the_expanded_name_budget",
        "cache_key::label_boundary_tests::presentation_names_preserve_labels_octets_and_hash_identity",
        "reuse::tests::request_reuse_separates_flags_edns_versions_and_udp_sizes",
        "hot_path::negative::tests::negative_cache_uses_soa_ttl_and_minimum_and_fixed_ttl_only_shortens",
    ],
    "dae-resident-dns": [
        "runtime::cache_tests::tc_udp_then_tcp_and_edns_retry_reach_the_upstream",
        "runtime::cache_tests::cache_and_flight_share_only_compatible_requests_and_restore_case",
        "runtime::cache_tests::escaped_labels_stay_separate_in_cache_flights_reload_and_owner_removal",
        "runtime::cache_tests::resident_dns_flight_bounds_followers_and_retained_response_bytes",
        "cache::poison_tests::registering_during_publication_never_loses_a_waiter",
        "cache::poison_tests::publication_without_followers_does_not_copy_or_reserve_a_response",
        "runtime::transport::wire::doh_limit_tests::doh_http1_limits_decoded_body_separately_from_headers_and_chunks",
        "runtime::transport::tls_https::tests::doh_h2_bounds_decoded_body_across_data_frames",
        "runtime::transport::tls_https::tests::doh_h2_rejects_oversized_content_length_before_waiting_for_data",
        "runtime::transport::h3::proxied::request::body_limit_tests::direct_and_proxy_doh3_bound_body_and_reject_large_declared_lengths",
        "clock::tests::wall_clock_steps_do_not_change_fixed_original_ttls_or_reload_deadlines",
    ],
    "dae-resident-dataplane": [
        "udp::proxy_dns_forwarder::tests::backpressure::pending_response_completes_while_another_send_is_backpressured",
        "udp::proxy_dns_forwarder::tests::backpressure::cancelling_a_pending_request_progresses_during_send_backpressure",
        "udp::proxy_dns_forwarder::tests::backpressure::pending_deadline_progresses_during_send_backpressure",
        "udp::proxy_dns_forwarder::tests::backpressure::cancelling_a_datagram_send_preserves_other_pending_and_socket",
        "udp::proxy_dns_forwarder::tests::backpressure::datagram_send_deadline_preserves_other_pending_and_socket",
        "udp::proxy_dns_forwarder::tests::backpressure::local_datagram_send_error_preserves_other_pending_and_socket",
        "udp::proxy_dns_forwarder::tests::backpressure::failed_datagram_sender_reopens_after_older_pending_drains",
        "udp::proxy_dns_forwarder::tests::backpressure::shared_session_send_failure_resets_other_pending",
        "udp::proxy_dns_forwarder::tests::backpressure::shutdown_interrupts_send_backpressure_and_releases_all_budgets",
        "udp::proxy_dns_forwarder::tests::backpressure::shutdown_interrupts_first_connection_handshake",
        "udp::proxy_dns_forwarder::tests::request_local_oversize_send_failure_preserves_an_existing_pending_response",
        "dns_runtime_tests::plan::resident_dns_ipversion_prefer_preserves_non_preferred_cached_response",
    ],
}


def verify_critical_tests(package, listed, ignored):
    active = set(listed) - set(ignored)
    missing = [name for name in CRITICAL_TESTS[package] if name + ": test" not in active]
    if missing:
        raise RuntimeError(f"{package}: critical DNS tests missing or ignored: {', '.join(missing)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default="production-performance")
    args = parser.parse_args()
    for package, prefix in SUITES.items():
        command = ["cargo", "test", "--locked", "--profile", args.profile,
                   "-p", package, "--lib", "--no-run", "--message-format=json"]
        if package in {"dae-resident-dns", "dae-resident-dataplane"}:
            command.extend(["--features", "dns-runtime-tests"])
        binaries = []
        with subprocess.Popen(command, stdout=subprocess.PIPE, text=True) as process:
            for line in process.stdout:
                message = json.loads(line)
                if (message.get("reason") == "compiler-artifact"
                        and message.get("profile", {}).get("test")
                        and message.get("executable")
                        and message["target"]["name"] == package.replace("-", "_")):
                    binaries.append(message["executable"])
            if process.wait():
                return 1
        if len(binaries) != 1:
            raise RuntimeError(f"{package}: expected one test executable")
        result = subprocess.run([binaries[0], "--list", "--format", "terse"],
                                text=True, capture_output=True, check=True)
        required = {line for line in result.stdout.splitlines()
                    if line.startswith(prefix) and line.endswith(": test")}
        ignored = subprocess.run([binaries[0], "--ignored", "--list", "--format", "terse"],
                                 text=True, capture_output=True, check=True)
        verify_critical_tests(package, result.stdout.splitlines(), ignored.stdout.splitlines())
        active = required - set(ignored.stdout.splitlines())
        if not active:
            raise RuntimeError(f"{package}: required suite {prefix} has no active tests")
        print(f"OK: {package} {prefix}: {len(active)} active, "
              f"{len(required) - len(active)} explicitly ignored tests")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
