#!/usr/bin/env python3
"""Enforce physical ownership of extracted product-control domains."""

from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).parents[2]
REQUIRED_CRATES = (
    "dae-product-core",
    "dae-product-control",
    "dae-product-http",
    "dae-product-identity",
    "dae-product-persistence",
    "dae-product-runtime",
    "dae-product-subscription",
    "dae-product-geodata",
)
REQUIRED_OWNERSHIP_FILES = (
    "crates/dae-product-control/src/local_control_client.rs",
    "crates/dae-product-control/src/routes.rs",
    "crates/dae-product-control/src/durable_recovery.rs",
    "crates/dae-product-control/src/auth_crypto.rs",
    "crates/dae-product-control/src/bundle/export.rs",
    "crates/dae-product-control/src/bundle/import.rs",
    "crates/dae-product-http/src/job_queue.rs",
    "crates/dae-product-http/src/listener_readiness.rs",
    "crates/dae-product-runtime/src/active_resources.rs",
    "crates/dae-product-runtime/src/global_config.rs",
    "crates/dae-product-runtime/src/benchmark.rs",
    "crates/dae-product-http/src/route_audit.rs",
    "crates/dae-product-core/src/package.rs",
    "crates/dae-product-identity/src/auth.rs",
    "crates/dae-product-persistence/src/json_storage.rs",
    "crates/dae-product-persistence/src/state/mod.rs",
    "crates/dae-product-subscription/src/group_store.rs",
    "crates/dae-product-subscription/src/group_summary.rs",
    "crates/dae-product-subscription/src/group_summary_batch.rs",
    "crates/dae-product-subscription/src/node_view.rs",
    "crates/dae-product-subscription/src/scheduler.rs",
    "crates/dae-product-subscription/src/subscription_view.rs",
    "crates/dae-product-control/src/groups.rs",
    "crates/dae-product-control/src/groups.rs",
    "crates/dae-product-control/src/group_filter_preview.rs",
    "crates/dae-product-control/src/file_import/mod.rs",
    "crates/dae-product-runtime/src/materialization.rs",
    "crates/dae-product-subscription/src/refresh_node_sync.rs",
    "crates/dae-product-subscription/src/refresh_transaction.rs",
    "crates/dae-product-control/src/section_parsers.rs",
    "crates/dae-product-control/src/sections.rs",
    "crates/dae-product-control/src/selection.rs",
)
FORBIDDEN_DAEMON_PATHS = (
    "control_runtime",
    "auth_runtime",
    "durable_commit",
    "durable_recovery.rs",
    "http_connections.rs",
    "http_request.rs",
    "http_request",
    "http_server/job_queue.rs",
    "http_server/listener_readiness.rs",
    "product_shutdown.rs",
    "state_connection.rs",
    "state_integrity.rs",
    "state_migration.rs",
    "state_schema.rs",
    "runtime_transition.rs",
    "benchmark.rs",
    "resources/global_merge.rs",
    "resources/global_parse_helpers.rs",
    "resources/global_render.rs",
    "resources/global_config.rs",
    "runtime_apply/coordinator.rs",
    "runtime_materialization/materialize.rs",
    "runtime_materialization/queries.rs",
    "runtime_materialization/render.rs",
    "nodes_subscriptions_groups/subscription_refresh/node_sync.rs",
    "nodes_subscriptions_groups/subscription_refresh/transaction.rs",
    "runtime_materialization/metadata.rs",
    "runtime_materialization/active_resources.rs",
    "dae_file_import.rs",
    "dae_file_import",
    "geodata/file.rs",
    "geodata/source.rs",
    "geodata/status_cache.rs",
    "geodata/time.rs",
    "geodata/transaction/journal.rs",
    "geodata/transaction/recovery.rs",
    "geodata/types.rs",
    "nodes_subscriptions_groups/node_identity.rs",
    "nodes_subscriptions_groups/group_summary.rs",
    "nodes_subscriptions_groups/group_summary_batch.rs",
    "nodes_subscriptions_groups/groups.rs",
    "nodes_subscriptions_groups/subscription_delete.rs",
    "nodes_subscriptions_groups/subscription_filter_preview.rs",
    "nodes_subscriptions_groups/groups.rs",
    "nodes_subscriptions_groups/scheduler/invalid_cron.rs",
    "nodes_subscriptions_groups/subscription_import_result.rs",
    "nodes_subscriptions_groups/subscription_refresh/content.rs",
    "nodes_subscriptions_groups/subscription_refresh/fetch_error.rs",
    "nodes_subscriptions_groups/subscription_refresh/outcome.rs",
    "nodes_subscriptions_groups/subscription_refresh/persistence.rs",
    "nodes_subscriptions_groups/subscription_refresh/helper/process.rs",
    "nodes_subscriptions_groups/subscription_refresh/helper/protocol.rs",
    "runtime_overview/cgroup_memory",
    "runtime_overview/interfaces.rs",
    "latency/job_state.rs",
    "latency/nodes.rs",
    "latency/persistence.rs",
    "latency/storage.rs",
)
FORBIDDEN_DAEMON_DEFINITIONS = (
    "classify_product_api_route",
    "compile_subscription_name_filter",
    "count_nodes_for_subscription",
    "due_scheduled_subscriptions",
    "get_group_value_with_conn",
    "list_group_summaries_batched",
    "list_nodes_by_scope_with_connection",
    "list_subscriptions_value",
    "load_active_runtime_resources",
    "run_local_control_reload_command",
    "run_local_control_wait_ready_command",
    "subscription_node_row_value",
)
DAEMON_CRATE_REFERENCE = re.compile(
    r"\b(?:dae_daemon\s*::|(?:pub\s+)?use\s+dae_daemon\b|extern\s+crate\s+dae_daemon\b)"
)
DAEMON_RESIDENT_INTERNAL_REFERENCE = re.compile(
    r"\bdae_resident_(?:core|dns|plan|tcp|udp|transport)\s*(?:::|;)|"
    r"\bdae_resident_dataplane\s*::(?!\s*facade\s*::)"
)
PRODUCT_CRATE_REFERENCE = re.compile(r"\bdae_product_[A-Za-z0-9_]+\b")


def rust_sources(root: pathlib.Path) -> list[pathlib.Path]:
    return sorted(root.rglob("*.rs"))


def validate(root: pathlib.Path) -> list[str]:
    errors: list[str] = []
    product_roots: list[pathlib.Path] = []
    for crate in REQUIRED_CRATES:
        source = root / "crates" / crate / "src"
        if not source.is_dir():
            errors.append(f"required product source directory is missing: {source.relative_to(root)}")
        else:
            product_roots.append(source)

    for relative in REQUIRED_OWNERSHIP_FILES:
        path = root / relative
        if not path.is_file():
            errors.append(f"required product owner file is missing: {relative}")

    daemon_product = root / "crates" / "dae-daemon" / "src" / "daed_product"
    if not daemon_product.is_dir():
        errors.append(
            f"daemon product adapter directory is missing: {daemon_product.relative_to(root)}"
        )
    else:
        for relative in FORBIDDEN_DAEMON_PATHS:
            path = daemon_product / relative
            contains_source = path.is_file() or (path.is_dir() and any(path.rglob("*.rs")))
            if contains_source:
                errors.append(
                    f"extracted product implementation returned to daemon: {path.relative_to(root)}"
                )

    for source_root in product_roots:
        for path in rust_sources(source_root):
            text = path.read_text(encoding="utf-8")
            if DAEMON_CRATE_REFERENCE.search(text):
                errors.append(
                    f"product crate references daemon implementation: {path.relative_to(root)}"
                )

    daemon_root = root / "crates" / "dae-daemon" / "src"
    if daemon_root.is_dir():
        for path in rust_sources(daemon_root):
            text = path.read_text(encoding="utf-8")
            if DAEMON_RESIDENT_INTERNAL_REFERENCE.search(text):
                errors.append(
                    f"daemon bypasses resident facade: {path.relative_to(root)}"
                )
            for name in FORBIDDEN_DAEMON_DEFINITIONS:
                if re.search(rf"\bfn\s+{re.escape(name)}\b", text):
                    errors.append(
                        f"extracted product function returned to daemon: "
                        f"{path.relative_to(root)} ({name})"
                    )
            if path.parent == daemon_product and path.name == "daed_product.rs":
                continue
            if "extern crate dae_product_" in text:
                errors.append(
                    f"daemon bypasses product facade with extern crate: {path.relative_to(root)}"
                )
            for line_number, line in enumerate(text.splitlines(), start=1):
                if "pub mod dae_product_" in line and PRODUCT_CRATE_REFERENCE.search(line):
                    errors.append(
                        f"daemon shadows a product crate module: {path.relative_to(root)}:{line_number}"
                    )
    return errors


def main() -> int:
    errors = validate(ROOT)
    if errors:
        print("product boundary gate: FAILED", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(
        "product boundary gate: PASS "
        f"({len(REQUIRED_CRATES)} product crates, extracted ownership paths checked)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
