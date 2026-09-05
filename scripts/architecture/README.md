# Architecture dependency gate

`dependency_policy.json` is the allowlist for direct workspace-to-workspace
dependencies. Every workspace package has a layer identity and separate
`normal`, `build`, and `dev` dependency sets. The policy is default-deny:
adding a direct workspace edge requires an intentional policy change.

The checker validates:

- workspace membership and package/layer coverage;
- exact Cargo metadata edges for all three dependency kinds;
- cycles in normal/build dependency edges;
- layer direction and generic same-layer resident-domain boundaries;
- workspace crate imports in production, dev, and build sources;
- bare, visibility-qualified, grouped, and `extern crate` workspace imports;
- product domain crates cannot directly depend on another product domain crate;
- external `#[path]` source embedding, except for explicit test-only compatibility paths.
- production/test line budgets for the large daemon, resident assembly, and outbound boundaries.
- daemon access to resident implementations is restricted to the resident façade.

The product adapter policy also assigns every remaining daemon product path to
an explicit role and enforces both per-path and aggregate production budgets.
These paths are host adapters only: product behavior belongs to the product
crates, while resident startup, allocator integration, HTTP socket handling,
and process-level observation remain in the daemon.

Run it locally with:

```text
python3 scripts/architecture/check_dependencies.py
```

When a physical boundary changes, update the policy and the relevant boundary
tests in the same change. The checker and its synthetic regression tests run
from `scripts/release_gate.sh`.

The product-control adapter exposes selected symbols in `domain_api.rs` rather
than entire product crates. The product boundary checker rejects whole-domain
re-exports; adding a public domain symbol does not automatically expose it to
the daemon. `OwnerGeneration` belongs to `dae-core-types`; runtime-control
retains a compatibility re-export of that same type.

`source_boundary_policy.json` keeps the v1 `production` field's historical
meaning: lines in non-test-named Rust files, including inline tests, comments,
and blank lines. Package and subtree limits overlap and are checked separately,
never added together. Reviewed baselines are fixed; CI does not refresh them
automatically. This source count is not evidence about selected release features.

`check_release_features.py` checks the default `dae-daemon` normal/build graph
independently of workspace tests and benchmarks. It compares complete feature
tokens and package identities, rejects support features and forbidden providers,
and fails if Cargo or parsing fails. `check_production_deps.sh --all-features`
retains workspace analysis while still checking an independent default product
graph; it does not build mutually exclusive production features together.

Use `--target`, `--features`, and `--no-default-features` to check a supported
product variant. Cargo tree can union features of repeated host/target package
identities; the checker conservatively rejects forbidden features in that
union, so separate product compilation remains necessary. The release gate
therefore runs a default daemon check before its workspace checks.

Test support belongs in dev dependencies or explicitly enabled test features.
Product-control/runtime benchmark fixtures require `benchmark-support`, which
the existing daemon benchmark feature forwards and `dae-bench` enables. The
legacy Boring selector names remain compatible without enabling QUIC fixtures.
