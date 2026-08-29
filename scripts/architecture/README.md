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
- workspace crate imports in production and build sources;
- external `#[path]` source embedding, except for explicit test-only compatibility paths.
- production/test line budgets for the large daemon, resident assembly, and outbound boundaries.
- daemon access to resident implementations is restricted to the resident façade.

Run it locally with:

```text
python3 scripts/architecture/check_dependencies.py
```

When a physical boundary changes, update the policy and the relevant boundary
tests in the same change. The checker and its synthetic regression tests run
from `scripts/release_gate.sh`.
