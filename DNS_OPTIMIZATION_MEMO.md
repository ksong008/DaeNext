# DNS Optimization Memo

Date: 2026-04-18
Branch: `personal/test-dns`

## Background

This memo records the DNS-related problems found during investigation, the fixes already applied, the test/workflow adjustments made to validate those fixes, and the next optimization items to continue.

## Problems Found

### 1. Local DNS listener correctness issues

- `dns.bind` could be combined with `dns.routing.request -> asis`, which caused the request to be sent back to `dae` itself and form a self-loop.
- The local DNS listener parsed the configured bind string instead of the actual listener address from `ResponseWriter`, which made address handling fragile.
- The TCP DNS listener startup path called `ListenAndServe()` twice on failure.

### 2. DNS forwarder lifecycle / resource management issues

- `DoUDP` created a UDP connection but did not store it into `d.conn`, so `Close()` could not reliably close it.
- `dnsForwarderCache` reused forwarder instances that were not safe to share:
  - `DoTCP`
  - `DoTLS`
  - `DoUDP`
  These implementations stored per-request connection state on the struct itself, which made cache reuse unsafe under concurrency.
- `DoH` mutated `http.Client.CheckRedirect` per request, which was not safe for shared use.
- `DoQ` / `DoTLS` had cleanup gaps on error paths.

### 3. DNS UDP behavior issues

- UDP upstream queries used a background resend loop that resent packets every second in a fairly blind way.
- DNS timeout/failure information was not actually fed back into dialer health reporting, even though the callback path existed.

### 4. DNS cache / routing synchronization issues

- Expired DNS cache entries were treated as misses, but were not actively removed.
- `cacheRemoveCallback` was not properly used for expired entry cleanup, so the kernel-side domain routing map could keep stale associations longer than desired.

### 5. DNS upstream freshness issue

- `UpstreamResolver` effectively resolved an upstream only once and then reused it indefinitely.
- For upstreams backed by domains/CDN/rotating IPs, this could pin `dae` to stale upstream IPs for too long.

### 6. `ipversion_prefer` latency issue

- When handling `A`/`AAAA` with preference enabled, the implementation waited on both lookups too aggressively.
- This could delay the preferred fast path and add unnecessary upstream pressure.

### 7. Validation workflow problems discovered while testing

- There was no dedicated lightweight workflow for core validation on the test branch.
- Existing unit execution did not clearly report which package failed.
- CI lacked geolocation assets (`geoip.dat`, `geosite.dat`) for some tests.
- A number of legacy tests had brittle assumptions unrelated to the new DNS logic, which blocked end-to-end validation:
  - config marshal round-trip metadata comparison
  - config marshaller missing leaf types
  - bitlist capacity assumptions tied to internal buffer growth strategy
  - packet sniffer tests sharing global state
  - outbound dialer group tests depending on random distribution / dead dialers being considered “best”

## Changes Applied

### A. Local listener safety

Files:

- `control/dns_listener.go`
- `control/dns_control.go`
- `docs/en/configuration/dns.md`
- `docs/zh/configuration/dns.md`
- `control/dns_listener_test.go`

Changes:

- Parse actual local/remote addresses from `dns.ResponseWriter`.
- Fix duplicate TCP listener startup call.
- Reject `asis` when `dns.bind` is used through the local listener path.
- Add tests for:
  - endpoint parsing
  - address parsing
  - local listener rejecting `asis`
- Document that `dns.bind` must not be combined with `request -> asis`.

### B. Forwarder lifecycle and DNS path safety

Files:

- `control/dns.go`
- `control/dns_control.go`
- `control/control_plane.go`
- `control/dns_control_test.go`

Changes:

- Introduced reuse policy:
  - reusable: DoH / DoQ class of forwarders that are safe to cache
  - non-reusable: TCP / TLS / plain UDP forwarders that hold per-request connection state
- Closed non-reusable forwarders immediately after use.
- Wired timeout/failure detection back into `TimeoutExceedCallback`.
- Fixed UDP connection close path by storing the created connection.
- Replaced blind resend behavior with bounded retry logic.
- Made DoH client reuse safer.
- Added cache cleanup on expired DNS entries and on explicit cache removal.
- Added tests around:
  - reusable forwarder selection
  - timeout failure classification
  - expired cache removal
  - DNS ID zeroing helper behavior

### C. DNS upstream refresh

Files:

- `component/dns/upstream.go`
- `component/dns/upstream_test.go`
- `component/dns/dns.go`

Changes:

- Added refresh-aware `UpstreamResolver` behavior.
- Added:
  - refresh interval
  - retry interval
  - injectable clock and resolver for tests
- On refresh failure, keep the last known good upstream and retry later.
- Added `Upstream.Index` so response routing does not need a side map from `*Upstream -> index`.
- Added tests for:
  - cache reuse before refresh
  - refresh after interval
  - fallback to previous upstream on refresh failure

### D. `ipversion_prefer` path optimization

File:

- `control/dns_control.go`

Changes:

- Preferred qtype (`A` or `AAAA`, depending on config) now takes the direct fast path and does not wait for the opposite qtype.
- Non-preferred qtype still performs concurrent coordination:
  - if preferred qtype has IPs, reject the non-preferred query
  - otherwise use the requested qtype result
- This reduces unnecessary waiting and cuts duplicate upstream work on the common path.

### E. DNS cache / forwarder cleanup and long-running memory control

Files:

- `control/dns_control.go`
- `control/dns_control_test.go`

Changes:

- Added background cleanup workers to `DnsController`.
- Added periodic DNS cache sweeping for expired entries.
- Expired cache removal now actively calls `cacheRemoveCallback`, which helps keep kernel-side domain routing in sync.
- Added DNS forwarder cache idle eviction.
- Added DNS forwarder cache capacity cap and oldest-entry eviction when the cache is full.
- Added controller lifecycle handling so background cleanup goroutines are stopped on `Close()`.
- Added tests for:
  - cache expiry sweep behavior
  - respecting the latest effective deadline
  - forwarder idle eviction
  - forwarder oldest-entry eviction when cache is full

## Validation Workflow Changes

File:

- `.github/workflows/daecore.yml`

Changes:

- Added dedicated `daecore` workflow.
- Split into `unit` and `build` jobs.
- Added geolocation asset preparation in CI.
- Added better package-level failure reporting in `unit`.
- Kept `control/kern/tests` outside this workflow because it belongs to specialized kernel/BPF validation.

## Supporting Test/Infrastructure Fixes Found During Validation

These were not the original DNS target, but were necessary to make the branch testable end-to-end.

Files:

- `config/marshal.go`
- `config/marshal_test.go`
- `common/bitlist/bitlist_test.go`
- `common/netutils/ip46_test.go`
- `control/packet_sniffer_pool_test.go`
- `component/outbound/dialer_group_test.go`

Summary:

- Ignore parse-time annotation metadata when checking config marshal round-trip equality.
- Support additional scalar leaf types in config marshaller.
- Remove brittle assumptions about internal buffer capacity growth in bitlist tests.
- Initialize direct dialers explicitly in `ResolveIp46` test.
- Isolate packet sniffer tests from global pooled state.
- Make outbound selection tests deterministic and aligned with actual alive-dialer selection semantics.

## Commits So Far

- `0fc95a6` Improve DNS forwarder lifecycle and listener safety
- `d578694` Add daecore workflow for core validation
- `86930b1` Split daecore workflow into unit and build jobs
- `5c9f4a3` Stabilize daecore unit coverage
- `d1e5a0d` Fix unit test assumptions for daecore
- `5502101` Narrow daecore unit scope to stable core packages
- `4d3e7c0` Restore full daecore coverage and fix test robustness
- `0e6d58d` Support int leaves in config marshaller
- `c91848d` Normalize config marshal round-trip assertions
- `f627094` Improve daecore unit failure diagnostics
- `d565dd1` Stabilize outbound dialer group tests
- `e1f77b0` Refresh DNS upstreams and streamline ip preference
- `461f66b` Add DNS cache and forwarder cleanup

## Current Validation Strategy

- Work on `personal/test-dns`
- Let `daecore` validate the branch before merging/cherry-picking into `personal/stable`
- Keep iterating on failures until the test branch is stable

## Recommended Next DNS Optimization Items

### 1. Cache eviction / cleanup strategy

- Completed in a first useful form.
- Remaining work:
  - consider configurable cache size / policy per deployment
  - consider richer eviction signals beyond idle time and hard cap

### 2. Make upstream refresh configurable

- Expose refresh interval / retry interval via config if needed.
- Consider jitter to avoid synchronized refresh spikes.

### 3. DNS metrics / observability

- Track:
  - refresh success/failure
  - fallback-to-stale events
  - qtype preference short-circuit rate
  - UDP retry counts
  - cache hit / expired / removed counters

### 4. Evaluate whether reusable forwarders need bounded cache size

- Basic cap + idle eviction has been added.
- Remaining work:
  - measure whether the default cap is appropriate
  - decide whether protocol-specific caps are needed

### 5. Optimize cache hit hot path

- Partially completed.
- Done:
  - `dnsCacheMu` upgraded to `RWMutex`
  - pre-packed cached DNS responses added for cache-hit fast path
- Remaining opportunities:
  - shard `dnsCache` for even lower lock contention under very high concurrency
  - consider packing only hot entries if memory/entry ratio becomes a concern

## Memory / Lifecycle Audit Conclusion

Date: 2026-04-18

The DNS module was reviewed with the goals:

- stability
- speed
- no memory leaks / no unbounded long-running growth

Current conclusion:

- No obvious leak-style issue remains on the primary DNS path.
- The module is now in a "safe and tunable" state rather than a "buggy and risky" state.

Reviewed areas:

- `dnsCache`
  - now has active expiration sweep
  - removal path is wired to kernel-side cleanup callback
  - remaining concern is tuning / capacity policy, not leakage

- `dnsForwarderCache`
  - now has idle eviction
  - now has hard capacity cap
  - remaining concern is threshold tuning, not unbounded growth

- `handling sync.Map`
  - reference count + delete-on-zero path looks bounded

- background goroutines
  - `DnsController` janitors are tied to context cancellation
  - `Close()` now cancels and waits

- `UpstreamResolver`
  - bounded per-upstream state
  - refresh with stale fallback does not introduce growth across refresh cycles

- transport forwarders
  - reusable vs non-reusable split is in place
  - close paths are much safer than the original implementation

Net assessment:

- acceptable for continued use and iteration
- further work should focus on bounded-performance tuning, not emergency leak fixing

### 6. Revisit remaining package-level test stability

- Keep improving `daecore` until it provides a dependable branch-gating signal for broader changes, not just DNS.
