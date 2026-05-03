# DNS Optimization Memo

Date: 2026-04-18
Branch: `personal/stable`

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

## 2026-05-03 Follow-up DNS Review

Scope:

- review only; no code changes applied in this pass
- re-check current `dae` DNS implementation after the earlier lifecycle/cache fixes
- identify the next worthwhile enhancement items rather than repeating already-completed cleanup work

Current assessment:

- The primary DNS path still looks materially better than the pre-fix state.
- No new obvious leak-style or unbounded-growth issue was found in this pass.
- The remaining work is now mostly correctness edge cases, protocol completeness, and observability.

Recommended next items by priority:

### 1. Add UDP truncation fallback to TCP for `tcp+udp` upstreams

Reason:

- `tcp+udp` upstream selection currently prefers UDP first.
- If the UDP response is truncated (`TC=1`), the current path does not appear to promote that query to TCP automatically.
- This leaves large answers, long TXT responses, DNSSEC-heavy replies, and similar cases less robust than they should be.

Suggested direction:

- Detect truncated UDP DNS responses.
- When the selected upstream supports TCP (`tcp+udp`), retry the same query over TCP automatically.
- Add a precise regression test around the `TC -> TCP` upgrade path.

### 2. Make DNS cache stats collection side-effect free, or make its cleanup path fully consistent

Reason:

- `CacheStats()` currently prunes expired DNS cache entries while collecting stats.
- That means a read-like runtime stats path can mutate DNS cache state.
- More importantly, this pruning path does not route expired-entry removal through the same `cacheRemoveCallback` handling used by the normal cache cleanup paths, which risks stale kernel-side domain-routing state lingering longer than expected.

Suggested direction:

- Prefer making `CacheStats()` a pure observation path.
- If it must prune, route removals through the same callback/cleanup logic used elsewhere.
- Add a unit test to lock this behavior down.

### 3. Strengthen DoH request/response handling

Reason:

- The current DoH path is GET-only.
- It does not appear to validate HTTP status code or response content type before attempting DNS unpack.
- When an upstream or middlebox returns an HTML error page, redirect page, or other non-DNS body, diagnosis becomes noisier than necessary.

Suggested direction:

- Validate HTTP status before unpacking.
- Validate `Content-Type` compatibility where practical.
- Consider POST fallback or POST-by-default for larger DNS payloads to reduce URL-length sensitivity.

### 4. Refine TTL / cache semantics

Reason:

- Cache normalization currently uses a fairly coarse TTL policy.
- Empty successful answers still collapse onto the Firefox-oriented minimum cache TTL behavior.
- Fixed TTL handling is functional, but there is still room to make the semantics clearer, especially for special records and manually seeded upstream-host cache entries.

Suggested direction:

- Revisit whether the effective TTL should use the minimum TTL across relevant answers instead of the first answer only.
- Revisit negative/no-answer success caching semantics explicitly.
- Re-check how `fixed_domain_ttl` should interact with manually seeded upstream-host cache entries.

### 5. Tighten response validation and observability

Reason:

- Response handling could be more defensive for mismatch/debug scenarios.
- Current runtime stats already expose DNS cache and DNS forwarder cache entry counts, but not the more useful DNS-path health counters.

Suggested direction:

- Consider validating response question identity more strictly before caching/serving.
- Add counters for:
  - UDP retries
  - `TC -> TCP` fallback count
  - DoH status/content-type failures
  - cache hits / expired removals
  - upstream refresh success / failure / stale-fallback reuse

Notes for future implementation:

- Start with item 1 first; it has the clearest correctness payoff.
- Item 2 is the next best cleanup because it affects runtime correctness and observability consistency.
- Items 3-5 can be staged independently after the transport fallback and stats-path cleanup are in place.

## 2026-05-03 Implementation Pass: `tcp+udp` truncated UDP fallback to TCP

Branch:

- `bpf0.21.0`

Goal:

- implement item 1 from the 2026-05-03 follow-up review
- improve correctness for `tcp+udp` DNS upstreams when the initial UDP response is truncated (`TC=1`)

Files changed:

- `control/dns_control.go`
- `control/dns_control_test.go`

Implementation summary:

- Extracted a small `forwardDnsUpstream` helper from `dialSend` so the actual forwarder acquire/send/release logic can be reused cleanly for protocol fallback without duplicating timeout and cleanup behavior.
- Added `shouldRetryTruncatedDnsOverTcp` to gate the new behavior narrowly:
  - response must be truncated
  - current transport must be UDP
  - configured upstream scheme must be `tcp+udp`
- Added a TCP-only re-selection step for the same upstream:
  - clone the upstream shape temporarily with scheme forced to `tcp`
  - call the existing `bestDialerChooser` again so TCP fallback chooses a proper TCP path instead of reusing the prior UDP choice blindly
- On successful TCP retry, continue normal response routing / normalization / caching using the TCP response.
- Kept the behavior intentionally narrow in this pass:
  - pure `udp://` upstreams are unchanged
  - no concurrent multi-upstream fan-out was introduced
  - no extra observability counters were added yet

Why this shape:

- The existing request path and response routing are single-upstream oriented.
- Re-running the selector with a TCP-only upstream view keeps the fallback compatible with the current dialer / routing design and avoids inventing a parallel selection path just for this case.
- Extracting the forwarding helper makes future DNS transport work easier, especially if later work adds hedged queries or richer transport fallback.

Tests added:

- `TestDialSendRetriesTruncatedTCPUDPResponseOverTCP`
  - verifies that a truncated UDP response from a `tcp+udp` upstream triggers a second TCP attempt
  - verifies that the TCP answer wins and is what ends up in DNS cache
- `TestDialSendDoesNotRetryTruncatedPureUDPResponseOverTCP`
  - verifies that plain `udp://` upstreams do not silently gain TCP fallback behavior

Validation:

- Formatting:
  - `/usr/lib/go-1.23/bin/gofmt -w /root/project/dae/control/dns_control.go /root/project/dae/control/dns_control_test.go`
- Focused regression:
  - `PATH=/usr/lib/go-1.23/bin:$PATH GOTOOLCHAIN=go1.24.3 GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn /usr/lib/go-1.23/bin/go test ./control -run 'Test(DialSendRetriesTruncatedTCPUDPResponseOverTCP|DialSendDoesNotRetryTruncatedPureUDPResponseOverTCP|DialSendUsesRequestContext)$' -count=1 -v`
- Broader DNS control-path coverage:
  - `PATH=/usr/lib/go-1.23/bin:$PATH GOTOOLCHAIN=go1.24.3 GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn /usr/lib/go-1.23/bin/go test ./control -run 'Test(ParseEndpoint|AddrPortFromNetAddr|HandleWithResponseWriterRejectsAsIsForLocalListener|DNSForwarderReusable|ShouldReportDnsDialFailure|LookupDnsRespCacheRemovesExpiredEntry|DnsDataWithZeroIDDoesNotMutateInput|LookupDnsRespCacheUsesPackedResponse|SweepDnsCacheUsesLatestDeadline|UpdateDnsCacheEvictsOldestWhenCacheFull|SweepDnsForwarderCacheRemovesIdleEntries|GetDnsForwarderEvictsOldestWhenCacheFull|ReleaseDnsForwarderRemovesFailedReusableEntry|SweepDnsForwarderCacheKeepsInUseEntry|DialSendUsesRequestContext|DialSendRetriesTruncatedTCPUDPResponseOverTCP|DialSendDoesNotRetryTruncatedPureUDPResponseOverTCP)$' -count=1 -v`
- Upstream resolver regression check:
  - `PATH=/usr/lib/go-1.23/bin:$PATH GOTOOLCHAIN=go1.24.3 GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn /usr/lib/go-1.23/bin/go test ./component/dns -run 'Test(UpstreamResolverUsesCacheBeforeRefresh|UpstreamResolverRefreshesAfterInterval|UpstreamResolverKeepsPreviousUpstreamOnRefreshFailure|UpstreamResolverDeduplicatesConcurrentRefresh)$' -count=1 -v`
- Drift check:
  - `git diff --check`

Validation result:

- All targeted and broader DNS-related local tests above passed in this pass.
- `git diff --check` passed.

Follow-up items still open after this pass:

- make `CacheStats()` side-effect free or align its cleanup behavior with `cacheRemoveCallback`
- strengthen DoH HTTP status / content-type handling
- refine TTL / negative-cache semantics
- add DNS path observability counters

## 2026-05-03 Implementation Pass: make `CacheStats()` side-effect free

Branch:

- `bpf0.21.0`

Goal:

- implement item 2 from the 2026-05-03 follow-up review
- stop runtime stats collection from mutating DNS cache state
- keep expired-entry cleanup semantics centralized in the normal DNS cache cleanup paths instead of silently deleting entries during stats reads

Files changed:

- `control/dns_control.go`
- `control/dns_control_test.go`

Implementation summary:

- Changed `DnsController.CacheStats()` to become a pure observation path for DNS cache entries:
  - it now acquires `dnsCacheMu` with `RLock`
  - it counts only entries whose effective expiry (`cacheExpiresAt`) is still valid
  - it no longer deletes expired entries while computing stats
- Left actual expired-entry removal responsibility with the existing mutation paths:
  - background sweep
  - lookup-time expiry cleanup
  - explicit removal/update paths
- Kept DNS forwarder cache stats behavior unchanged in this pass:
  - the function still reports the current cached forwarder entry count
  - no new forwarder cleanup behavior was added here

Why this shape:

- The earlier implementation made a read-like runtime stats path mutate DNS controller state.
- That was undesirable on its own, and it also bypassed the normal `cacheRemoveCallback` cleanup semantics that help keep kernel-side domain routing state aligned.
- Making `CacheStats()` pure is cleaner than teaching this read path to perform full cleanup side effects.
- Counting only live DNS cache entries still keeps the stats output useful without turning stats collection into an implicit maintenance operation.

Tests added:

- `TestCacheStatsCountsOnlyLiveDnsEntriesWithoutMutation`
  - verifies `CacheStats()` counts only currently live DNS cache entries
  - verifies it uses the latest effective expiry semantics (`cacheExpiresAt`)
  - verifies it does not invoke `cacheRemoveCallback`
  - verifies it does not delete expired entries from the cache map

Validation:

- Formatting:
  - `/usr/lib/go-1.23/bin/gofmt -w /root/project/dae/control/dns_control.go /root/project/dae/control/dns_control_test.go`
- Focused regression:
  - `PATH=/usr/lib/go-1.23/bin:$PATH GOTOOLCHAIN=go1.24.3 GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn /usr/lib/go-1.23/bin/go test ./control -run 'Test(CacheStatsCountsOnlyLiveDnsEntriesWithoutMutation|SweepDnsCacheUsesLatestDeadline|LookupDnsRespCacheRemovesExpiredEntry|DialSendRetriesTruncatedTCPUDPResponseOverTCP|DialSendDoesNotRetryTruncatedPureUDPResponseOverTCP)$' -count=1 -v`
- Broader DNS control-path coverage:
  - `PATH=/usr/lib/go-1.23/bin:$PATH GOTOOLCHAIN=go1.24.3 GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn /usr/lib/go-1.23/bin/go test ./control -run 'Test(ParseEndpoint|AddrPortFromNetAddr|HandleWithResponseWriterRejectsAsIsForLocalListener|DNSForwarderReusable|ShouldReportDnsDialFailure|LookupDnsRespCacheRemovesExpiredEntry|DnsDataWithZeroIDDoesNotMutateInput|LookupDnsRespCacheUsesPackedResponse|SweepDnsCacheUsesLatestDeadline|CacheStatsCountsOnlyLiveDnsEntriesWithoutMutation|UpdateDnsCacheEvictsOldestWhenCacheFull|SweepDnsForwarderCacheRemovesIdleEntries|GetDnsForwarderEvictsOldestWhenCacheFull|ReleaseDnsForwarderRemovesFailedReusableEntry|SweepDnsForwarderCacheKeepsInUseEntry|DialSendUsesRequestContext|DialSendRetriesTruncatedTCPUDPResponseOverTCP|DialSendDoesNotRetryTruncatedPureUDPResponseOverTCP)$' -count=1 -v`
- Upstream resolver regression check:
  - `PATH=/usr/lib/go-1.23/bin:$PATH GOTOOLCHAIN=go1.24.3 GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn /usr/lib/go-1.23/bin/go test ./component/dns -run 'Test(UpstreamResolverUsesCacheBeforeRefresh|UpstreamResolverRefreshesAfterInterval|UpstreamResolverKeepsPreviousUpstreamOnRefreshFailure|UpstreamResolverDeduplicatesConcurrentRefresh)$' -count=1 -v`
- Drift check:
  - `git diff --check`

Validation result:

- All focused and broader DNS-related local tests above passed in this pass.
- `git diff --check` passed.

Net effect after this pass:

- runtime stats no longer act as an implicit DNS cache cleanup path
- effective DNS cache counts shown by stats still exclude expired entries
- expired-entry cleanup remains concentrated in the existing explicit DNS cache maintenance paths

Follow-up items still open after this pass:

- strengthen DoH HTTP status / content-type handling
- refine TTL / negative-cache semantics
- add DNS path observability counters

## 2026-05-03 Implementation Pass: strengthen DoH request/response handling

Branch:

- `bpf0.21.0`

Goal:

- implement item 3 from the 2026-05-03 follow-up review
- improve DoH transport robustness and diagnostics
- avoid depending on GET-only request encoding for larger DNS payloads

Files changed:

- `control/dns.go`
- `control/dns_http_test.go`

Implementation summary:

- Split DoH request construction and response validation into small helpers:
  - `buildDoHRequest`
  - `validateDoHResponse`
- Added payload-aware DoH method selection:
  - small encoded queries still use GET
  - larger encoded queries switch to POST automatically
- Added a conservative encoded-query threshold:
  - `doHGetMaxEncodedQueryBytes = 1024`
  - once the base64url-encoded `dns=` payload grows past that size, the request uses POST
- Kept the existing DNS ID-zeroing behavior for DoH cache friendliness in both GET and POST paths.
- Strengthened response validation before DNS unpack:
  - require HTTP `200 OK`
  - if `Content-Type` is present, parse it with `mime.ParseMediaType`
  - accept `application/dns-message`
  - accept `application/dns-message` with parameters
  - reject invalid or obviously wrong media types such as `text/html`
- Kept handling intentionally compatible in one area:
  - if a DoH server omits `Content-Type` entirely, the response is still allowed and the DNS payload is unpacked as before
  - this keeps the change diagnostic-focused without unnecessarily breaking looser servers in this pass

Why this shape:

- The previous DoH path always used GET and trusted the response body without checking HTTP-level signals first.
- That made large queries less robust and made HTML error pages or proxy responses fail later as generic DNS unpack errors.
- Moving request construction and response validation into helpers keeps the transport logic readable and makes future DoH work easier to extend.

Tests added:

- `TestBuildDoHRequestUsesGetForSmallPayload`
- `TestBuildDoHRequestUsesPostForLargePayload`
- `TestSendHttpDNSRejectsNonOKStatus`
- `TestSendHttpDNSRejectsUnexpectedContentType`
- `TestSendHttpDNSAcceptsContentTypeWithParameters`
- `TestSendHttpDNSUsesPostFallbackForLargePayload`
- `TestValidateDoHResponseRejectsInvalidContentTypeHeader`
- `TestBuildDoHRequestPreservesTargetPathEscaping`

Validation:

- Formatting:
  - `/usr/lib/go-1.23/bin/gofmt -w /root/project/dae/control/dns.go /root/project/dae/control/dns_http_test.go`
- Focused DoH regression:
  - `PATH=/usr/lib/go-1.23/bin:$PATH GOTOOLCHAIN=go1.24.3 GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn /usr/lib/go-1.23/bin/go test ./control -run 'Test(BuildDoHRequestUsesGetForSmallPayload|BuildDoHRequestUsesPostForLargePayload|SendHttpDNSRejectsNonOKStatus|SendHttpDNSRejectsUnexpectedContentType|SendHttpDNSAcceptsContentTypeWithParameters|SendHttpDNSUsesPostFallbackForLargePayload|ValidateDoHResponseRejectsInvalidContentTypeHeader|BuildDoHRequestPreservesTargetPathEscaping)$' -count=1 -v`
- Broader DNS control-path coverage:
  - `PATH=/usr/lib/go-1.23/bin:$PATH GOTOOLCHAIN=go1.24.3 GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn /usr/lib/go-1.23/bin/go test ./control -run 'Test(ParseEndpoint|AddrPortFromNetAddr|HandleWithResponseWriterRejectsAsIsForLocalListener|DNSForwarderReusable|ShouldReportDnsDialFailure|LookupDnsRespCacheRemovesExpiredEntry|DnsDataWithZeroIDDoesNotMutateInput|LookupDnsRespCacheUsesPackedResponse|SweepDnsCacheUsesLatestDeadline|CacheStatsCountsOnlyLiveDnsEntriesWithoutMutation|UpdateDnsCacheEvictsOldestWhenCacheFull|SweepDnsForwarderCacheRemovesIdleEntries|GetDnsForwarderEvictsOldestWhenCacheFull|ReleaseDnsForwarderRemovesFailedReusableEntry|SweepDnsForwarderCacheKeepsInUseEntry|DialSendUsesRequestContext|DialSendRetriesTruncatedTCPUDPResponseOverTCP|DialSendDoesNotRetryTruncatedPureUDPResponseOverTCP|BuildDoHRequestUsesGetForSmallPayload|BuildDoHRequestUsesPostForLargePayload|SendHttpDNSRejectsNonOKStatus|SendHttpDNSRejectsUnexpectedContentType|SendHttpDNSAcceptsContentTypeWithParameters|SendHttpDNSUsesPostFallbackForLargePayload|ValidateDoHResponseRejectsInvalidContentTypeHeader|BuildDoHRequestPreservesTargetPathEscaping)$' -count=1 -v`
- Upstream resolver regression check:
  - `PATH=/usr/lib/go-1.23/bin:$PATH GOTOOLCHAIN=go1.24.3 GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn /usr/lib/go-1.23/bin/go test ./component/dns -run 'Test(UpstreamResolverUsesCacheBeforeRefresh|UpstreamResolverRefreshesAfterInterval|UpstreamResolverKeepsPreviousUpstreamOnRefreshFailure|UpstreamResolverDeduplicatesConcurrentRefresh)$' -count=1 -v`
- Drift check:
  - `git diff --check`

Validation result:

- All focused DoH tests above passed.
- The broader DNS-related local test set also passed after the DoH changes.
- `git diff --check` passed.

Net effect after this pass:

- DoH now fails earlier and more clearly on HTTP-layer errors.
- Large DoH queries no longer depend on GET-only encoding.
- Wrong or malformed DoH `Content-Type` values are rejected before DNS unpack.

Follow-up items still open after this pass:

- refine TTL / negative-cache semantics
- add DNS path observability counters

## 2026-05-03 Implementation Pass: refine TTL and empty-success cache semantics

Branch:

- `bpf0.21.0`

Goal:

- implement item 4 from the 2026-05-03 follow-up review
- stop using first-answer TTL only
- stop assigning a blanket synthetic cache TTL to successful empty-answer responses
- make explicit-deadline cache entries keep their explicit lifetime without being distorted by `fixed_domain_ttl`

Files changed:

- `control/dns_control.go`
- `control/dns_control_test.go`

Implementation summary:

- Replaced first-answer TTL selection with minimum-answer TTL selection:
  - added `minDNSAnswerTTL`
  - cache lifetime for a successful answered response now uses the minimum TTL found across the response answers
- Removed the old blanket successful-empty-answer cache behavior:
  - the previous path assigned a synthetic TTL and cached empty `NOERROR` responses
  - the new path treats `NOERROR` with no answers as non-cacheable by default
- Clarified explicit-deadline cache semantics:
  - `UpdateDnsCacheDeadline` now behaves as a true explicit-deadline path
  - it no longer consults `fixed_domain_ttl`
  - this preserves the intended lifetime for manually seeded cache entries such as upstream-host routing support entries
- Kept normal upstream-response fixed TTL override behavior unchanged:
  - `UpdateDnsCacheTtl` still applies `fixed_domain_ttl` to regular TTL-based cache updates
  - `OriginalDeadline` continues to preserve the upstream-derived lifetime
- Switched `__updateDnsCacheDeadline` to use the controller clock (`c.now`) instead of calling `time.Now()` directly:
  - this keeps the cache-update path more consistent with the rest of the controller
  - it also makes the TTL behavior easier to test precisely

Why this shape:

- Using only the first answer TTL was unnecessarily coarse when mixed-TTL answers were present.
- The blanket synthetic cache TTL for empty successful answers was too aggressive and too implicit; it could retain “no data” results longer than intended without strong protocol evidence.
- `UpdateDnsCacheDeadline` is currently used for explicit cache lifetime injection, especially the long-lived upstream-host bootstrap entries. Those entries should keep their explicitly supplied deadline rather than being silently rewritten by `fixed_domain_ttl`.

Tests added:

- `TestNormalizeAndCacheDnsRespUsesMinimumAnswerTTL`
- `TestNormalizeAndCacheDnsRespSkipsEmptySuccess`
- `TestUpdateDnsCacheTtlAppliesFixedDomainTTL`
- `TestUpdateDnsCacheDeadlineIgnoresFixedDomainTTL`

Validation:

- Formatting:
  - `/usr/lib/go-1.23/bin/gofmt -w /root/project/dae/control/dns_control.go /root/project/dae/control/dns_control_test.go`
- Focused TTL/empty-success regression:
  - `PATH=/usr/lib/go-1.23/bin:$PATH GOTOOLCHAIN=go1.24.3 GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn /usr/lib/go-1.23/bin/go test ./control -run 'Test(NormalizeAndCacheDnsRespUsesMinimumAnswerTTL|NormalizeAndCacheDnsRespSkipsEmptySuccess|UpdateDnsCacheTtlAppliesFixedDomainTTL|UpdateDnsCacheDeadlineIgnoresFixedDomainTTL|CacheStatsCountsOnlyLiveDnsEntriesWithoutMutation|DialSendRetriesTruncatedTCPUDPResponseOverTCP|BuildDoHRequestUsesPostForLargePayload)$' -count=1 -v`
- Broader DNS control-path coverage:
  - `PATH=/usr/lib/go-1.23/bin:$PATH GOTOOLCHAIN=go1.24.3 GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn /usr/lib/go-1.23/bin/go test ./control -run 'Test(ParseEndpoint|AddrPortFromNetAddr|HandleWithResponseWriterRejectsAsIsForLocalListener|DNSForwarderReusable|ShouldReportDnsDialFailure|LookupDnsRespCacheRemovesExpiredEntry|DnsDataWithZeroIDDoesNotMutateInput|LookupDnsRespCacheUsesPackedResponse|SweepDnsCacheUsesLatestDeadline|CacheStatsCountsOnlyLiveDnsEntriesWithoutMutation|NormalizeAndCacheDnsRespUsesMinimumAnswerTTL|NormalizeAndCacheDnsRespSkipsEmptySuccess|UpdateDnsCacheTtlAppliesFixedDomainTTL|UpdateDnsCacheDeadlineIgnoresFixedDomainTTL|UpdateDnsCacheEvictsOldestWhenCacheFull|SweepDnsForwarderCacheRemovesIdleEntries|GetDnsForwarderEvictsOldestWhenCacheFull|ReleaseDnsForwarderRemovesFailedReusableEntry|SweepDnsForwarderCacheKeepsInUseEntry|DialSendUsesRequestContext|DialSendRetriesTruncatedTCPUDPResponseOverTCP|DialSendDoesNotRetryTruncatedPureUDPResponseOverTCP|BuildDoHRequestUsesGetForSmallPayload|BuildDoHRequestUsesPostForLargePayload|SendHttpDNSRejectsNonOKStatus|SendHttpDNSRejectsUnexpectedContentType|SendHttpDNSAcceptsContentTypeWithParameters|SendHttpDNSUsesPostFallbackForLargePayload|ValidateDoHResponseRejectsInvalidContentTypeHeader|BuildDoHRequestPreservesTargetPathEscaping)$' -count=1 -v`
- Upstream resolver regression check:
  - `PATH=/usr/lib/go-1.23/bin:$PATH GOTOOLCHAIN=go1.24.3 GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn /usr/lib/go-1.23/bin/go test ./component/dns -run 'Test(UpstreamResolverUsesCacheBeforeRefresh|UpstreamResolverRefreshesAfterInterval|UpstreamResolverKeepsPreviousUpstreamOnRefreshFailure|UpstreamResolverDeduplicatesConcurrentRefresh)$' -count=1 -v`
- Drift check:
  - `git diff --check`

Validation result:

- All focused TTL/empty-success tests above passed.
- The broader DNS-related local test set also passed after the TTL/cache changes.
- `git diff --check` passed.

Net effect after this pass:

- successful answered DNS responses now honor the minimum answer TTL
- successful empty-answer responses are no longer cached by default
- explicit-deadline cache entries keep their explicit deadline
- `fixed_domain_ttl` remains effective for normal TTL-based cache updates

Follow-up items still open after this pass:

- add DNS path observability counters

## 2026-05-03 Implementation Pass: add DNS path observability counters

Branch:

- `bpf0.21.0`

Goal:

- implement item 5 from the 2026-05-03 follow-up review
- expose lightweight DNS-path health counters without changing the existing DNS routing behavior
- cover both control-path events and upstream-refresh events in one stats surface

Files changed:

- `control/dns_metrics.go`
- `control/control_plane.go`
- `control/dns.go`
- `control/dns_control.go`
- `control/dns_control_test.go`
- `control/dns_http_test.go`
- `component/dns/upstream_stats.go`
- `component/dns/upstream.go`
- `component/dns/upstream_test.go`

Implementation summary:

- Added a small process-wide DNS observability snapshot for control-path counters:
  - `DnsObservabilityStats`
  - `snapshotDnsObservabilityStats()`
- Extended `ControlPlane.CacheStats()` to include these additive DNS totals alongside the existing cache-entry counts:
  - this keeps the new observability surface close to the current runtime cache stats path
  - no existing DNS cache counting semantics were changed in this pass
- Added control-path counters for:
  - DNS cache hits
  - DNS cache expired-entry removals
  - UDP retry attempts
  - `TC=1` UDP-to-TCP fallback attempts for `tcp+udp` upstreams
  - DoH HTTP-status validation failures
  - DoH `Content-Type` validation failures
- Wired the counters into the actual state-transition points instead of logging-only paths:
  - `LookupDnsRespCache` records successful live-cache hits
  - `LookupDnsRespCache` records expired-entry removals when lookup-time expiry cleanup happens
  - `sweepDnsCache` records expired-entry removals from background cleanup
  - `evictDnsCacheEntriesLocked` records expired-entry removals when a cache update opportunistically clears stale entries
  - `DoUDP.ForwardDNS` records each real retry before the next UDP attempt
  - `dialSend` records each truncated-response fallback attempt before retrying over TCP
  - `validateDoHResponse` records status/content-type failures before returning the validation error
- Added a separate upstream-refresh counter snapshot in `component/dns`:
  - refresh success total
  - refresh failure total
  - stale-upstream reuse total
- Wired `UpstreamResolver.GetUpstream()` to record:
  - success when a new upstream resolve + callback cycle completes
  - failure when resolve or finish-init callback fails
  - stale reuse when an existing upstream is kept after a refresh failure

Why this shape:

- The observability request was about health counters, not a new metrics subsystem.
- A small additive snapshot is enough to answer the operational questions raised in the review:
  - are we serving from cache?
  - are stale entries being cleaned?
  - are UDP retries or `TC -> TCP` fallbacks happening?
  - are DoH responses failing at HTTP validation?
  - are upstream refreshes succeeding or falling back to stale data?
- Keeping the counters close to the state-mutation points makes the counts more trustworthy than trying to infer them later from logs or cache length snapshots.
- Splitting upstream-refresh counters into `component/dns` avoids forcing extra control-plane plumbing through the resolver construction path.

Tests added / expanded:

- `TestLookupDnsRespCacheTracksHitAndExpiredRemovalCounters`
- `TestDoUDPForwardDNSTracksRetryCounter`
- `TestDialSendRetriesTruncatedTCPUDPResponseOverTCP`
  - expanded to assert the truncated-fallback counter
- `TestDialSendDoesNotRetryTruncatedPureUDPResponseOverTCP`
  - expanded to assert the fallback counter stays unchanged
- `TestSendHttpDNSRejectsNonOKStatus`
  - expanded to assert the DoH status-failure counter
- `TestSendHttpDNSRejectsUnexpectedContentType`
  - expanded to assert the DoH content-type-failure counter
- `TestUpstreamResolverKeepsPreviousUpstreamOnRefreshFailure`
  - expanded to assert refresh success/failure/stale-reuse counters

Validation:

- Formatting:
  - `/usr/lib/go-1.23/bin/gofmt -w /root/project/dae/control/dns_metrics.go /root/project/dae/control/dns.go /root/project/dae/control/dns_control.go /root/project/dae/control/control_plane.go /root/project/dae/control/dns_control_test.go /root/project/dae/control/dns_http_test.go /root/project/dae/component/dns/upstream.go /root/project/dae/component/dns/upstream_stats.go /root/project/dae/component/dns/upstream_test.go`
- Focused observability regression:
  - `PATH=/usr/lib/go-1.23/bin:$PATH GOTOOLCHAIN=go1.24.3 GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn /usr/lib/go-1.23/bin/go test ./control -run 'Test(LookupDnsRespCacheTracksHitAndExpiredRemovalCounters|DoUDPForwardDNSTracksRetryCounter|DialSendRetriesTruncatedTCPUDPResponseOverTCP|DialSendDoesNotRetryTruncatedPureUDPResponseOverTCP|SendHttpDNSRejectsNonOKStatus|SendHttpDNSRejectsUnexpectedContentType)$' -count=1 -v`
- Upstream refresh observability regression:
  - `PATH=/usr/lib/go-1.23/bin:$PATH GOTOOLCHAIN=go1.24.3 GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn /usr/lib/go-1.23/bin/go test ./component/dns -run 'Test(UpstreamResolverUsesCacheBeforeRefresh|UpstreamResolverRefreshesAfterInterval|UpstreamResolverKeepsPreviousUpstreamOnRefreshFailure|UpstreamResolverDeduplicatesConcurrentRefresh)$' -count=1 -v`
- Broader DNS control-path coverage:
  - `PATH=/usr/lib/go-1.23/bin:$PATH GOTOOLCHAIN=go1.24.3 GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn /usr/lib/go-1.23/bin/go test ./control -run 'Test(ParseEndpoint|AddrPortFromNetAddr|HandleWithResponseWriterRejectsAsIsForLocalListener|DNSForwarderReusable|ShouldReportDnsDialFailure|LookupDnsRespCacheRemovesExpiredEntry|LookupDnsRespCacheTracksHitAndExpiredRemovalCounters|DnsDataWithZeroIDDoesNotMutateInput|LookupDnsRespCacheUsesPackedResponse|SweepDnsCacheUsesLatestDeadline|CacheStatsCountsOnlyLiveDnsEntriesWithoutMutation|NormalizeAndCacheDnsRespUsesMinimumAnswerTTL|NormalizeAndCacheDnsRespSkipsEmptySuccess|UpdateDnsCacheTtlAppliesFixedDomainTTL|UpdateDnsCacheDeadlineIgnoresFixedDomainTTL|UpdateDnsCacheEvictsOldestWhenCacheFull|SweepDnsForwarderCacheRemovesIdleEntries|GetDnsForwarderEvictsOldestWhenCacheFull|ReleaseDnsForwarderRemovesFailedReusableEntry|SweepDnsForwarderCacheKeepsInUseEntry|DoUDPForwardDNSTracksRetryCounter|DialSendUsesRequestContext|DialSendRetriesTruncatedTCPUDPResponseOverTCP|DialSendDoesNotRetryTruncatedPureUDPResponseOverTCP|BuildDoHRequestUsesGetForSmallPayload|BuildDoHRequestUsesPostForLargePayload|SendHttpDNSRejectsNonOKStatus|SendHttpDNSRejectsUnexpectedContentType|SendHttpDNSAcceptsContentTypeWithParameters|SendHttpDNSUsesPostFallbackForLargePayload|ValidateDoHResponseRejectsInvalidContentTypeHeader|BuildDoHRequestPreservesTargetPathEscaping)$' -count=1 -v`
- Drift check:
  - `git diff --check`

Validation result:

- The focused observability tests passed.
- The upstream resolver regression set passed with the new refresh counters enabled.
- The broader DNS control regression set passed with the new counters in place.
- `git diff --check` passed.

Net effect after this pass:

- DNS cache stats now have companion health counters instead of only entry counts.
- The DNS path can now answer whether retries, truncated fallbacks, or DoH validation failures are actually happening.
- Upstream refresh behavior now exposes whether the resolver is progressing normally or repeatedly falling back to stale upstreams.

Follow-up items still open after this pass:

- consider stricter DNS response identity validation before caching/serving, especially for mismatch/debug scenarios noted in the 2026-05-03 review

## 2026-05-03 Implementation Pass: validate upstream response identity before routing/caching

Branch:

- `bpf0.21.0`

Goal:

- implement the remaining response-identity hardening item from the 2026-05-03 follow-up review
- reject mismatched upstream DNS responses before they participate in response routing, cache normalization, or client reply assembly

Files changed:

- `control/dns_control.go`
- `control/dns_control_test.go`

Implementation summary:

- Added explicit response/request identity validation helpers:
  - `canonicalDnsQuestionName`
  - `dnsQuestionsEqual`
  - `formatDnsQuestion`
  - `validateDnsResponseForRequest`
- `dialSend` now unpacks the outgoing DNS request once at the send boundary and validates each upstream response against that request before doing anything else with the response.
- The validation currently enforces:
  - upstream response must be non-nil
  - upstream response must actually be a DNS response (`Response=true`)
  - if the request carried questions, the response must also carry questions
  - response question count must match request question count
  - each response question must match the corresponding request question after canonicalized-name comparison, with exact qtype/qclass matching
- Validation is applied to both:
  - the initial upstream response
  - the second response returned after `TC=1` `udp -> tcp` fallback for `tcp+udp` upstreams
- On validation failure:
  - response routing is skipped
  - DNS cache normalization is skipped
  - the mismatched response is not sent back to the client

Why this shape:

- Before this pass, a malformed or mismatched upstream response could still enter response routing and then be considered for cache/store/send paths.
- The review goal here was not general protocol normalization; it was to place a hard guard at the upstream receive boundary.
- Doing the check inside `dialSend` is the narrowest useful place:
  - it covers all upstream transport implementations uniformly
  - it runs before response routing and cache mutation
  - it rechecks the TCP retry path too, instead of trusting fallback responses implicitly

Tests added:

- `TestValidateDnsResponseForRequest`
  - accepts canonical-name-equivalent matching questions
  - rejects missing response question sections
  - rejects mismatched response questions
- `TestDialSendRejectsMismatchedResponseQuestion`
  - verifies a mismatched upstream response is rejected on the real `dialSend` path
  - verifies no DNS cache entry is created from the bad response

Validation:

- Formatting:
  - `/usr/lib/go-1.23/bin/gofmt -w /root/project/dae/control/dns_control.go /root/project/dae/control/dns_control_test.go`
- Focused identity-validation regression:
  - `PATH=/usr/lib/go-1.23/bin:$PATH GOTOOLCHAIN=go1.24.3 GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn /usr/lib/go-1.23/bin/go test ./control -run 'Test(ValidateDnsResponseForRequest|DialSendRejectsMismatchedResponseQuestion|DialSendRetriesTruncatedTCPUDPResponseOverTCP|DialSendDoesNotRetryTruncatedPureUDPResponseOverTCP|NormalizeAndCacheDnsRespUsesMinimumAnswerTTL|LookupDnsRespCacheTracksHitAndExpiredRemovalCounters)$' -count=1 -v`
- Broader DNS control-path coverage:
  - `PATH=/usr/lib/go-1.23/bin:$PATH GOTOOLCHAIN=go1.24.3 GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn /usr/lib/go-1.23/bin/go test ./control -run 'Test(ParseEndpoint|AddrPortFromNetAddr|HandleWithResponseWriterRejectsAsIsForLocalListener|DNSForwarderReusable|ShouldReportDnsDialFailure|LookupDnsRespCacheRemovesExpiredEntry|LookupDnsRespCacheTracksHitAndExpiredRemovalCounters|DnsDataWithZeroIDDoesNotMutateInput|LookupDnsRespCacheUsesPackedResponse|SweepDnsCacheUsesLatestDeadline|CacheStatsCountsOnlyLiveDnsEntriesWithoutMutation|NormalizeAndCacheDnsRespUsesMinimumAnswerTTL|NormalizeAndCacheDnsRespSkipsEmptySuccess|ValidateDnsResponseForRequest|UpdateDnsCacheTtlAppliesFixedDomainTTL|UpdateDnsCacheDeadlineIgnoresFixedDomainTTL|UpdateDnsCacheEvictsOldestWhenCacheFull|SweepDnsForwarderCacheRemovesIdleEntries|GetDnsForwarderEvictsOldestWhenCacheFull|ReleaseDnsForwarderRemovesFailedReusableEntry|SweepDnsForwarderCacheKeepsInUseEntry|DoUDPForwardDNSTracksRetryCounter|DialSendUsesRequestContext|DialSendRetriesTruncatedTCPUDPResponseOverTCP|DialSendDoesNotRetryTruncatedPureUDPResponseOverTCP|DialSendRejectsMismatchedResponseQuestion|BuildDoHRequestUsesGetForSmallPayload|BuildDoHRequestUsesPostForLargePayload|SendHttpDNSRejectsNonOKStatus|SendHttpDNSRejectsUnexpectedContentType|SendHttpDNSAcceptsContentTypeWithParameters|SendHttpDNSUsesPostFallbackForLargePayload|ValidateDoHResponseRejectsInvalidContentTypeHeader|BuildDoHRequestPreservesTargetPathEscaping)$' -count=1 -v`
- Drift check:
  - `git diff --check`

Validation result:

- Focused response-identity validation tests passed.
- The broader DNS control regression set still passed with the new guard in place.
- `git diff --check` passed.

Net effect after this pass:

- Wrong-question DNS responses now stop at the upstream receive boundary instead of flowing into route/cache/send logic.
- The earlier transport fallback and cache-semantics changes continue to work under the stricter validation.

Follow-up items still open after this pass:

- decide whether DNS observability counters should also be surfaced through the main runtime overview/API path instead of only the cache-stats surface
- evaluate whether transport-specific response ID validation is worth adding for transports that preserve request IDs (`udp`/`tcp`/`tls`)

## 2026-05-03 Implementation Pass: surface DNS observability counters through runtime overview

Branch:

- `bpf0.21.0`

Goal:

- complete the remaining observability follow-up from the previous pass
- make the DNS health counters visible through the main runtime overview path, not only through `ControlPlane.CacheStats()`

Files changed:

- `control/runtime_stats.go`
- `control/runtime_stats_test.go`
- `engine/runtime.go`
- `engine/runtime_test.go`

Implementation summary:

- Extended `control.RuntimeStatsSnapshot` to include `DnsObservabilityStats`.
- Added a small hook variable in `control/runtime_stats.go`:
  - `runtimeStatsDnsObservabilitySnapshot = snapshotDnsObservabilityStats`
  - this keeps the production path simple while making the new field testable without mutating global live counters
- `SnapshotRuntimeStats(...)` now attaches the current DNS observability snapshot before returning the runtime stats payload.
- Extended `engine.RuntimeOverview` to also include `DnsObservabilityStats`.
- Added a small `engine`-level seam:
  - `snapshotRuntimeStats = control.SnapshotRuntimeStats`
  - this allows a tight unit test that verifies runtime overview does not drop the new DNS fields while staying decoupled from the control package’s internal globals
- `Engine.GetRuntimeOverview(...)` now simply forwards the DNS observability fields from `control.RuntimeStatsSnapshot` into `engine.RuntimeOverview`.

Why this shape:

- The previous pass already had the right DNS counters, but they only surfaced on the cache-stats side.
- The main runtime overview is the more natural place for “is DNS healthy right now?” style signals because it already aggregates other live operational stats.
- This pass intentionally kept the implementation additive:
  - no new API shape was invented
  - no existing runtime overview fields changed meaning
  - the DNS counters are simply carried through the existing overview object
- The test seams are deliberately narrow and local. They avoid needing unstable global counter resets just to verify field plumbing.

Tests added:

- `TestSnapshotRuntimeStatsIncludesDnsObservabilityStats`
  - verifies `SnapshotRuntimeStats` includes the DNS observability payload
- `TestGetRuntimeOverviewIncludesDnsObservabilityStats`
  - verifies `Engine.GetRuntimeOverview` preserves the DNS observability payload in the overview returned to callers

Validation:

- Formatting:
  - `/usr/lib/go-1.23/bin/gofmt -w /root/project/dae/control/runtime_stats.go /root/project/dae/control/runtime_stats_test.go /root/project/dae/engine/runtime.go /root/project/dae/engine/runtime_test.go`
- Focused runtime-overview regression:
  - `PATH=/usr/lib/go-1.23/bin:$PATH GOTOOLCHAIN=go1.24.3 GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn /usr/lib/go-1.23/bin/go test ./control -run 'Test(RuntimeStatsSnapshotAggregatesAcrossShards|RuntimeStatsSnapshotIncludesRecordsFromMultipleBuckets|SnapshotRuntimeStatsIncludesDnsObservabilityStats)$' -count=1 -v`
  - `PATH=/usr/lib/go-1.23/bin:$PATH GOTOOLCHAIN=go1.24.3 GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn /usr/lib/go-1.23/bin/go test ./engine -run 'TestGetRuntimeOverviewIncludesDnsObservabilityStats$' -count=1 -v`
- Broader DNS + runtime stats coverage:
  - `PATH=/usr/lib/go-1.23/bin:$PATH GOTOOLCHAIN=go1.24.3 GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn /usr/lib/go-1.23/bin/go test ./control -run 'Test(ParseEndpoint|AddrPortFromNetAddr|HandleWithResponseWriterRejectsAsIsForLocalListener|DNSForwarderReusable|ShouldReportDnsDialFailure|LookupDnsRespCacheRemovesExpiredEntry|LookupDnsRespCacheTracksHitAndExpiredRemovalCounters|DnsDataWithZeroIDDoesNotMutateInput|LookupDnsRespCacheUsesPackedResponse|SweepDnsCacheUsesLatestDeadline|CacheStatsCountsOnlyLiveDnsEntriesWithoutMutation|NormalizeAndCacheDnsRespUsesMinimumAnswerTTL|NormalizeAndCacheDnsRespSkipsEmptySuccess|ValidateDnsResponseForRequest|UpdateDnsCacheTtlAppliesFixedDomainTTL|UpdateDnsCacheDeadlineIgnoresFixedDomainTTL|UpdateDnsCacheEvictsOldestWhenCacheFull|SweepDnsForwarderCacheRemovesIdleEntries|GetDnsForwarderEvictsOldestWhenCacheFull|ReleaseDnsForwarderRemovesFailedReusableEntry|SweepDnsForwarderCacheKeepsInUseEntry|DoUDPForwardDNSTracksRetryCounter|DialSendUsesRequestContext|DialSendRetriesTruncatedTCPUDPResponseOverTCP|DialSendDoesNotRetryTruncatedPureUDPResponseOverTCP|DialSendRejectsMismatchedResponseQuestion|BuildDoHRequestUsesGetForSmallPayload|BuildDoHRequestUsesPostForLargePayload|SendHttpDNSRejectsNonOKStatus|SendHttpDNSRejectsUnexpectedContentType|SendHttpDNSAcceptsContentTypeWithParameters|SendHttpDNSUsesPostFallbackForLargePayload|ValidateDoHResponseRejectsInvalidContentTypeHeader|BuildDoHRequestPreservesTargetPathEscaping|RuntimeStatsSnapshotAggregatesAcrossShards|RuntimeStatsSnapshotIncludesRecordsFromMultipleBuckets|SnapshotRuntimeStatsIncludesDnsObservabilityStats)$' -count=1 -v`
- Drift check:
  - `git diff --check`

Validation result:

- Focused runtime-stats and runtime-overview tests passed.
- The broader DNS control regression set still passed with the runtime overview wiring in place.
- `git diff --check` passed.

Net effect after this pass:

- DNS observability counters now flow through both:
  - `ControlPlane.CacheStats()`
  - the main runtime overview path returned by `Engine.GetRuntimeOverview(...)`
- Consumers of the normal runtime overview no longer need a separate cache-stats read just to understand DNS retry/fallback/refresh behavior.

Follow-up items still open after this pass:

- evaluate whether transport-specific response ID validation is worth adding for transports that preserve request IDs (`udp`/`tcp`/`tls`)

## 2026-05-03 Implementation Pass: validate response IDs for ID-preserving DNS transports

Branch:

- `bpf0.21.0`

Goal:

- complete the remaining response-validation follow-up from the previous pass
- reject upstream responses with mismatched DNS IDs on transports that preserve request IDs
- keep DoH/DoQ-style zero-ID behavior intact for transports that intentionally rewrite IDs for cache-friendliness

Files changed:

- `control/dns_control.go`
- `control/dns_control_test.go`

Implementation summary:

- Extended `validateDnsResponseForRequest` with an explicit `requireMatchingID` flag.
- Added `shouldValidateDnsResponseID` to gate ID validation only for transports where request IDs are expected to round-trip unchanged:
  - `udp`
  - `tcp`
  - `tcp+udp`
  - `tls`
- `dialSend` now applies question validation and, when appropriate, response-ID validation:
  - on the first upstream response
  - on the fallback TCP response after a truncated `tcp+udp` UDP reply
- The resulting behavior is now transport-aware:
  - plain UDP/TCP/TLS DNS responses must match both question identity and DNS ID
  - DoH/HTTP3/DoQ-style transports are still allowed to return zeroed IDs, because those transports intentionally zero request IDs in this codebase

Why this shape:

- Question validation alone closes the larger correctness hole, but on ID-preserving transports it still leaves a smaller ambiguity window: a response can match the question but still belong to a different outstanding exchange.
- The transport-specific gate keeps the stricter check where it is protocol-correct, while avoiding false positives on DoH/DoQ/H3 where the request ID is deliberately rewritten for cache-friendliness.
- Reusing the same `dialSend` boundary preserves the earlier design goal: bad upstream responses stop before route/cache/send logic.

Tests added / expanded:

- `TestValidateDnsResponseForRequest`
  - expanded to reject mismatched IDs when ID validation is required
  - expanded to allow mismatched IDs when ID validation is intentionally disabled
- `TestDialSendRejectsMismatchedResponseIDForUdpUpstream`
  - verifies a plain UDP upstream response with the wrong ID is rejected
  - verifies no DNS cache entry is created from that bad response
- `TestDialSendAllowsZeroResponseIDForDoH`
  - verifies DoH-style zero-ID responses remain accepted and cacheable

Validation:

- Formatting:
  - `/usr/lib/go-1.23/bin/gofmt -w /root/project/dae/control/dns_control.go /root/project/dae/control/dns_control_test.go`
- Focused transport-ID regression:
  - `PATH=/usr/lib/go-1.23/bin:$PATH GOTOOLCHAIN=go1.24.3 GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn /usr/lib/go-1.23/bin/go test ./control -run 'Test(ValidateDnsResponseForRequest|DialSendRejectsMismatchedResponseQuestion|DialSendRejectsMismatchedResponseIDForUdpUpstream|DialSendAllowsZeroResponseIDForDoH|DialSendRetriesTruncatedTCPUDPResponseOverTCP|DialSendDoesNotRetryTruncatedPureUDPResponseOverTCP)$' -count=1 -v`
- Broader DNS + runtime stats coverage:
  - `PATH=/usr/lib/go-1.23/bin:$PATH GOTOOLCHAIN=go1.24.3 GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn /usr/lib/go-1.23/bin/go test ./control -run 'Test(ParseEndpoint|AddrPortFromNetAddr|HandleWithResponseWriterRejectsAsIsForLocalListener|DNSForwarderReusable|ShouldReportDnsDialFailure|LookupDnsRespCacheRemovesExpiredEntry|LookupDnsRespCacheTracksHitAndExpiredRemovalCounters|DnsDataWithZeroIDDoesNotMutateInput|LookupDnsRespCacheUsesPackedResponse|SweepDnsCacheUsesLatestDeadline|CacheStatsCountsOnlyLiveDnsEntriesWithoutMutation|NormalizeAndCacheDnsRespUsesMinimumAnswerTTL|NormalizeAndCacheDnsRespSkipsEmptySuccess|ValidateDnsResponseForRequest|UpdateDnsCacheTtlAppliesFixedDomainTTL|UpdateDnsCacheDeadlineIgnoresFixedDomainTTL|UpdateDnsCacheEvictsOldestWhenCacheFull|SweepDnsForwarderCacheRemovesIdleEntries|GetDnsForwarderEvictsOldestWhenCacheFull|ReleaseDnsForwarderRemovesFailedReusableEntry|SweepDnsForwarderCacheKeepsInUseEntry|DoUDPForwardDNSTracksRetryCounter|DialSendUsesRequestContext|DialSendRetriesTruncatedTCPUDPResponseOverTCP|DialSendDoesNotRetryTruncatedPureUDPResponseOverTCP|DialSendRejectsMismatchedResponseQuestion|DialSendRejectsMismatchedResponseIDForUdpUpstream|DialSendAllowsZeroResponseIDForDoH|BuildDoHRequestUsesGetForSmallPayload|BuildDoHRequestUsesPostForLargePayload|SendHttpDNSRejectsNonOKStatus|SendHttpDNSRejectsUnexpectedContentType|SendHttpDNSAcceptsContentTypeWithParameters|SendHttpDNSUsesPostFallbackForLargePayload|ValidateDoHResponseRejectsInvalidContentTypeHeader|BuildDoHRequestPreservesTargetPathEscaping|RuntimeStatsSnapshotAggregatesAcrossShards|RuntimeStatsSnapshotIncludesRecordsFromMultipleBuckets|SnapshotRuntimeStatsIncludesDnsObservabilityStats)$' -count=1 -v`
- Runtime overview regression:
  - `PATH=/usr/lib/go-1.23/bin:$PATH GOTOOLCHAIN=go1.24.3 GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn /usr/lib/go-1.23/bin/go test ./engine -run 'TestGetRuntimeOverviewIncludesDnsObservabilityStats$' -count=1 -v`
- Drift check:
  - `git diff --check`

Validation result:

- Focused transport-ID validation tests passed.
- The broader DNS control regression set passed with the new ID validation in place.
- The runtime overview regression still passed after the DNS-path tightening.
- `git diff --check` passed.

Net effect after this pass:

- ID-preserving DNS transports now require both:
  - matching request/response question identity
  - matching request/response DNS ID
- ID-rewriting transports such as DoH remain compatible with the existing zero-ID behavior.

Follow-up items still open after this pass:

- no immediate DNS hardening items remain from the 2026-05-03 review; the next work should come from new runtime evidence or new protocol-specific findings
