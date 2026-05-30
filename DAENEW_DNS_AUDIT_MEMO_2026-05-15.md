# daenew DNS Audit Memo

Date: 2026-05-15
Branch: daenew
Scope: DNS workflow, request/response routing, cache behavior, and dial_mode behavior for ip/domain/domain+/domain++.

## Current Workspace

- Repository: `/root/project/dae`
- Branch state when audited: `daenew...origin/daenew`
- Existing dirty state before this memo: untracked `rust/`
- This memo started as audit-only. It now also tracks local reproduce/fix/validation work for DNS functional defects.

## High-Level DNS Flow

1. DNS requests enter `DnsController.HandleWithResponseWriter_` or `Handle_`.
2. `dns.routing.request` selects `reject`, `asis`, or a configured upstream.
3. Cache lookup uses `canonical qname + qtype` as the cache key.
4. Cache miss is forwarded through the selected upstream. Supported upstream schemes include `udp`, `tcp`, `tcp+udp`, `tls`, `https`, `h3`/`http3`, and `quic`.
5. DNS responses pass through `dns.routing.response`, which can `accept`, `reject`, or resend through another upstream.
6. Accepted/rejected successful responses are normalized and cached.
7. A/AAAA answers update the DNS cache and the domain routing map so kernel routing can match `domain(...)` rules by destination IP.

Key source paths:

- `component/dns/dns.go`
- `component/dns/request_routing.go`
- `component/dns/response_routing.go`
- `component/dns/upstream.go`
- `control/dns_control.go`
- `control/dns_cache.go`
- `control/dns.go`
- `control/control_plane.go`
- `control/domain_routing_tracker.go`
- `control/kern/tproxy.c`

## dial_mode Behavior

### ip

- Sniffing timeout is forced to zero.
- Normal traffic dials the destination IP.
- DNS requests can still be intercepted, cached, and used to update domain routing maps.
- Domain rewrite is not used for outbound dial target.

### domain

- Intended behavior in docs: use sniffed domain as dial target for proxied traffic, but do not reroute based on sniffed domain.
- Current implementation:
  - If DNS cache proves the sniffed domain is real, use the domain as dial target.
  - If cache miss, `ResolveIp46` actively resolves the sniffed domain.
  - If active resolve succeeds, code sets `shouldReroute = true`, which causes userspace rerouting.
- This creates a behavior mismatch with the documented "does not impact routing" wording.

### domain+

- Skips the active "is this a real domain" check.
- Uses sniffed domain as dial target for proxied non-reserved outbound traffic.
- Does not force rerouting.
- If DNS traffic does not pass through dae, normal `domain(...)` rules still cannot rely on DNS cache.

### domain++

- Based on `domain+`.
- Forces rerouting with the sniffed domain for non-reserved outbound traffic.
- Does not work for direct/block/reserved paths, which matches the documented limitation.

## Findings

## Functional Defect Fix Worklog

Policy for this pass:

1. Add or run a focused local test that reproduces the defect before changing runtime logic.
2. Record the failing command and symptom in this memo.
3. Apply the smallest code change that fixes the defect.
4. Re-run the focused test and record the result.
5. Move to the next defect only after the current one has a recorded verification result.

Priority order for functional defects:

| Priority | Finding | Status | Reason |
| --- | --- | --- | --- |
| P0 | Synthetic domain verification can use `asis` and query the original traffic target as DNS | Fixed locally | Highest correctness and leakage risk. |
| P1 | `fixed_domain_ttl: 0` can still serve client DNS responses from cache until upstream TTL | Fixed locally | Clear documentation mismatch and stale-answer risk. |
| P2 | `domain` mode reroutes after active resolve on cache miss | Fixed locally | Clear docs mismatch, but behavior may have compatibility implications. |
| P3 | Bare IPv6 in `ip(...)` rules defaults to `/32` instead of `/128` | Fixed locally | Local parser bug with contained blast radius. |
| P4 | Transparent TCP/53 is treated as ordinary TCP traffic | Expected behavior / document boundary | Clients may intentionally use external TCP DNS; DNS controller TCP support is provided through `dns.bind`, not transparent TCP interception. |

Environment setup:

- System Go is too old for this workspace (`go1.19.8`).
- Cached Go toolchain used for tests: `/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.linux-amd64/bin/go`.
- `control/kern/headers` and `trace/kern/headers` submodules were initialized locally.
- bpf2go artifacts were generated with:

```sh
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.linux-amd64/bin:$PATH GOWORK=off make ebpf
```

The generated bpf2go artifacts are required for focused `control` package tests in this checkout.

Per-defect validation log:

### P0 synthetic `asis` lookup

Reproduction test added:

- `control/dns_control_test.go`: `TestResolveIp46SyntheticLookupRejectsAsIsOriginalTarget`

Failing command before fix:

```sh
/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.linux-amd64/bin/go test ./control -run TestResolveIp46SyntheticLookupRejectsAsIsOriginalTarget -count=1
```

Observed failure before fix:

```text
expected synthetic asis lookup to stay unverified, got ip4=1.1.1.1 ip6=2001:db8::1
```

Interpretation:

- The synthetic `ResolveIp46` path can currently resolve through `dns.routing.request fallback: asis`.
- In that path, `dialSend` materializes `asis` from `req.realDst`, which is the original traffic destination rather than a DNS server.
- This confirms the high-severity leakage/correctness finding.

Fix applied:

- Added a `udpRequest.disallowAsIs` guard for synthetic resolver calls.
- `ResolveIp46` marks its internal A/AAAA lookups with `disallowAsIs = true`.
- `handleWithResponseWriter_` now rejects `asis` only when that guard is set.
- Normal transparent DNS `asis` behavior is unchanged.

Passing command after fix:

```sh
/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.linux-amd64/bin/go test ./control -run TestResolveIp46SyntheticLookupRejectsAsIsOriginalTarget -count=1
```

Result:

```text
ok  	github.com/daeuniverse/dae/control	0.003s
```

### P1 `fixed_domain_ttl: 0` client cache semantics

Reproduction test added:

- `control/dns_control_test.go`: `TestFixedDomainTTLZeroDisablesClientResponseCache`

Failing command before fix:

```sh
/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.linux-amd64/bin/go test ./control -run TestFixedDomainTTLZeroDisablesClientResponseCache -count=1
```

Observed failure before fix:

```text
expected fixed_domain_ttl: 0 to disable client response cache
```

Interpretation:

- `UpdateDnsCacheTtl` stores `Deadline = now` and `OriginalDeadline = now + upstream TTL`.
- `LookupDnsRespCache(cacheKey, false)` should honor `Deadline` for client-visible response cache, but currently falls back to `cacheExpiresAt`, sees `OriginalDeadline`, and returns the stale client response.
- The cache entry should be allowed to remain internally for domain-routing association, but it must not be served to DNS clients after `Deadline`.

Fix applied:

- Added `cacheLookupDeadline` to make client-visible and internal lookup deadlines explicit.
- `LookupDnsRespCache(cacheKey, false)` now returns cache entries only while `Deadline` is valid.
- If `Deadline` is expired but `cacheExpiresAt` is still valid, the entry is retained internally and returned as a miss to the client lookup path.
- `LookupDnsRespCache(cacheKey, true)` can still use `OriginalDeadline` for internal domain verification/routing association checks.

Passing command after fix:

```sh
/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.linux-amd64/bin/go test ./control -run TestFixedDomainTTLZeroDisablesClientResponseCache -count=1
```

Result:

```text
ok  	github.com/daeuniverse/dae/control	0.003s
```

### P2 `domain` mode active resolve reroute

Reproduction test added:

- `control/control_plane_test.go`: `TestChooseDialTargetDomainModeDoesNotRerouteAfterActiveResolve`

Failing command before fix:

```sh
/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.linux-amd64/bin/go test ./control -run TestChooseDialTargetDomainModeDoesNotRerouteAfterActiveResolve -count=1
```

Observed failure before fix:

```text
shouldReroute = true, want false for dial_mode domain
```

Interpretation:

- Documentation says `dial_mode: domain` rewrites the proxy dial target after routing and does not affect routing.
- Current cache-miss active resolve path confirms the sniffed domain is real, then sets `shouldReroute = true`.
- This makes `domain` behave partly like `domain++` and can change group selection unexpectedly.

Fix applied:

- Active resolve in `dial_mode: domain` still verifies that the sniffed domain has A/AAAA records.
- Verified domains are still used as proxy dial targets.
- The positive real-domain cache now records `shouldReroute = false`.
- Forced rerouting remains reserved for `dial_mode: domain++`.

Passing command after fix:

```sh
/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.linux-amd64/bin/go test ./control -run TestChooseDialTargetDomainModeDoesNotRerouteAfterActiveResolve -count=1
```

Result:

```text
ok  	github.com/daeuniverse/dae/control	0.003s
```

### P3 bare IPv6 prefix parsing

Reproduction test added:

- `component/routing/function_parser_test.go`: `TestParsePrefixesUsesHostPrefixForBareAddresses`

Failing command before fix:

```sh
/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.linux-amd64/bin/go test ./component/routing -run TestParsePrefixesUsesHostPrefixForBareAddresses -count=1
```

Observed failure before fix:

```text
prefixes[1] = 2001:db8::1/32, want 2001:db8::1/128
```

Interpretation:

- `parsePrefixes` appends `/32` to every bare address.
- That is correct for bare IPv4 host addresses.
- For bare IPv6 host addresses it broadens the match to a `/32` IPv6 prefix instead of a single host.

Fix applied:

- `parsePrefixes` now parses bare values as `netip.Addr` first.
- Bare IPv4 addresses become `/32`.
- Bare IPv6 addresses become `/128`.
- Explicit CIDR input remains unchanged.

Passing command after fix:

```sh
/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.linux-amd64/bin/go test ./component/routing -run TestParsePrefixesUsesHostPrefixForBareAddresses -count=1
```

Result:

```text
ok  	github.com/daeuniverse/dae/component/routing	0.002s
```

Final local regression after P0-P3 fixes:

```sh
/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.linux-amd64/bin/go test ./component/dns ./component/routing -count=1
/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.linux-amd64/bin/go test ./control -run 'Test(ResolveIp46SyntheticLookupRejectsAsIsOriginalTarget|FixedDomainTTLZeroDisablesClientResponseCache|ChooseDialTargetDomainModeDoesNotRerouteAfterActiveResolve|LookupDnsRespCache|UpdateDnsCacheTtlAppliesFixedDomainTTL|UpdateDnsCacheDeadlineIgnoresFixedDomainTTL|HandleWithResponseWriterRejectsAsIsForLocalListener)' -count=1
/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.linux-amd64/bin/go test ./control -count=1
```

Result:

```text
ok  	github.com/daeuniverse/dae/component/dns	0.002s
ok  	github.com/daeuniverse/dae/component/routing	0.002s
ok  	github.com/daeuniverse/dae/control	0.004s
ok  	github.com/daeuniverse/dae/control	6.494s
```

Design boundary confirmed:

- P4 transparent TCP/53 DNS interception is not a correctness bug in the current model.
- Transparent TCP/53 enters dae's ordinary TCP proxy/routing path, but is not parsed by the DNS controller.
- If a client intentionally connects to `8.8.8.8:53/tcp`, dae should not silently convert that flow into a dae-managed DNS query.
- TCP DNS enters the DNS controller when the client explicitly uses `dns.bind` with a TCP-capable listener, for example `tcp+udp://0.0.0.0:53`.
- `dns.upstream` values such as `tcp+udp://8.8.8.8:53` control how dae contacts upstream DNS after a request has entered the DNS controller; they do not imply transparent TCP/53 interception.
- A future transparent TCP DNS parser would be an opt-in feature requiring separate framing, stream, and policy design, not a bug fix.

### 1. Synthetic domain verification can accidentally query the original target as DNS

Severity: high

In `domain` mode, when a sniffed domain has no DNS cache entry, `ChooseDialTarget` calls `ResolveIp46`. That synthetic lookup reuses `req.realDst = dst`, where `dst` is the original traffic target.

If `dns.routing.request` resolves to `asis`, `dialSend` constructs a DNS upstream from `req.realDst`. In this synthetic path, that means dae may send DNS packets to the original website IP and port, for example an HTTPS server on port 443.

Impact:

- Extra connection latency on first access.
- Potential DNS leakage or unexpected UDP/TCP traffic to application targets.
- Active domain verification may fail for reasons unrelated to the domain itself.

Suggested fix:

- Disallow `asis` for synthetic resolver calls from `ResolveIp46`.
- Prefer `global.fallback_resolver` or another explicit resolver for synthetic checks.
- If no explicit resolver is available, treat the sniffed domain as unverified instead of sending DNS to the original destination.

### 2. fixed_domain_ttl: 0 does not fully match the documented no-cache behavior

Severity: medium-high

Docs say a fixed TTL of zero means dae should query upstream every time and not cache DNS results for that domain.

Current code stores both:

- `Deadline`: affected by `fixed_domain_ttl`
- `OriginalDeadline`: upstream original TTL

But cache expiry uses the later of the two deadlines. Therefore when `fixed_domain_ttl` is zero, the cached response can still remain usable until the upstream TTL expires.

Impact:

- `fixed_domain_ttl: 0` does not force every query to upstream.
- DDNS or fast-changing domains may keep stale answers longer than configured.

Suggested fix:

- Separate client DNS response cache from internal domain-routing retention.
- For normal DNS response lookup, honor `Deadline` only.
- If internal routing map needs to retain until `OriginalDeadline`, keep that as a separate internal retention path and do not serve it to clients.

### 3. domain mode currently reroutes in some cache-miss cases

Severity: medium

Documentation says `domain` changes the dial target after routing and does not reroute. Current code sets `shouldReroute = true` after active `ResolveIp46` succeeds.

Impact:

- `domain` and `domain++` are less distinct than documented.
- Users may see domain-based policy changes in `domain` mode when they expect only dial-target rewrite.

Suggested fix:

- Decide the intended behavior.
- If reroute is intentional, update docs and comments.
- If old semantics are intended, remove `shouldReroute = true` from the `domain` active-resolve success path.

### 4. Bare IPv6 in ip(...) rules defaults to /32 instead of /128

Severity: medium

`parsePrefixes` appends `/32` whenever the value has no explicit slash. This is correct for IPv4 host addresses but wrong for IPv6 host addresses.

Impact:

- `ip(2001:db8::1)` matches `2001:db8::/32`, not only `2001:db8::1/128`.
- This affects DNS response routing `ip(...)` pollution checks and general routing `ip(...)` rules.

Suggested fix:

- Parse bare values with `netip.ParseAddr` first.
- If IPv4, use `/32`.
- If IPv6, use `/128`.
- Keep explicit CIDR behavior unchanged.

### 5. Transparent TCP/53 is an ordinary TCP flow, not a DNS controller input

Severity: none; design boundary

Transparent UDP traffic to port 53 enters `DnsController`. TCP DNS over port 53 does not go through the DNS controller in the transparent path. TCP DNS is only covered when using `dns.bind` local listener with TCP enabled.

Expected behavior:

- Clients intentionally using external TCP DNS, such as `8.8.8.8:53/tcp`, are routed as ordinary TCP traffic.
- These flows do not populate DNS cache or domain routing maps because dae is not acting as the DNS server for them.
- Domain-based routing for later connections may depend on sniffing or `domain++` if DNS did not enter dae.

Documented boundary:

- `dns.bind: tcp+udp://...` is the supported way to make TCP DNS enter the DNS controller.
- `dns.upstream: tcp+udp://...` is still meaningful, but it only controls dae-to-upstream DNS transport after a DNS request has already entered the controller.
- Transparent TCP DNS interception should only be considered as a separate opt-in feature.

## Cache Notes

- DNS cache max entries: 4096.
- DNS forwarder cache max entries: 128.
- Forwarder cache is only reused for DoH over TCP and DoQ/H3 over UDP.
- Empty successful DNS responses are intentionally not cached.
- A/AAAA answers are normalized to TTL 0 before returning to clients, while dae keeps internal cache by upstream TTL or fixed TTL.
- Domain routing ownership is tracked by cache key so one IP shared by multiple domains can merge bitmaps and remove one owner without deleting the other domain's routing bits.

## Local DNS Cache Recommendations

The DNS cache should be treated as two related but separate mechanisms:

1. Client response cache.
2. Internal routing association cache.

The current `DnsCache` carries both responsibilities. That makes simple TTL semantics harder, especially for `fixed_domain_ttl: 0`.

### 1. Split client response cache from routing association cache

Client response cache should answer DNS clients. It must strictly follow the client-visible TTL policy:

- If `fixed_domain_ttl` is not configured, use the upstream response minimum TTL.
- If `fixed_domain_ttl: 10`, the client-visible cache expires after 10 seconds.
- If `fixed_domain_ttl: 0`, do not serve the response from local cache; query upstream each time.

Routing association cache should maintain `IP -> domain rule bitmap` for `domain(...)` routing. Its retention can be based on upstream original TTL or a separate internal cap, but it should not make expired client response cache entries visible again.

Recommended interface split:

- `LookupDnsResponseCache`: returns only client-visible cached responses and honors `Deadline`.
- `LookupDomainRoutingAssociation`: returns internal association state and can honor `OriginalDeadline` or a separate routing deadline.
- Expiry/removal callbacks must update `domain_routing_map` independently from response cache serving.

### 2. Clarify fixed_domain_ttl semantics

The intended user-facing semantics should be:

- `fixed_domain_ttl: 0` means no client response cache.
- `fixed_domain_ttl > 0` means client response cache TTL is exactly that fixed value.
- Internal domain routing retention is separate and should be documented if it remains after response cache expiry.

This directly addresses the audit finding where `Deadline` expires but `OriginalDeadline` can still cause a cache hit through `cacheExpiresAt`.

### 3. Structure cache keys

Current cache keys are string-based and effectively combine canonical qname and qtype. For correctness and future extension, use a typed key internally:

```go
type dnsCacheKey struct {
    Name  string
    Type  uint16
    Class uint16
}
```

If a string key is still needed for snapshot/import/export compatibility, use a stable delimiter format:

```text
example.com.|1|1
```

This avoids ambiguous string concatenation and allows qclass-aware behavior. Most queries are `IN`, but storing qclass explicitly keeps the cache model correct.

### 4. Add negative caching only cautiously

The current behavior skips successful empty-answer caching. That is conservative and acceptable.

If negative caching is added later:

- Cache `NXDOMAIN` using SOA minimum TTL or a small capped TTL.
- Cache `NOERROR` with empty answer only for a short TTL, or keep current no-cache behavior.
- Do not cache `SERVFAIL`, `REFUSED`, timeout, or transport errors except for very short failure suppression.
- Add a separate negative-cache hit metric before enabling it broadly.

The main risk is turning temporary upstream failure into persistent user-visible DNS failure.

### 5. Preserve CNAME semantics for domain routing

For responses like:

```text
foo.example.com CNAME cdn.example.net
cdn.example.net A 1.2.3.4
```

The routing association should at least map `1.2.3.4` to the original query name `foo.example.com`, because user routing rules often target the original domain. The full DNS response should still be preserved for client response cache.

Optional enhancement:

- Also associate final CNAME target bitmap if needed.
- Do not replace the original query name's domain bitmap with only the CNAME target bitmap.

### 6. Keep eviction and owner cleanup coupled

When a response cache entry or routing association owner is evicted:

- Remove the owner from the domain routing tracker.
- Recompute shared-IP merged bitmap.
- Do not delete another domain's bitmap for the same IP.

The existing `domainRoutingTracker` already has the right direction for shared-IP owner tracking; future cache changes should keep that invariant.

### 7. Expose useful cache observability

Useful counters and gauges:

- DNS response cache entries.
- Domain routing association entries.
- DNS forwarder cache entries.
- DNS cache hit count.
- DNS cache expired removal count.
- Upstream refresh success/failure.
- Response routing retry count.
- Negative cache hit count, if negative caching is introduced.

Some of these already exist in `DnsObservabilityStats`; the recommendation is to keep response-cache and routing-association visibility distinct.

### 8. Make reload cache policy explicit

Recommended reload behavior:

- DNS config unchanged: response cache may be restored.
- Routing rules changed: recompute domain bitmap with the new matcher before restoring `domain_routing_map`.
- DNS upstream/request/response routing changed: clear response cache to avoid old upstream policy pollution.
- Group/outbound changed: response cache can usually remain, but routing association should be verified against the new routing matcher state.

The current code already has a partial "restore cached DNS records when DNS config itself is unchanged" model. It should be made explicit and tested.

### 9. Lowest-priority future option: persistent SQLite lazy cache

Priority: lowest. This is a later performance and resilience option, not a prerequisite for fixing current DNS correctness issues.

If DNS lazy cache is implemented with local storage, prefer a SQLite `.db` store over JSON or a simple `.bin` snapshot when the goal is to exceed the current in-memory `4096` entry limit.

Recommended default path:

```text
<config_dir>/cache.d/dns-lazy-cache.db
```

Recommended model:

- Keep the existing in-memory DNS cache as the hot cache.
- Treat SQLite as a larger local lazy-cache store for cold or stale-but-still-usable entries.
- Keep a separate memory entry limit and DB entry/size limits, for example `memory_entries`, `db_entries`, and `db_max_size`.
- Do not make DB storage part of the critical DNS response path; writes should be asynchronous and batched.
- DB write failures should log warnings but must not break DNS resolution.
- Preserve strict semantics for `fixed_domain_ttl: 0`: matching domains must not be served from memory lazy cache or DB lazy cache.

Suggested config shape:

```dae
dns {
    lazy_cache {
        enabled: true
        persist: true
        cache_file: 'cache.d/dns-lazy-cache.db'

        memory_entries: 4096
        db_entries: 100000
        db_max_size: '64MiB'

        stale_ttl: 1h
        refresh_timeout: 2s
        flush_interval: 30s
        serve_stale_on_error: true
    }
}
```

Suggested SQLite schema direction:

```sql
CREATE TABLE dns_cache (
    qname TEXT NOT NULL,
    qtype INTEGER NOT NULL,
    qclass INTEGER NOT NULL DEFAULT 1,
    response_wire BLOB NOT NULL,
    fresh_until INTEGER NOT NULL,
    stale_until INTEGER NOT NULL,
    original_until INTEGER NOT NULL,
    last_access INTEGER NOT NULL,
    hit_count INTEGER NOT NULL DEFAULT 0,
    flags INTEGER NOT NULL DEFAULT 0,
    config_hash BLOB NOT NULL,
    PRIMARY KEY (qname, qtype, qclass)
);
```

Store DNS responses as wire-format blobs with DNS ID normalized to zero, not as JSON-expanded RR structures. The DB should be considered disposable cache state: on version mismatch, invalid `config_hash`, corruption, or expired `stale_until`, entries should be ignored or deleted.

## Initial Audit Validation

Commands attempted:

```sh
go test ./component/dns ./component/routing ./control -run 'Test(NewRejectsDuplicateUpstreamTags|DomainRoutingTracker|UpdateDnsCache|NormalizeAndCache|LookupDnsRespCache|DialSend|ValidateDnsResponse|DNS|Dns|ChooseDialTarget)'
```

Result with system Go:

- Failed before tests because `/root/project/go.work` uses `go 1.24.0` while system Go is `go1.19.8`.

Retried with cached toolchain:

```sh
/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.linux-amd64/bin/go test ./component/dns
```

Result:

- Passed.

Control package attempt with Go 1.25.9:

- Failed at build stage because generated bpf2go types are absent in this checkout:
  - `bpfObjects`
  - `bpfRoutingResult`
  - `bpfMatchSet`

Therefore, this memo is based on static source audit plus successful `component/dns` package tests, not full `control` package test execution.

Update during local fix pass:

- `control/kern/headers` and `trace/kern/headers` were initialized.
- bpf2go artifacts were generated locally with Go 1.25.9 and `GOWORK=off`.
- After that setup, focused `control` tests and full `go test ./control -count=1` passed. See the per-defect validation log above for exact commands and results.

## Recommended Next Steps

Completed in this pass:

1. Fixed synthetic `ResolveIp46` so it cannot use `asis` with the original destination.
2. Split client response cache lookup semantics from internal routing association retention.
3. Fixed `fixed_domain_ttl: 0` client-visible cache behavior.
4. Aligned `dial_mode: domain` active-resolve behavior with the documented no-reroute semantics.
5. Fixed bare IPv6 prefix parsing.
6. Added focused tests for the cache, dial-mode, and prefix parsing items above.
7. Generated local bpf2go artifacts so full `control` tests could run.

Completed follow-up:

1. Structure DNS cache keys with qname, qtype, and qclass.

Remaining follow-up:

1. Clarify the `dns.bind` versus transparent DNS boundary in user documentation.
2. Lowest priority: evaluate persistent SQLite DNS lazy cache after the correctness fixes are complete.

### Follow-up 1 Worklog: Structured DNS Cache Key

Status: fixed locally.

Change summary:

- Replaced the internal DNS response cache map key with a structured key:
  - `qname`
  - `qtype`
  - `qclass`
- Kept the control-plane reload snapshot surface as `map[string]*DnsCache`, but
  changed the new serialized key format to `qname|qtype|qclass`.
- Added compatibility parsing for the old serialized key format, such as
  `example.com.1`, so reload can still restore snapshots produced before this
  change.
- Preserved existing exported cache update helpers as INET-class helpers, while
  response normalization now stores the real DNS question class from the
  upstream response's question.
- Updated packed cache responses to retain the question class instead of always
  creating an INET question.
- Updated domain-routing owner keys to use the structured key's stable string
  form.

Why this is useful:

- Prevents cache collisions between the same domain queried with different DNS
  classes.
- Makes A and AAAA separation explicit in a typed key rather than relying on a
  concatenated string.
- Makes reload restoration less fragile by using a parser instead of manually
  splitting on the last dot.
- Gives the future persistent DNS lazy cache a stable key shape before adding
  disk storage.

Validation:

```sh
GOWORK=off /root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.linux-amd64/bin/go test ./control -run 'TestDnsCacheKeyIncludesQuestionTypeAndClass|TestNormalizeAndCacheDnsRespUsesQuestionClassInCacheKey|TestUpdateDnsCacheDeadlineAssignsRouteOwnerKey' -count=1
GOWORK=off /root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.linux-amd64/bin/go test ./component/dns ./component/routing -count=1
GOWORK=off /root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.linux-amd64/bin/go test ./control -count=1
```

Result:

- Passed.

### Follow-up Validation 1-3 Worklog

Scope requested:

- Validate reload DNS cache policy.
- Validate CNAME semantics for domain-routing association and client response
  cache preservation.
- Validate cache eviction / domain-routing owner cleanup with structured owner
  keys.
- Do not work on observability split or negative caching in this pass.

Validation and local fixes:

1. Reload DNS cache policy
   - Confirmed the engine only snapshots DNS cache for reload when the DNS
     config is unchanged.
   - Extracted the restore path into `restoreDnsCacheSnapshot` so it can be
     unit-tested without starting a full control plane.
   - Validated both old `example.com.1` keys and new
     `example.com.|1|1`-style keys.
   - Validated restored cache entries recompute `DomainBitmap` through the new
     controller's `NewCache` path instead of trusting the old snapshot bitmap.
   - Validated non-INET `qclass` entries restore under their structured key and
     do not collide with INET lookups.

2. CNAME semantics
   - Found that reload restoration should prefer `PackedResponse` when
     available; rebuilding from cached IPs alone can drop the CNAME chain from
     the client-visible cached response.
   - Added `answersForQuestion` so restore can unpack and reuse the full cached
     DNS answer set when the packed response question matches the cache key.
   - Validated restored CNAME cache keeps the original query name's
     `DomainBitmap`, retains the CNAME target A IP for domain routing, and
     still serves a packed response containing both CNAME and target A records.

3. Domain-routing owner cleanup
   - Added a structured-owner test covering the same qname/qtype with different
     qclass values.
   - Validated removing one owner does not remove the other owner's bitmap for
     the same IP.

Validation:

```sh
GOWORK=off /root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.linux-amd64/bin/go test ./control -run 'TestRestoreDnsCacheSnapshotParsesLegacyAndStructuredKeys|TestRestoreDnsCacheSnapshotPreservesPackedCNAMEAndQuestionDomainBitmap|TestDomainRoutingTrackerKeepsStructuredOwnersSeparateOnRemove' -count=1
GOWORK=off /root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.linux-amd64/bin/go test ./component/dns ./component/routing -count=1
GOWORK=off /root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.linux-amd64/bin/go test ./control -count=1
```

Result:

- Passed.

## Deferred Runtime Memory Optimization Backlog

These items are intentionally deferred until the DNS correctness work above is
handled. They are not blockers for the DNS workflow audit, but should be
revisited after the DNS optimization pass and lazy-cache decision.

Priority order for later review:

1. Runtime traffic statistics retention and snapshot allocations.
   - `control/runtime_stats.go` keeps up to one hour of 250 ms buckets across
     16 shards. This is useful for WebUI history, but it creates a steady
     resident cost and the snapshot path temporarily allocates map, bucket, and
     sample slices.
   - Candidate direction: use a fixed ring buffer, downsample older history,
     and aggregate directly to the requested `maxPoints` instead of materializing
     all raw buckets for each overview request.

2. Subscription parsing and control-plane build peak memory.
   - `common/subscription/subscription.go` currently reads each subscription
     into memory, base64/SIP008 parsing materializes full intermediate strings
     or structs, and `engine/runtime.go` stores all subscription results before
     merging them into `tagToNodeList`.
   - Candidate direction: stream base64 line parsing, avoid `strings.Split` on
     the full decoded payload, process subscription results as they arrive, and
     add total-node or total-subscription-size guardrails.

3. Dialer, group, and health-check resident state.
   - Every node creates a `Dialer` with six collections plus probe HTTP state,
     while each non-fixed group creates multiple `AliveDialerSet` maps. Group
     check-option overrides clone dialers, which can multiply state for large
     node and group counts.
   - Candidate direction: lazy-create probe transports and collections, avoid
     full dialer clones for group check overrides, and make `AliveDialerSet`
     storage policy-aware so fixed/random/min-latency modes only allocate the
     state they actually need.

4. Group filter compilation during reload.
   - `component/outbound/filter.go` compiles regexp filters during every
     dialer/filter match, which increases reload-time CPU and temporary
     allocations when there are many nodes and groups.
   - Candidate direction: compile group filters once during config/control-plane
     build and reuse the compiled matcher objects.
   - Local follow-up status: fixed locally. `FilterAndAnnotate` now prepares an
     internal filter representation for each group and lazily compiles each
     regexp at first actual evaluation, then reuses the compiled regexp for the
     rest of that group filtering pass. This keeps the previous short-circuit
     behavior for filters that are never reached while removing per-node regexp
     compilation in normal reload filtering.
   - Added coverage:
     - `TestDialerSetFilterAndAnnotateMatchesCompiledFilters`
     - `TestDialerSetFilterAndAnnotateBadRegex`
     - `TestDialerSetFilterAndAnnotateEmptySetDoesNotCompileFilters`
   - Local validation:
     ```sh
     GOWORK=off /root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.linux-amd64/bin/go test ./component/outbound -run 'TestDialerSetFilterAndAnnotate' -count=1
     GOWORK=off /root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.linux-amd64/bin/go test ./component/outbound -count=1
     GOWORK=off /root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.linux-amd64/bin/go test ./component/outbound ./control -count=1
     GOWORK=off /root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.linux-amd64/bin/go test ./component/outbound -bench BenchmarkDialerSetFilterAndAnnotateRegex -benchmem -run '^$' -count=3
     ```
   - Local benchmark after fix with 1000 synthetic nodes and regexp name/subtag
     filters:
     ```text
     BenchmarkDialerSetFilterAndAnnotateRegex-6  5266  234366 ns/op  148378 B/op  3108 allocs/op
     BenchmarkDialerSetFilterAndAnnotateRegex-6  4800  238997 ns/op  148377 B/op  3108 allocs/op
     BenchmarkDialerSetFilterAndAnnotateRegex-6  5202  239239 ns/op  148378 B/op  3108 allocs/op
     ```

5. UDP task queues under high-cardinality UDP traffic.
   - `control/udp_task_pool.go` can hold up to 2048 per-key queues, each with a
     buffered channel and goroutine.
   - Candidate direction: make the queue count and queue length configurable, or
     replace per-key goroutines with a sharded keyed executor.

6. Packet sniffer burst memory and re-handle copies.
   - `control/packet_sniffer_pool.go` allows up to 1024 packet sniffers, and
     `component/sniffing/sniffer.go` allows up to 64 KiB buffered per sniffer.
     `Sniffer.Data()` deep-copies chunks before UDP re-handling copies them
     again.
   - Candidate direction: make sniffer limits configurable, reduce the default
     burst ceiling if needed, and avoid deep copies by using controlled
     ownership transfer or pooled buffers.

7. DNS cache reload snapshot and domain-routing tracker storage.
   - `ControlPlane.SnapshotDnsCache()` deep-clones cache entries on reload when
     DNS config is unchanged. `domainRoutingTracker` uses maps even for the
     common one-IP or two-IP DNS answer case.
   - Candidate direction: consider immutable/shared packed DNS responses during
     reload, pooled response buffers for cache hits, and a small-array
     representation for owner IP sets before upgrading to maps.

8. Userspace routing matcher hot-path allocations.
   - `MatchDomainBitmap` allocates a bitmap for each domain match, and userspace
     routing creates temporary binary-prefix strings for IP/MAC matching.
   - Candidate direction: add `MatchDomainBitmapInto`, use a small fixed bitmap
     where possible, and avoid string conversion in IP/MAC matching.

Validation to add before making these changes:

- Synthetic subscription parsing benchmark for 10k, 50k, and 100k nodes.
- Control-plane build benchmark for `N` nodes by `M` groups.
- Runtime overview benchmark with one hour of samples and `maxPoints=180`.
- Packet sniffer burst benchmark at the configured pool limit.
- DNS cache reload benchmark with 4096 cached entries.
