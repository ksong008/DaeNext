# UDP Optimization Memo

Date: 2026-04-19
Branch: `personal/stable`

## Goal

This memo records the current UDP-path review under the constraints:

- stable
- fast
- no memory leaks / no unbounded long-running growth

The purpose is to keep a running engineering note for future UDP optimization work, similar to the DNS memo.

## Current Assessment

UDP is now the highest-value area to review after the DNS line became more stable.

Compared with DNS, UDP naturally has higher risk for:

- high-cardinality sessions
- large numbers of timers
- large numbers of goroutines
- short-lived object churn
- resource growth driven by traffic shape rather than configuration

At the moment, no single obvious “must-fix-now” leak has been confirmed in the UDP path, but several subsystems are structurally prone to long-running growth pressure and deserve focused lifecycle review.

## Main UDP Data Path

Relevant entry:

- `control/udp.go`

Main flow:

1. receive packet from TProxy UDP listener
2. recover original destination / routing result
3. optional DNS handling
4. optional packet sniffing
5. obtain or create UDP endpoint
6. forward packet upstream
7. relay response back through anyfrom listener

## High-Priority Review Areas

### 1. `UdpEndpointPool`

File:

- `control/udp_endpoint_pool.go`

Why it matters:

- one endpoint per source tuple
- one goroutine per endpoint (`ue.start()`)
- one timer per endpoint (`time.AfterFunc`)
- endpoint objects carry outbound / dialer / timeout / handler state

Risk profile:

- endpoint cardinality can grow with active UDP sources
- timer count scales with endpoint count
- goroutine count scales with endpoint count
- removal and timeout logic interacts with network read loop

Questions to answer in follow-up work:

- Is the NAT timeout too generous for typical workloads?
- Can endpoint lifecycle be made cheaper than one goroutine + one timer per endpoint?
- Is there any double-close / stale timer / stale pool entry race?
- Do we need explicit upper bounds or adaptive cleanup?

### 2. `UdpTaskPool`

File:

- `control/udp_task_pool.go`

Why it matters:

- one queue per task key
- one goroutine per queue
- one timer per queue
- lifetime tied to packet ordering guarantees

Risk profile:

- key cardinality can grow under wide fan-out traffic
- queue goroutines may become expensive under bursty workloads
- aging timer strategy may keep queues around longer than necessary

Questions to answer in follow-up work:

- Can ordering guarantees be preserved with a lighter structure?
- Can queue aging be made cheaper?
- Is queue reuse good enough under churn-heavy traffic?

### 3. `AnyfromPool`

File:

- `control/anyfrom_pool.go`

Why it matters:

- maps `lAddr` to listening UDP socket
- holds TTL timer per entry
- creates actual sockets via `ListenPacket`

Risk profile:

- high cardinality of `lAddr` can increase listener count
- timer-per-entry cost exists here as well
- listener creation is comparatively expensive

Questions to answer in follow-up work:

- Is the TTL appropriate?
- Is the map likely to grow under real workloads?
- Can refresh/eviction be done with lower timer overhead?

### 4. `PacketSnifferPool`

File:

- `control/packet_sniffer_pool.go`

Why it matters:

- stores per-key packet sniffer sessions
- uses `sync.Map`
- uses `createMuMap`
- uses per-entry TTL timers

Risk profile:

- more bookkeeping than the structure likely needs
- contains visible `FIXME` paths
- creates short-lived objects during sniffing-heavy traffic

Questions to answer in follow-up work:

- Can this be simplified?
- Are timers and create locks overbuilt for the real use case?
- Can we reduce object churn here?

## Things That Already Look Reasonable

### DNS bypass on UDP path

- DNS is already split off into its own controller path early enough.
- This reduces unnecessary mixing of packet-forwarding concerns and DNS concerns.

### Retry cap

- UDP upstream endpoint recreation in `control/udp.go` is bounded by `MaxRetry`.
- This prevents pathological endless recreation loops on repeated write failure.

### Pool abstractions exist

- Even though they may need tuning, UDP already uses explicit pooling / lifecycle containers rather than uncontrolled ad hoc allocations.

## Likely Next Optimization Order

Recommended priority:

1. `UdpEndpointPool`
2. `UdpTaskPool`
3. `AnyfromPool`
4. `PacketSnifferPool`

This order is chosen because:

- `UdpEndpointPool` sits closest to the main forwarding path and combines timer + goroutine + session growth risk.
- `UdpTaskPool` can amplify resource usage under high key cardinality.
- `AnyfromPool` and `PacketSnifferPool` matter too, but are slightly more peripheral than endpoint lifecycle.

## Suggested Optimization Principles

For all UDP work, keep the following rules:

- Avoid adding new functional surface area unless it directly improves stability/performance/memory bounds.
- Prefer bounded-resource designs over feature-rich designs.
- Minimize goroutines and per-entry timers where possible.
- Keep hot-path synchronization simple and cheap.
- Prefer deterministic cleanup and explicit lifecycle ownership.

## Applied Changes

### A. `UdpEndpointPool` lifecycle simplification

Files:

- `control/udp_endpoint_pool.go`
- `control/udp_endpoint_pool_test.go`

Changes:

- Removed per-endpoint `time.AfterFunc` usage.
- Added pool-level cleanup janitor with periodic sweep.
- Moved endpoint expiry to `lastActive + NatTimeout` checks.
- Added explicit `Touch(now)` and `Expired(now)` helpers on endpoints.
- Added idempotent endpoint close path via `sync.Once`.
- Added `onInactive` callback so read loop termination can remove stale endpoints from the pool.
- Added `UdpEndpointPool.Close()` to stop janitor and close remaining endpoints.

Why this helps:

- significantly fewer timers under large UDP endpoint cardinality
- simpler endpoint lifecycle ownership
- clearer long-running memory / timer growth bounds

Tests added:

- sweep removes expired endpoints
- inactive callback removes and closes endpoint
- pool close closes and removes remaining endpoints

### B. `UdpTaskPool` lifecycle simplification

Files:

- `control/udp_task_pool.go`
- `control/udp_task_pool_test.go`

Changes:

- Removed per-queue `time.AfterFunc` usage.
- Added pool-level cleanup janitor with periodic sweep.
- Added explicit queue activity tracking:
  - `lastActive`
  - `running`
- Added `UdpTaskPool.Close()` to stop cleanup and terminate queues.
- Kept per-key serialization semantics while reducing timer overhead.

Why this helps:

- fewer timers under high key cardinality
- better separation between “queue ordering” and “queue expiration”
- more predictable lifecycle management for long-running queues

Tests added:

- same-key tasks run in order
- idle queues are swept
- running queues are not swept prematurely

### C. `AnyfromPool` lifecycle simplification

Files:

- `control/anyfrom_pool.go`
- `control/anyfrom_pool_test.go`

Changes:

- Removed per-entry `time.AfterFunc` usage.
- Added pool-level cleanup janitor with periodic sweep.
- Added explicit `lastActive` tracking.
- Added `Expired(now)` and `Touch(now)` helpers.
- Added idempotent close path.
- Added `AnyfromPool.Close()` to stop cleanup and close pooled listeners.

Why this helps:

- fewer timers under high listener cardinality
- more predictable lifetime management for pooled UDP listeners
- better control over long-running map growth

Tests added:

- expired entries are swept
- fresh entries remain
- touch/refresh updates activity
- pool close closes all entries

### D. `PacketSnifferPool` lifecycle simplification

Files:

- `control/packet_sniffer_pool.go`
- `control/packet_sniffer_pool_test.go`

Changes:

- Removed per-entry `time.AfterFunc` usage.
- Added pool-level cleanup janitor with periodic sweep.
- Added explicit `lastActive` tracking.
- Added `Touch(now)` and `Expired(now)` helpers.
- Added idempotent close path.
- Added `PacketSnifferPool.Close()` to stop cleanup and close remaining sniffers.

Why this helps:

- fewer timers under sniffing-heavy traffic
- simpler packet sniffer lifecycle
- lower long-running bookkeeping overhead

Tests added:

- expired sniffers are swept
- fresh sniffers remain after touch

### E. Outbound stability PR follow-up

PR:

- `#1 stabilize outbound dialer checks and selection`

Files involved:

- `component/outbound/dialer/alive_dialer_set.go`
- `component/outbound/dialer/connectivity_check.go`
- `component/outbound/dialer/dialer.go`
- `component/outbound/dialer/latencies_n.go`
- `component/outbound/dialer_group.go`
- `component/outbound/dialer_group_test.go`
- `go.mod`

Review summary:

- The overall direction was reasonable and aligned with the post-UDP stabilization goals:
  - cleaner health-check lifecycle
  - safer dialer reselection
  - lower allocation overhead
  - no new user-facing behavior
- A concrete build blocker was found during review:
  - an unused import in `component/outbound/dialer/connectivity_check.go`
- After removing that import, Linux-targeted package compilation for outbound-related packages was able to proceed again.
- The branch also needed the corresponding `go.sum` entries for the forked `github.com/ksong008/outbound` replacement.

Follow-up changes applied before merge:

- Removed the unused import in `component/outbound/dialer/connectivity_check.go`.
- Added the missing `go.sum` entries for the forked outbound dependency.
- Re-pushed the PR branch after the fix.

Merge result:

- The PR branch was merged into `personal/stable`.
- Merge tip:
  - `a7a96d1` `Fix outbound stability PR build blockers`

Tag:

- `outboundmod`

## Current Conclusion

Short version:

- UDP is the next most important subsystem after DNS.
- No confirmed major leak has been proven yet.
- The design has several structures that can become expensive under scale.
- The first UDP lifecycle pass is done, and the next adjacent stabilization work has already extended into outbound health-check and selection logic.
- Follow-up work should focus on lifecycle cost and upper bounds, not on adding new features.

## Next Step

Recommended immediate next step:

- Keep UDP and outbound behavior under real traffic observation instead of expanding the design surface.

If follow-up work is needed, prefer:

- validating long-running memory behavior under real workload
- checking whether outbound health-check changes introduce any selection regressions
- only then making small, targeted stability fixes
