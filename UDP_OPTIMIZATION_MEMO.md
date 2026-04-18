# UDP Optimization Memo

Date: 2026-04-19
Branch: `personal/test-dns`

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

## Current Conclusion

Short version:

- UDP is the next most important subsystem after DNS.
- No confirmed major leak has been proven yet.
- The design has several structures that can become expensive under scale.
- Follow-up work should focus on lifecycle cost and upper bounds, not on adding new features.

## Next Step

Recommended immediate next step:

- Perform a dedicated lifecycle audit and optimization pass on `UdpEndpointPool`

Once that is complete, continue to:

- `UdpTaskPool`
- `AnyfromPool`
- `PacketSnifferPool`
