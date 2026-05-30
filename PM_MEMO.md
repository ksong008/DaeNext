# PM Memo

## Meta

- Date: 2026-05-14
- Last updated: 2026-05-14
- Branch: `daenew`
- Scope: understand the `daed -> dae-wing -> daenew -> outbound -> quic-go` chain, then identify low-risk, high-return Rust refactor candidates inside `daenew`
- Mode: audit-first, no code changes in this round
- Local-only: yes

## Current Snapshot

- Repo: `/root/project/dae`
- Branch status: `daenew...origin/daenew`
- This PM memo is local-only and excluded through `.git/info/exclude`
- There is an untracked local `rust/` directory in the repo; this memo is analysis-only and does not modify that workspace

## Goal Of This Entry

- First understand the real runtime and control flow instead of judging by directory names
- Then decide which `daenew` surfaces are suitable for Rust replacement
- Prioritize:
  - pure or mostly pure logic
  - CPU-hot or allocation-hot paths
  - narrow ABI / FFI boundary
  - strong existing tests or easy parity fixtures
- Avoid touching:
  - lifecycle-heavy runtime orchestration
  - protocol bodies
  - global kernel / netns / eBPF control flow

## Chain Understanding

### 1. `daed` is the product shell and API client

- Frontend code targets `/api` through a typed client:
  - `daed/apps/web/src/apis/client.ts:28`
- This layer is UI and request transport only; it is not the data plane

### 2. `dae-wing` is the control plane and runtime wrapper

- `daed/wing/engine/engine.go:8` directly aliases `github.com/daeuniverse/dae/engine`
- `daed/wing/cmd/run.go:105` starts the dae runtime through `engine.Default().Run(...)`
- `daed/wing/cmd/run.go:126` exposes `/api/` routes through `httpapi.NewHandler()`
- So `dae-wing` is not re-implementing the proxy runtime; it wraps and orchestrates `dae`

### 3. `/api/runtime/reload` flows into resource assembly, then into dae runtime reload

- Runtime reload API entry:
  - `daed/wing/transport/httpapi/handler.go:153`
  - `daed/wing/transport/httpapi/handler.go:172`
- `orchestrator.Run`:
  - locks runtime lifecycle
  - reads selected `config`, `dns`, `routing` from DB
  - parses them into a dae config model
  - computes referenced outbounds
  - assembles groups and nodes
  - calls `engine.Default().ReloadWithContext(...)`
- Key anchors:
  - `daed/wing/orchestrator/config_run.go:37`
  - `daed/wing/orchestrator/config_run.go:115`
  - `daed/wing/orchestrator/config_run.go:120`
  - `daed/wing/orchestrator/config_run.go:279`

### 4. `daenew` is the actual runtime and data plane

- `dae/engine/runtime.go:152` is the real runtime entry
- `dae/engine/runtime.go:193` creates the first `ControlPlane`
- `dae/engine/runtime.go:677` builds runtime config view, resolves subscriptions, prepares resolver dialers, and constructs the control plane
- `dae/engine/runtime.go:809` calls `control.NewControlPlane(...)`

### 5. `ControlPlane` turns resources into live routing, DNS, and outbound execution

- `dae/control/control_plane.go:365` starts building dialer groups
- `dae/control/control_plane.go:408` creates the outbound dialer set from links
- `dae/control/control_plane.go:497` builds routing matchers
- `dae/control/control_plane.go:504` builds userspace routing matcher
- This is the convergence point where config, nodes, routing, DNS, and runtime dependencies join

### 6. Live traffic path inside `daenew`

#### TCP path

- `dae/control/tcp.go:31` creates a connection sniffer
- `dae/control/tcp.go:35` sniffs target domain
- `dae/control/tcp.go:51` routes and dials through `RouteDialTcp`
- `dae/control/tcp.go:110` selects dial target and decides whether reroute is needed

#### UDP path

- `dae/control/udp.go:78` tries UDP endpoint reuse
- `dae/control/udp.go:109` identifies DNS requests
- `dae/control/udp.go:113` runs QUIC sniffing when suitable
- `dae/control/udp.go:173` sends DNS traffic into `dnsController`
- `dae/control/udp.go:189` continues with outbound dial selection for plain UDP

### 7. `dae` only wires outbound protocol registrations; protocol bodies live in `outbound`

- `dae/component/outbound/outbound.go:8` imports outbound dialers and protocols for registration side effects
- The protocol implementations are not inside `dae`

### 8. `outbound` depends on `quic-go` for QUIC-based protocols

- Module requirement:
  - `outbound/go.mod:9`
- Concrete protocol dependencies:
  - `outbound/protocol/tuic/dialer.go:12`
  - `outbound/protocol/hysteria2/client/client.go:19`
  - `outbound/protocol/hysteria2/client/client.go:20`
  - `outbound/protocol/juicity/client.go:19`

## Rust Refactor Candidates In `daenew`

## Priority 1: domain matcher

- Recommended target:
  - `component/routing/domain_matcher/*`
  - call sites in:
    - `control/routing_matcher_builder.go:357`
    - `component/dns/request_routing.go:132`
    - `component/dns/response_routing.go:181`
- Why this is low risk:
  - pure build-and-match logic
  - no system calls
  - no DB
  - no runtime lifecycle ownership
  - no protocol state machine
- Why this is high return:
  - reused by main routing and DNS routing
  - directly on match path
  - current code allocates a bitmap on each `MatchDomainBitmap(...)`
  - current structure is already a clear algorithm boundary
- Key anchors:
  - `component/routing/domain_matcher/ahocorasick_slimtrie.go:46`
  - `component/routing/domain_matcher/ahocorasick_slimtrie.go:95`
  - `control/routing_matcher_userspace.go:48`
- Rust boundary recommendation:
  - keep Go-side rule optimization and rule-to-matchset planning
  - move pattern ingestion, build, and bitmap matching into Rust
- Validation surface already present:
  - `component/routing/domain_matcher/ahocorasick_slimtrie_test.go`
  - `component/routing/domain_matcher/benchmark_test.go`
- Verdict:
  - best first candidate

## Priority 2: sniffing and QUIC/TLS/HTTP parsing

- Recommended target:
  - `component/sniffing/*`
  - `component/sniffing/internal/quicutils/*`
- Why this is low risk:
  - mostly pure byte parsing and bounded parser state
  - protocol sniffing result is a narrow output: domain / applicability / need-more
  - no control-plane ownership
- Why this is high return:
  - on TCP and UDP hot paths
  - current implementation already cares about buffer pooling and incremental parsing
  - QUIC initial parsing is byte-heavy and correctness-sensitive, which Rust handles well
- Key anchors:
  - `component/sniffing/sniffer.go:26`
  - `component/sniffing/sniffer.go:97`
  - `component/sniffing/sniffer.go:162`
  - `component/sniffing/quic.go:39`
  - `control/tcp.go:31`
  - `control/udp.go:113`
- Important parity notes:
  - do not only compare success cases
  - preserve `ErrNeedMore`, `ErrNotApplicable`, split-frame behavior, and QUIC crypto reassembly semantics
- Validation surface already present:
  - `component/sniffing/quic_test.go`
  - `component/sniffing/quic_bench_test.go`
  - `component/sniffing/sniffing_bench_test.go`
  - `component/sniffing/tls_test.go`
  - `component/sniffing/sniffer_test.go`
- Verdict:
  - very strong second candidate

## Priority 3: routing optimizer and geodata expansion

- Recommended target:
  - `component/routing/optimizer.go`
  - adjacent geodata decode/expand path
- Why this is low risk:
  - startup / reload path, not live packet path
  - batch transformation logic with deterministic output
  - naturally testable with fixtures
- Why this is high return:
  - large geosite / geoip expansions can be CPU and memory heavy during reload
  - Rust can reduce peak allocations and improve deterministic transform cost
- Key anchors:
  - `component/routing/optimizer.go:30`
  - `component/routing/optimizer.go:157`
  - `component/routing/optimizer.go:162`
  - `component/routing/optimizer.go:222`
- Recommended cut:
  - keep high-level optimizer orchestration in Go if needed
  - move geosite/geoip materialization and rule expansion helpers into Rust
- Verdict:
  - strong third candidate, especially if reload cost matters

## Priority 4: DNS request/response matchers and upstream parsing

- Recommended target:
  - `component/dns/request_routing.go`
  - `component/dns/response_routing.go`
  - selected parsing/model logic in `component/dns/upstream.go`
- Why this is low to medium risk:
  - request/response matcher logic is still matcher-like and deterministic
  - upstream scheme parsing is narrow and structured
- Why this is useful:
  - DNS routing shares domain matching characteristics with main routing
  - `ParseRawUpstream(...)` and refresh logic form a clean model boundary
- Key anchors:
  - `component/dns/dns.go:45`
  - `component/dns/dns.go:93`
  - `component/dns/request_routing.go:132`
  - `component/dns/response_routing.go:181`
  - `component/dns/upstream.go:57`
  - `component/dns/upstream.go:111`
  - `component/dns/upstream.go:196`
- Important restriction:
  - do not start with `control/dns_control.go`
  - matcher / parser can move earlier, controller should stay later
- Verdict:
  - good second-wave target, but not before domain matcher and sniffing

## Priority 5: selective config helpers, not the full config grammar

- Recommended target:
  - `config/config_merger.go`
  - selective normalization and validation helpers
- Why this is low risk:
  - include merge and file checks are bounded and deterministic
- Why this is not first priority:
  - full config parsing touches ANTLR grammar, reflection-heavy assignment, default decoding, and many error message shapes
  - `dae-wing` depends on parse/preview/validate behaviors across many endpoints
- Key anchors:
  - `config/config_merger.go:38`
  - `config/config_merger.go:50`
  - `config/parser.go:37`
  - `pkg/config_parser/config_parser.go:21`
- Recommended cut:
  - start from merger / normalization / helper transforms only
  - do not rewrite the whole grammar/parser first
- Verdict:
  - possible, but not a first-wave target

## Not Recommended Yet

- `engine/runtime.go`
- `control/control_plane.go`
- `control/tcp.go`
- `control/udp.go`
- `control/dns_control.go`
- `component/outbound/*`
- `/root/project/outbound` protocol implementations
- `/root/project/quic-go`
- `daed` frontend
- `dae-wing` orchestrator and API transport

### Reasons

- heavy lifecycle ownership
- netns / kernel / eBPF coupling
- reload semantics and long-lived state
- connection reuse, retry, and failure handling complexity
- cross-repo contract surface
- high regression cost relative to immediate performance gain

## Recommended Rust Rollout Order

1. `dae-domain-matcher`
2. `dae-sniffing`
3. geodata-backed routing optimizer helpers
4. DNS matcher + upstream parser

### Explicitly not first

- full config grammar rewrite
- control-plane lifecycle rewrite
- outbound protocol rewrite
- `quic-go` rewrite or replacement

## Operational Notes

- Current live checkout confirms the real layering is:
  - `daed` UI/product shell
  - `dae-wing` control plane and resource orchestration
  - `daenew` runtime/data plane
  - `outbound` protocol transport implementations
  - `quic-go` QUIC transport dependency for selected protocols
- Therefore, when the question is "what in `daenew` should be rewritten in Rust first", the answer is:
  - choose pure, reusable, CPU-hot, algorithmic components inside `dae`
  - do not start from orchestration, protocol bodies, or global runtime state

## Next Suggested Memo Slice

- If continuing from this note, the next useful artifact is a Rust migration design memo for the first candidate:
  - FFI boundary
  - input/output structs
  - parity fixture format
  - benchmark plan
  - rollback switch
