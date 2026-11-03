# Native listener publication

A physical native runtime owns its BPF object, four listener slots, and userspace
TCP/UDP consumers. Compatible configuration reloads publish logical generations
inside that owner; they do not replace these maps or sockets.

The `listen_socket_map` SOCKMAP has five entries:

| Key | Meaning |
|---|---|
| 0 / 1 | TCP IPv4 / IPv6 listener |
| 2 / 3 | UDP IPv4 / IPv6 socket |
| 4 | Publication barrier, containing the TCP listener socket |

A writer validates and duplicates every FD, then stages keys 0 through 3 in an
empty map. It writes key 4 only after both consumers adopt their sockets. The BPF
peer ingress checks key 4 before assigning a new TCP SYN or UDP datagram. A
missing barrier, missing listener, or failed `sk_assign` drops the packet and
increments its respective counter; every successful socket lookup is released.
Four sequential slot writes alone are not an atomic publication.

Writers serialize using a nonblocking flock on `/run/lock/dae-listener-map.lock`.
The inode is never unlinked. A busy writer causes an explicit startup/update
error. Failed staging removes only this transaction's entries after checking
their socket cookies. A SOCKMAP lookup returns a cookie, not a recoverable socket
FD. An active map is immutable: presenting the same complete set of socket
cookies is an idempotent validation; a different or incomplete publication is
rejected without overwriting it. To install different listeners, stop their old
physical owner first. Direct BPF writes bypassing the writer lock are outside
this API's concurrency contract.

The production starter waits at most five seconds for TCP Tokio-listener and
UDP AsyncFd adoption acknowledgements. A failed worker or publication fails
startup and shuts down the partial runtime. Temporary map/validation FDs and the
writer lock are released after publication. The physical runtime continues to
own the sockets and BPF links for normal shutdown and crash cleanup.

Resident startup duplicates one dual-stack TCP listener into keys 0 and 1, and
one dual-stack UDP socket into keys 2 and 3. Before host attachment, it reads all
five kernel cookies and requires every slot to be present, key 1 to equal key 0,
key 3 to equal key 2, and key 4 to equal key 0. A read error or failed consistency
check rejects startup and rolls back the partial runtime. These duplicate-slot
checks describe the resident layout; the external loader may supply separate
IPv4/IPv6 sockets. The reads are not an atomic snapshot or a comparison against
every original consumer cookie. They do not prevent a privileged writer
bypassing the API from replacing a consistent publication or changing slots
after the check.

## External loader protocol

`tproxy-listener open-handoff` now requires a `dae-listener-v1` consumer. It sends
one JSON `prepared` message and the two FDs via SCM_RIGHTS. The JSON includes a
random `ready_token`, the exact `ready_ack` text, and `ready_timeout_ms: 5000`.
After adopting both received FDs, the consumer sends:

```text
DAE_LISTENER_READY_V1 <ready_token>\n
```

Here `\n` denotes one newline byte. Only a matching ACK permits publication.
Send failure, closure, invalid ACK, or timeout returns an error and reclaims
staged entries. The helper's successful stdout JSON reports publication and
acknowledged readiness. Legacy receivers that do not ACK time out safely and
must be updated. An ACK proves adoption at that boundary; subsequent consumer
liveness remains the supervising owner's responsibility.

`update-map` accepts caller-owned, already adopted FDs and reports
`userspace_readiness_contract: caller-owned`; it does not claim to have observed
worker readiness. It also rejects replacement of active sockets.

## Regression gates

`scripts/check_native_bpf_objects.sh` checks both default/pname object layouts.
The root-only `scripts/run_native_ebpf_runtime_gate.sh` additionally requires
real kernel tests for all six L2 roles, listener negative actions/counters,
SOCKMAP staging/idempotence, and SCM_RIGHTS success/failure/ACK timeout. Test
count assertions reject skipped or unmatched test filters.

The UDP state ABI and initial connection-direction ownership are unchanged.
An existing state is usable only when `bpf_timer_start` succeeds; a concurrently
inserted but uninitialized timer can be completed by a concurrent observer.
Classification proceeds only after initialization and timer start succeed;
other helper errors remain fail-closed and counted. Full capacity can reject new
tuples while existing initialized entries remain refreshable. These guarantees
do not establish that every timer race is lossless.

See [UDP direction ownership](native-udp-direction.md) for the separate
provenance and first-writer contract.
