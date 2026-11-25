# Native attachment cleanup

The physical runtime retains the original program, namespace and cgroup FDs
needed to identify its attachments. Explicit cleanup releases successful items
and retains pending items for another call. An error is reported as a failure;
it does not prove that the affected filter has been removed. The caller must
retain the owner if it needs to retry. Drop makes a bounded cleanup attempt and
reports errors; it cannot provide recovery after the process has exited.

Compatible logical reloads retain the physical owner and do not detach its
links. Physical replacement, failed startup and shutdown exercise cleanup.
Pending physical cleanup must be resolved before replacing that owner.

## Kernel and concurrency boundaries

Aya 0.16 selects cgroup FD links on kernels at least 5.7 and legacy program
attachments below 5.7. The current resident admission gate requires `bpf_loop`
at its 5.17 version threshold, even without a configured WAN. Consequently the
legacy cgroup recovery branch is outside normal admitted resident deployments.
It has not been dynamically validated on an old kernel. A forced branch test
alone would not establish full old-kernel data-plane support.

FD link cleanup releases this owner's link. TC netlink recovery first observes
the exact interface, direction, priority, handle and program identity. Missing
entries complete cleanup; a different owner is refused. Observation followed by
deletion is not an atomic conditional delete against another privileged process.
Coordinate external TC writers; the runtime does not guarantee protection from
an arbitrary concurrent privileged replacement between these operations.

Before attaching a host TC netlink filter, the resident runtime pins its
program under the owner directory for that interface index, direction,
priority and handle. Recovery-enabled attach accepts priority 1 with handle
`0x2023:2` or priority 2 with handle `0x2023:4`. After a crash, startup reads
the program ID and tag from stale owner pins and verifies both against the
kernel filter at the slot before detaching. Absent slots already satisfy
recovery. With older builds, startup can identify a filter by the referenced
frozen PARAM map. The classifier role,
program ID and tag must agree with the kernel observations. The map must be a
single-entry `.rodata` array with a 4-byte key, a 48-byte PARAM value and
`BPF_F_RDONLY_PROG`. PARAM must use the current ABI (2) and carry a nonzero
owner PID and dae0 interface index. The PID must match a stale native owner
directory. The index must match dae0 when the interface still exists. A
program pin for the same slot takes precedence over the fallback. Recovery
from the packaged rb96 was verified after a forced exit. A filter in a
configured LAN or WAN recovery slot with unverifiable ownership blocks
startup and remains attached.

Native startup checks the reserved TC netlink slots on the configured LAN and
WAN interfaces even when the production link, namespace and pins are absent.
Crash recovery removes stale native pins after the topology is absent and a
fresh dump finds every reserved TC netlink slot empty on every interface in
the current network namespace. Occupancy on an interface outside the
configuration keeps the pins available and allows startup to continue.
Failed detach, failed topology cleanup, an incomplete dump, and
`cleanup-pending` also keep the affected pins available. The next native startup checks these
conditions again after a failed pin removal. Startup also prunes empty legacy
retry marker directories for the current namespace independently of the owner
pins.

Normal production topology removal releases its peer filter. The TC slot dump
covers the current network namespace. A surviving peer namespace
without its named mount or an interface moved to another network namespace
falls outside that scan.

Permanent permission or kernel errors can leave attachments pending. Cleanup
retains recovery evidence and refuses to report success; it does not guarantee
eventual removal. Restore the required permissions and retry explicit cleanup,
or inspect the recorded owner before performing external recovery. Shared
interface qdiscs and unrelated filters are not broad cleanup targets.
