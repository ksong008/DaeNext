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

Permanent permission or kernel errors can leave attachments pending. Cleanup
retains recovery evidence and refuses to report success; it does not guarantee
eventual removal. Restore the required permissions and retry explicit cleanup,
or inspect the recorded owner before performing external recovery. Shared
interface qdiscs and unrelated filters are not broad cleanup targets.
