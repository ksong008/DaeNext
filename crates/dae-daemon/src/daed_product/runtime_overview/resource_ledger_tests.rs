use super::*;

fn process() -> ProcessMetrics {
    ProcessMetrics {
        rss_bytes: 90 * 1024 * 1024,
        anonymous_rss_bytes: 60 * 1024 * 1024,
        file_rss_bytes: 30 * 1024 * 1024,
        vm_data_bytes: 72 * 1024 * 1024,
        thread_count: 41,
        cpu_usage_percent: 1.5,
    }
}

fn allocator() -> AllocatorStatsSnapshot {
    AllocatorStatsSnapshot {
        allocated: 20 * 1024 * 1024,
        active: 24 * 1024 * 1024,
        metadata: 1024 * 1024,
        resident: 32 * 1024 * 1024,
        mapped: 40 * 1024 * 1024,
        retained: 8 * 1024 * 1024,
    }
}

#[test]
fn total_resource_ledger_reconciles_bounded_surfaces_without_double_counting() {
    let runtime = json!({
        "runtimeGeneration": 12,
        "cleanup": { "running": true },
        "residentEbpf": {
            "mapProfile": "balanced",
            "mapProfileSource": "auto",
            "udpStateMetrics": { "insertFailureTotal": 3 },
        },
        "startupEvidence": {
            "mapCapacity": [{
                "name": "routing_tuples_map",
                "id": 7,
                "capacity": {
                    "status": "pass",
                    "source": "native-runtime",
                    "mapType": 1,
                    "flags": 0,
                    "keySize": 16,
                    "valueSize": 32,
                    "maxEntries": 65536,
                    "entries": 4643,
                    "entriesExact": true,
                    "entryCountMode": "exact",
                    "usageRatio": 0.07085,
                    "nearCapacity": false
                }
            }]
        },
        "residentDataplane": { "metrics": {
            "resources": { "runtimeProfile": { "profile": "balanced" } },
            "quicEndpoints": {
                "generation": 12,
                "liveStates": { "total": 1 },
                "udpFds": { "ipv4": 1, "ipv6": 0 },
                "endpointDriverTasks": { "live": 1 },
                "chargedBytes": { "total": 3014656 },
                "allLive": { "total": 2 },
                "admission": { "enforced": true },
                "admissionEnforced": true,
                "otherLiveGenerations": [{ "generation": 11 }]
            },
            "hysteria2Owners": {
                "activeOwners": 1,
                "activeLogicalLeases": 4,
                "activeUdpSessions": 2,
                "currentUdpQueuedBytes": 512,
                "budget": { "owners": 32 }
            },
            "meekTransportOwners": {
                "registeredKeys": 1,
                "registeredBuildTasks": 0,
                "reservedPhysicalConnections": 2,
                "highWaterReservedPhysicalConnections": 3,
                "activePhysicalConnections": 2,
                "highWaterPhysicalConnections": 3,
                "activeLeases": 1,
                "highWaterLeases": 2,
                "idlePhysicalConnections": 1,
                "highWaterIdlePhysicalConnections": 2,
                "activeBuilds": 0,
                "ownerStateBytesLowerBound": 256,
                "admissionEnforced": true,
                "shutdownTimedOut": false,
                "budget": { "owners": 32, "physicalConnections": 1024 }
            },
            "dnsTransportOwnersCurrent": 3,
            "dnsTransportOwnersMaximum": 5,
            "dnsTransportOwnersEvictedCurrent": 1,
            "dnsTransportOwnersEvictedMaximum": 2,
            "dnsTransportOwnerBytesCurrent": 12288,
            "dnsTransportOwnerBytesMaximum": 20480,
            "proxyDnsUdpQueuedBytesCurrent": 120,
            "proxyDnsUdpPendingBytesCurrent": 256,
            "proxyDnsUdpPendingMetadataBytesCurrent": 96,
            "proxyDnsUdpPendingMetadataBytesMaximum": 384,
            "proxyDnsUdpResponseBytesCurrent": 1500,
            "proxyDnsUdpResponseBytesMaximum": 4096
        }}
    });
    let cgroup = json!({
        "available": true,
        "currentBytes": "106876928",
        "peakBytes": "263467008",
        "highBytes": null,
        "maxBytes": "536870912",
        "usageRatio": 0.1991,
        "events": { "high": "0" },
        "stat": {
            "anon": "63094784",
            "file": "5124096",
            "kernel": "37806080",
            "vmalloc": "33136640",
            "sock": "212992",
            "slab": "3234416"
        }
    });

    let ledger = total_resource_ledger_json(&runtime, process(), Some(&allocator()), &cgroup);
    assert_eq!(ledger["cgroup"]["peakBytes"], "263467008");
    assert_eq!(ledger["cgroup"]["memoryStat"]["vmallocBytes"], "33136640");
    assert_eq!(ledger["allocator"]["allocatedBytes"], "20971520");
    assert_eq!(ledger["ebpfMaps"]["capacitySnapshot"][0]["entries"], 4643);
    assert_eq!(ledger["ebpfMaps"]["currentEvidenceComplete"], true);
    assert_eq!(ledger["quicEndpoints"]["otherLiveGenerationCount"], 1);
    assert_eq!(
        ledger["meekTransportOwners"]["activePhysicalConnections"],
        2
    );
    assert_eq!(ledger["meekTransportOwners"]["idlePhysicalConnections"], 1);
    assert_eq!(ledger["meekTransportOwners"]["admissionEnforced"], true);
    assert_eq!(ledger["dnsTransportOwners"]["current"], 3);
    assert_eq!(
        ledger["dnsTransportOwners"]["ownerStateBytesCurrent"],
        12288
    );
    assert_eq!(
        ledger["proxyDnsUdpBuffers"]["pendingMetadataBytesCurrent"],
        96
    );
    assert_eq!(ledger["proxyDnsUdpBuffers"]["responseBytesMaximum"], 4096);
    assert_eq!(ledger["generationOverlap"]["active"], true);
    assert_eq!(ledger["budget"]["cgroupLimitFinite"], true);
    assert_eq!(
        ledger["accounting"]["rssAllocatorMapAndCgroupMustNotBeSummed"],
        true
    );
    assert!(ledger.get("totalBytes").is_none());
}

#[test]
fn total_resource_ledger_marks_missing_peak_and_map_evidence_explicitly() {
    let ledger = total_resource_ledger_json(
        &json!({}),
        ProcessMetrics::default(),
        None,
        &json!({ "available": false }),
    );
    assert_eq!(ledger["allocator"]["available"], false);
    assert_eq!(ledger["cgroup"]["peakBytes"], Value::Null);
    assert_eq!(ledger["ebpfMaps"]["currentEvidenceComplete"], false);
    assert_eq!(ledger["ebpfMaps"]["peakEntriesAvailable"], false);
    assert_eq!(ledger["ebpfMaps"]["perMapMemlockAvailable"], false);
    assert_eq!(ledger["budget"]["cgroupLimitFinite"], false);
}
