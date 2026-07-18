use super::*;

pub(in crate::daed_product) fn total_resource_ledger_json(
    runtime: &Value,
    process: ProcessMetrics,
    allocator: Option<&AllocatorStatsSnapshot>,
    cgroup_memory: &Value,
) -> Value {
    let resident_metrics = runtime.pointer("/residentDataplane/metrics");
    let resident_metric = |name: &str| {
        resident_metrics
            .and_then(|metrics| metrics.get(name))
            .cloned()
            .unwrap_or(Value::Null)
    };
    let quic = runtime
        .pointer("/residentDataplane/metrics/quicEndpoints")
        .cloned()
        .unwrap_or(Value::Null);
    let hysteria2 = runtime
        .pointer("/residentDataplane/metrics/hysteria2Owners")
        .cloned()
        .unwrap_or(Value::Null);
    let anytls = runtime
        .pointer("/residentDataplane/metrics/anytlsOwners")
        .cloned()
        .unwrap_or(Value::Null);
    let runtime_profile = runtime
        .pointer("/residentDataplane/metrics/resources/runtimeProfile")
        .cloned()
        .unwrap_or(Value::Null);
    let map_capacity = runtime
        .pointer("/startupEvidence/mapCapacity")
        .and_then(Value::as_array)
        .map(|rows| rows.iter().map(map_capacity_row).collect::<Vec<_>>())
        .unwrap_or_default();
    let map_current_evidence_complete = !map_capacity.is_empty()
        && map_capacity.iter().all(|row| {
            row["status"].as_str() == Some("pass")
                && row["entries"].as_u64().is_some()
                && row["maxEntries"].as_u64().is_some()
        });
    let other_live_generations = quic["otherLiveGenerations"]
        .as_array()
        .map(Vec::len)
        .unwrap_or(0);
    let generation_overlap_active = other_live_generations > 0
        || runtime
            .pointer("/cleanup/running")
            .and_then(Value::as_bool)
            .unwrap_or(false);

    json!({
        "schema": "resident-total-resource-ledger",
        "schemaVersion": 1,
        "snapshotOnly": true,
        "process": {
            "rssBytes": process.rss_bytes.to_string(),
            "anonymousRssBytes": process.anonymous_rss_bytes.to_string(),
            "fileRssBytes": process.file_rss_bytes.to_string(),
            "vmDataBytes": process.vm_data_bytes.to_string(),
            "threads": process.thread_count,
        },
        "allocator": allocator.map(allocator_ledger_json).unwrap_or_else(|| json!({
            "available": false,
            "source": "allocator-stats-unavailable",
        })),
        "cgroup": {
            "available": cgroup_memory["available"].clone(),
            "currentBytes": cgroup_memory["currentBytes"].clone(),
            "peakBytes": cgroup_memory["peakBytes"].clone(),
            "highBytes": cgroup_memory["highBytes"].clone(),
            "maxBytes": cgroup_memory["maxBytes"].clone(),
            "usageRatio": cgroup_memory["usageRatio"].clone(),
            "events": cgroup_memory["events"].clone(),
            "memoryStat": {
                "anonBytes": cgroup_memory.pointer("/stat/anon").cloned().unwrap_or(Value::Null),
                "fileBytes": cgroup_memory.pointer("/stat/file").cloned().unwrap_or(Value::Null),
                "kernelBytes": cgroup_memory.pointer("/stat/kernel").cloned().unwrap_or(Value::Null),
                "vmallocBytes": cgroup_memory.pointer("/stat/vmalloc").cloned().unwrap_or(Value::Null),
                "socketBytes": cgroup_memory.pointer("/stat/sock").cloned().unwrap_or(Value::Null),
                "slabBytes": cgroup_memory.pointer("/stat/slab").cloned().unwrap_or(Value::Null),
            },
        },
        "ebpfMaps": {
            "profile": runtime.pointer("/residentEbpf/mapProfile").cloned().unwrap_or(Value::Null),
            "profileSource": runtime.pointer("/residentEbpf/mapProfileSource").cloned().unwrap_or(Value::Null),
            "capacitySnapshot": map_capacity,
            "currentEvidenceComplete": map_current_evidence_complete,
            "peakEntriesAvailable": false,
            "perMapMemlockAvailable": false,
            "globalVmallocSource": "cgroup.memory.stat.vmalloc",
            "udpStateInsertFailureTotal": runtime
                .pointer("/residentEbpf/udpStateMetrics/insertFailureTotal")
                .cloned()
                .unwrap_or(Value::Null),
        },
        "quicEndpoints": {
            "currentGeneration": quic["generation"].clone(),
            "liveStates": quic["liveStates"].clone(),
            "udpFds": quic["udpFds"].clone(),
            "endpointDriverTasks": quic["endpointDriverTasks"].clone(),
            "chargedBytes": quic["chargedBytes"].clone(),
            "allLive": quic["allLive"].clone(),
            "admission": quic["admission"].clone(),
            "admissionEnforced": quic["admissionEnforced"].clone(),
            "otherLiveGenerationCount": other_live_generations,
        },
        "hysteria2Owners": {
            "activeOwners": hysteria2["activeOwners"].clone(),
            "activeLogicalLeases": hysteria2["activeLogicalLeases"].clone(),
            "activeUdpSessions": hysteria2["activeUdpSessions"].clone(),
            "currentUdpQueuedBytes": hysteria2["currentUdpQueuedBytes"].clone(),
            "budget": hysteria2["budget"].clone(),
        },
        "anytlsOwners": {
            "mode": anytls["mode"].clone(),
            "concurrentLogicalMultiplexing": anytls["concurrentLogicalMultiplexing"].clone(),
            "registeredKeys": anytls["registeredKeys"].clone(),
            "registeredPhysicalSessions": anytls["registeredPhysicalSessions"].clone(),
            "activePhysicalSessions": anytls["activePhysicalSessions"].clone(),
            "idlePhysicalSessions": anytls["idlePhysicalSessions"].clone(),
            "activeLogicalStreams": anytls["activeLogicalStreams"].clone(),
            "ownerStateBytesLowerBound": anytls["ownerStateBytesLowerBound"].clone(),
            "ownerPaddingSchemeBytes": anytls["ownerPaddingSchemeBytes"].clone(),
            "currentLogicalBufferBytes": anytls["currentLogicalBufferBytes"].clone(),
            "highWaterLogicalBufferBytes": anytls["highWaterLogicalBufferBytes"].clone(),
            "admissionEnforced": anytls["admissionEnforced"].clone(),
            "budget": anytls["budget"].clone(),
        },
        "dnsTransportOwners": {
            "current": resident_metric("dnsTransportOwnersCurrent"),
            "maximum": resident_metric("dnsTransportOwnersMaximum"),
            "evictedCurrent": resident_metric("dnsTransportOwnersEvictedCurrent"),
            "evictedMaximum": resident_metric("dnsTransportOwnersEvictedMaximum"),
            "ownerStateBytesCurrent": resident_metric("dnsTransportOwnerBytesCurrent"),
            "ownerStateBytesMaximum": resident_metric("dnsTransportOwnerBytesMaximum"),
        },
        "proxyDnsUdpBuffers": {
            "queuedBytesCurrent": resident_metric("proxyDnsUdpQueuedBytesCurrent"),
            "pendingPayloadBytesCurrent": resident_metric("proxyDnsUdpPendingBytesCurrent"),
            "pendingMetadataBytesCurrent": resident_metric("proxyDnsUdpPendingMetadataBytesCurrent"),
            "pendingMetadataBytesMaximum": resident_metric("proxyDnsUdpPendingMetadataBytesMaximum"),
            "responseBytesCurrent": resident_metric("proxyDnsUdpResponseBytesCurrent"),
            "responseBytesMaximum": resident_metric("proxyDnsUdpResponseBytesMaximum"),
        },
        "generationOverlap": {
            "active": generation_overlap_active,
            "runtimeGeneration": runtime["runtimeGeneration"].clone(),
            "otherLiveQuicGenerations": other_live_generations,
            "cleanupRunning": runtime.pointer("/cleanup/running").cloned().unwrap_or(Value::Null),
        },
        "budget": {
            "runtimeProfile": runtime_profile,
            "cgroupLimitFinite": cgroup_memory["maxBytes"].is_string(),
            "quicAdmissionEnforced": quic["admissionEnforced"].clone(),
            "mapCurrentEvidenceComplete": map_current_evidence_complete,
            "mapPeakEvidenceAvailable": false,
            "selectionPolicy": "profile-derived limits plus measured peak evidence; no host-specific constants",
        },
        "accounting": {
            "cgroupCurrentIncludesProcessAndKernel": true,
            "rssAllocatorMapAndCgroupMustNotBeSummed": true,
            "allocatorLiveIsNotAnonymousRss": true,
            "mapVmallocIsNotAllocatorResident": true,
            "dnsOwnerStateBytesAreALowerBound": true,
            "dnsQuicEndpointChargesAreReportedSeparately": true,
            "anytlsLogicalBufferBytesAreProfileCharges": true,
            "anytlsOwnerStateBytesAreALowerBound": true,
        },
    })
}

fn allocator_ledger_json(stats: &AllocatorStatsSnapshot) -> Value {
    json!({
        "available": true,
        "source": "jemalloc-epoch-stats",
        "allocatedBytes": stats.allocated.to_string(),
        "activeBytes": stats.active.to_string(),
        "metadataBytes": stats.metadata.to_string(),
        "residentBytes": stats.resident.to_string(),
        "mappedBytes": stats.mapped.to_string(),
        "retainedBytes": stats.retained.to_string(),
        "activeMinusAllocatedBytes": stats.active_minus_allocated().to_string(),
        "residentMinusActiveBytes": stats.resident_minus_active().to_string(),
    })
}

fn map_capacity_row(row: &Value) -> Value {
    let capacity = &row["capacity"];
    json!({
        "name": row["name"].clone(),
        "id": row["id"].clone(),
        "status": capacity["status"].clone(),
        "mapType": capacity["mapType"].clone(),
        "flags": capacity["flags"].clone(),
        "keySize": capacity["keySize"].clone(),
        "valueSize": capacity["valueSize"].clone(),
        "maxEntries": capacity["maxEntries"].clone(),
        "entries": capacity["entries"].clone(),
        "entriesExact": capacity["entriesExact"].clone(),
        "entryCountMode": capacity["entryCountMode"].clone(),
        "usageRatio": capacity["usageRatio"].clone(),
        "nearCapacity": capacity["nearCapacity"].clone(),
        "source": capacity["source"].clone(),
        "measurementBoundary": "resident-start capacity snapshot",
    })
}

#[cfg(test)]
#[path = "resource_ledger_tests.rs"]
mod tests;
