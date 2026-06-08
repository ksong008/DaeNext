use super::*;
#[derive(Debug)]
pub(crate) struct ResidentDataplaneRuntime {
    pub(in crate::production_runtime_owner) stop: Arc<AtomicBool>,
    pub(in crate::production_runtime_owner) handles: Vec<JoinHandle<()>>,
    pub(in crate::production_runtime_owner) event_file: PathBuf,
    pub(in crate::production_runtime_owner) event_lock: Arc<Mutex<()>>,
    pub(in crate::production_runtime_owner) reload_generation: u64,
    pub(in crate::production_runtime_owner) metrics: Arc<ResidentDataplaneMetrics>,
    pub(in crate::production_runtime_owner) udp_packet_workers_active: Arc<AtomicUsize>,
    pub(in crate::production_runtime_owner) groups: Vec<Arc<plan::ResidentProxyGroupPlan>>,
    pub(in crate::production_runtime_owner) manual_probe_plans:
        BTreeMap<String, Result<plan::ResidentProxyProbePlan, String>>,
}

impl ResidentDataplaneRuntime {
    pub(in crate::production_runtime_owner) fn metrics_snapshot(&self) -> Value {
        let mut snapshot = self.metrics.snapshot();
        snapshot["reloadGeneration"] = json!(self.reload_generation);
        snapshot["packetSessionManager"] = json!({
            "schemaVersion": 1,
            "manager": "bounded-resident-packet-session",
            "reloadGeneration": self.reload_generation,
        });
        snapshot
    }

    pub(in crate::production_runtime_owner) fn prune_event_log(&self) -> std::io::Result<()> {
        let _guard = self
            .event_lock
            .lock()
            .map_err(|_| std::io::Error::other("resident event log lock poisoned"))?;
        prune_resident_event_log_file(&self.event_file)
    }

    pub(in crate::production_runtime_owner) fn clear_event_log(&self) -> std::io::Result<()> {
        let _guard = self
            .event_lock
            .lock()
            .map_err(|_| std::io::Error::other("resident event log lock poisoned"))?;
        clear_resident_event_log_file(&self.event_file)
    }

    pub(in crate::production_runtime_owner) fn node_latency_snapshots(&self) -> Vec<Value> {
        let reload_generation = self.reload_generation;
        preferred_latency_snapshots(
            self.groups
                .iter()
                .flat_map(|group| group.latency_snapshots())
                .map(|snapshot| resident_latency_snapshot_json(snapshot, reload_generation)),
        )
    }

    pub(in crate::production_runtime_owner) fn probe_node_latencies(
        &self,
        links: &[String],
    ) -> Vec<Value> {
        if links.is_empty() {
            return Vec::new();
        }
        let requested = links
            .iter()
            .filter(|link| !link.is_empty())
            .cloned()
            .collect::<HashSet<_>>();
        if requested.is_empty() {
            return Vec::new();
        }

        let checked_at = unix_now_secs();
        let mut snapshots = Vec::new();
        let mut tasks = Vec::new();
        for link in requested {
            match self.manual_probe_plans.get(&link) {
                Some(Ok(candidate)) => tasks.push(candidate.clone()),
                Some(Err(err)) => snapshots.push(manual_probe_unavailable_snapshot(
                    &link,
                    "native outbound probe not admitted for this node",
                    err,
                    checked_at,
                    self.reload_generation,
                )),
                None => snapshots.push(manual_probe_unavailable_snapshot(
                    &link,
                    "node is not present in the current runtime config",
                    "materialize/reload runtime before testing this node",
                    checked_at,
                    self.reload_generation,
                )),
            }
        }

        for chunk in tasks.chunks(RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY) {
            let reload_generation = self.reload_generation;
            let mut chunk_snapshots = thread::scope(|scope| {
                let mut handles = Vec::new();
                for candidate in chunk.iter().cloned() {
                    let groups = &self.groups;
                    handles.push(scope.spawn(move || {
                        probe_resident_candidate_tcp_latency_snapshot(
                            groups,
                            candidate,
                            reload_generation,
                        )
                    }));
                }
                handles
                    .into_iter()
                    .filter_map(|handle| handle.join().ok())
                    .collect::<Vec<_>>()
            });
            snapshots.append(&mut chunk_snapshots);
        }
        preferred_latency_snapshots(snapshots)
    }

    pub(in crate::production_runtime_owner) fn shutdown(&mut self, steps: &mut Vec<Value>) {
        self.stop.store(true, Ordering::Relaxed);
        let mut joined = 0_usize;
        let mut panicked = 0_usize;
        for handle in self.handles.drain(..) {
            match handle.join() {
                Ok(()) => joined += 1,
                Err(_) => panicked += 1,
            }
        }
        let udp_packet_drain = wait_for_udp_packet_workers_to_drain(
            &self.udp_packet_workers_active,
            RESIDENT_UDP_PACKET_WORKER_DRAIN_TIMEOUT,
        );
        steps.push(json!({
            "name": "stop-resident-tcp-udp-dataplane-workers",
            "status": if panicked == 0 && udp_packet_drain.drained { "pass" } else { "fail" },
            "joined_worker_threads": joined,
            "panicked_worker_threads": panicked,
            "udp_packet_worker_drain": udp_packet_drain.to_value(),
            "event_file": path_string(&self.event_file),
        }));
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(in crate::production_runtime_owner) struct UdpPacketWorkerDrain {
    pub(in crate::production_runtime_owner) drained: bool,
    pub(in crate::production_runtime_owner) remaining_workers: usize,
    pub(in crate::production_runtime_owner) waited_ms: u128,
    pub(in crate::production_runtime_owner) timeout_ms: u128,
}

impl UdpPacketWorkerDrain {
    fn to_value(&self) -> Value {
        json!({
            "status": if self.drained { "pass" } else { "timeout" },
            "remainingWorkers": self.remaining_workers,
            "waitedMs": self.waited_ms,
            "timeoutMs": self.timeout_ms,
        })
    }
}

pub(in crate::production_runtime_owner) fn wait_for_udp_packet_workers_to_drain(
    active_workers: &AtomicUsize,
    timeout: Duration,
) -> UdpPacketWorkerDrain {
    let started_at = Instant::now();
    loop {
        let remaining_workers = active_workers.load(Ordering::Relaxed);
        if remaining_workers == 0 {
            return UdpPacketWorkerDrain {
                drained: true,
                remaining_workers,
                waited_ms: started_at.elapsed().as_millis(),
                timeout_ms: timeout.as_millis(),
            };
        }
        if started_at.elapsed() >= timeout {
            return UdpPacketWorkerDrain {
                drained: false,
                remaining_workers,
                waited_ms: started_at.elapsed().as_millis(),
                timeout_ms: timeout.as_millis(),
            };
        }
        thread::sleep(RESIDENT_IDLE_SLEEP);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_packet_worker_drain_returns_pass_when_idle() {
        let active_workers = AtomicUsize::new(0);
        let drain =
            wait_for_udp_packet_workers_to_drain(&active_workers, Duration::from_millis(10));
        assert!(drain.drained);
        assert_eq!(drain.remaining_workers, 0);
        assert_eq!(drain.to_value()["timeoutMs"], json!(10));
    }

    #[test]
    fn udp_packet_worker_drain_reports_timeout_when_workers_remain() {
        let active_workers = AtomicUsize::new(1);
        let drain =
            wait_for_udp_packet_workers_to_drain(&active_workers, Duration::from_millis(10));
        assert!(!drain.drained);
        assert_eq!(drain.remaining_workers, 1);
        assert_eq!(drain.to_value()["status"], json!("timeout"));
    }
}
