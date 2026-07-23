use super::super::*;
use super::*;

pub(super) struct StandaloneManualProbeJob<'a> {
    pub(super) job_id: u64,
    pub(super) cancellation: &'a LatencyJobCancellation,
    pub(super) state: &'a Path,
    pub(super) runtime: &'a ProductRuntimeManager,
    pub(super) jobs: &'a LatencyJobManager,
    pub(super) conn: &'a mut Connection,
    pub(super) lifecycle_epoch: u64,
    pub(super) config_snapshot: &'a ManualProbeConfigSnapshot,
}

pub(super) struct StandaloneManualProbeOutcome {
    pub(super) completed: usize,
    pub(super) succeeded: usize,
}

impl StandaloneManualProbeJob<'_> {
    pub(super) fn run(
        &mut self,
        nodes: &[LatencyProbeNode],
    ) -> io::Result<StandaloneManualProbeOutcome> {
        self.ensure_current()?;
        let mut completed = 0usize;
        let mut succeeded = 0usize;
        let chunk_size = self
            .config_snapshot
            .parent_chunk_size(latency_probe_unique_link_count(nodes))
            .max(1);
        for link_chunk in latency_probe_link_chunks(nodes, chunk_size) {
            if self.cancellation.is_requested() {
                break;
            }
            let chunk_nodes = latency_probe_nodes_for_links(nodes, &link_chunk);
            let chunk_nodes = current_latency_probe_nodes(self.conn, &chunk_nodes)?;
            if chunk_nodes.is_empty() {
                continue;
            }
            self.ensure_current()?;
            let link_chunk = latency_probe_unique_links(&chunk_nodes);
            let node_index = RuntimeNodeLatencyIndex::new(&chunk_nodes);
            let mut runtime_snapshots = Vec::with_capacity(link_chunk.len());
            let probe_cancelled = self.config_snapshot.probe_streaming(
                self.job_id,
                &link_chunk,
                || self.cancellation.is_requested(),
                |snapshot| runtime_snapshots.push(snapshot.clone()),
            )?;
            if probe_cancelled || self.cancellation.is_requested() {
                break;
            }
            self.ensure_current()?;
            let mut results = super::jobs::node_latency_results_for_runtime_snapshots(
                &chunk_nodes,
                &node_index,
                &runtime_snapshots,
            );
            self.config_snapshot.apply_persistence_fence(&mut results);
            if results.is_empty() {
                continue;
            }
            let (written, written_alive) =
                super::persistence::write_node_latency_results(self.conn, &results)?;
            self.ensure_current()?;
            if written == 0 {
                continue;
            }
            completed = completed.saturating_add(written);
            succeeded = succeeded.saturating_add(written_alive);
            self.jobs.mark_progress(
                self.job_id,
                completed,
                succeeded,
                completed.saturating_sub(succeeded),
            );
        }
        Ok(StandaloneManualProbeOutcome {
            completed,
            succeeded,
        })
    }

    fn ensure_current(&self) -> io::Result<()> {
        if self.runtime.latency_probe_lifecycle_epoch() != self.lifecycle_epoch
            || self.runtime.current_probe_generation().is_some()
        {
            return Err(io::Error::other(
                "manual latency probe runtime state changed while the job was running",
            ));
        }
        if !self.config_snapshot.is_current(self.state)? {
            return Err(io::Error::other(
                "manual latency probe configuration changed while the job was running",
            ));
        }
        Ok(())
    }
}
