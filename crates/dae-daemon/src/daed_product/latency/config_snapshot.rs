use super::super::*;
use super::*;

#[derive(Clone, Debug)]
pub(super) struct ManualProbeConfigSnapshot {
    content: Arc<str>,
    desired_state_revision: Arc<RuntimeDesiredStateRevision>,
    concurrency: usize,
    tcp_probe_timeout: Duration,
}

impl ManualProbeConfigSnapshot {
    pub(super) fn capture(state: &Path) -> io::Result<Self> {
        let plan = prepare_runtime_materialization_plan(state)?;
        let config = build_runtime_config_from_content(&plan.content).map_err(io::Error::other)?;
        Ok(Self {
            concurrency: crate::production_runtime_owner::resident_manual_latency_probe_concurrency_from_config(
                &config,
            ),
            tcp_probe_timeout:
                crate::production_runtime_owner::resident_tcp_latency_probe_timeout_from_config(
                    &config,
                ),
            desired_state_revision: Arc::new(plan.desired_state_revision()),
            content: Arc::from(plan.content),
        })
    }

    pub(super) fn parent_chunk_size(&self, unique_link_count: usize) -> usize {
        latency_probe_helper_parent_chunk_size(self.concurrency, unique_link_count)
    }

    pub(super) fn is_current(&self, state: &Path) -> io::Result<bool> {
        let conn = open_state_connection(state)?;
        Ok(runtime_desired_state_revision_from_connection(&conn)? == *self.desired_state_revision)
    }

    pub(super) fn probe_streaming<F, C>(
        &self,
        execution_id: u64,
        links: &[String],
        should_cancel: C,
        on_snapshot: F,
    ) -> io::Result<bool>
    where
        F: FnMut(&Value),
        C: FnMut() -> bool,
    {
        match run_latency_probe_helper_streaming(
            LatencyProbeHelperInput::selected_state(&self.content),
            execution_id,
            self.concurrency,
            self.tcp_probe_timeout,
            links,
            should_cancel,
            on_snapshot,
        ) {
            Ok(LatencyProbeHelperStreamOutcome::Completed) => Ok(false),
            Ok(LatencyProbeHelperStreamOutcome::Cancelled) => Ok(true),
            Err(err) => Err(io::Error::other(format!(
                "manual latency probe helper failed: {}",
                err.message
            ))),
        }
    }

    pub(super) fn apply_persistence_fence(&self, results: &mut [NodeLatencyWrite]) {
        for result in results {
            result.probe_generation = None;
            result.desired_state_revision = Some(Arc::clone(&self.desired_state_revision));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::tests::support::FreshProductState;
    use super::*;

    #[test]
    fn selected_state_snapshot_is_read_only_and_revision_bound() {
        let fixture = FreshProductState::new("manual-probe-config-snapshot");
        fixture.seed_selected_resources();
        let snapshot = ManualProbeConfigSnapshot::capture(fixture.state()).unwrap();

        assert!(snapshot.is_current(fixture.state()).unwrap());
        assert_eq!(
            fixture
                .connection()
                .query_row("SELECT COUNT(*) FROM systems", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );

        fixture
            .connection()
            .execute(
                "UPDATE dns SET version = version + 1 WHERE selected = 1",
                [],
            )
            .unwrap();
        assert!(!snapshot.is_current(fixture.state()).unwrap());
    }
}
