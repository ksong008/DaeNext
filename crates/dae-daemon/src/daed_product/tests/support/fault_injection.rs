use super::*;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum RuntimeFaultPoint {
    CreateDirectory,
    WriteCandidate,
    SyncCandidate,
    RenameCandidate,
    CommitDatabase,
    StartCandidate,
    CommitPostStart,
    PublishLogPolicy,
    Rollback,
}

impl RuntimeFaultPoint {
    pub(crate) const ALL: [Self; 9] = [
        Self::CreateDirectory,
        Self::WriteCandidate,
        Self::SyncCandidate,
        Self::RenameCandidate,
        Self::CommitDatabase,
        Self::StartCandidate,
        Self::CommitPostStart,
        Self::PublishLogPolicy,
        Self::Rollback,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::CreateDirectory => "create-directory",
            Self::WriteCandidate => "write-candidate",
            Self::SyncCandidate => "sync-candidate",
            Self::RenameCandidate => "rename-candidate",
            Self::CommitDatabase => "commit-database",
            Self::StartCandidate => "start-candidate",
            Self::CommitPostStart => "commit-post-start",
            Self::PublishLogPolicy => "publish-log-policy",
            Self::Rollback => "rollback",
        }
    }
}

#[derive(Default)]
pub(crate) struct RuntimeFaultFixture {
    armed: BTreeMap<RuntimeFaultPoint, usize>,
    visited: Vec<RuntimeFaultPoint>,
}

impl RuntimeFaultFixture {
    pub(crate) fn fail_next(&mut self, point: RuntimeFaultPoint) {
        *self.armed.entry(point).or_default() += 1;
    }

    pub(crate) fn checkpoint(&mut self, point: RuntimeFaultPoint) -> io::Result<()> {
        self.visited.push(point);
        let Some(remaining) = self.armed.get_mut(&point) else {
            return Ok(());
        };
        if *remaining == 0 {
            return Ok(());
        }
        *remaining -= 1;
        Err(io::Error::other(format!(
            "injected runtime fixture fault at {}",
            point.as_str()
        )))
    }

    pub(crate) fn visited(&self) -> &[RuntimeFaultPoint] {
        &self.visited
    }
}

impl RuntimeApplyCheckpoints for RuntimeFaultFixture {
    fn checkpoint(&mut self, point: RuntimeApplyCheckpoint) -> io::Result<()> {
        let point = match point {
            RuntimeApplyCheckpoint::CreateDirectory => RuntimeFaultPoint::CreateDirectory,
            RuntimeApplyCheckpoint::WriteCandidate => RuntimeFaultPoint::WriteCandidate,
            RuntimeApplyCheckpoint::SyncCandidate => RuntimeFaultPoint::SyncCandidate,
            RuntimeApplyCheckpoint::StartCandidate => RuntimeFaultPoint::StartCandidate,
            RuntimeApplyCheckpoint::CommitPostStart => RuntimeFaultPoint::CommitPostStart,
            RuntimeApplyCheckpoint::RenameCandidate => RuntimeFaultPoint::RenameCandidate,
            RuntimeApplyCheckpoint::CommitDatabase => RuntimeFaultPoint::CommitDatabase,
            RuntimeApplyCheckpoint::PublishLogPolicy => RuntimeFaultPoint::PublishLogPolicy,
            RuntimeApplyCheckpoint::Rollback => RuntimeFaultPoint::Rollback,
        };
        RuntimeFaultFixture::checkpoint(self, point)
    }
}

#[test]
fn runtime_fault_fixture_covers_every_transaction_boundary_once() {
    for point in RuntimeFaultPoint::ALL {
        let mut fixture = RuntimeFaultFixture::default();
        fixture.fail_next(point);
        let error = fixture.checkpoint(point).unwrap_err();
        assert!(error.to_string().contains(point.as_str()), "{error}");
        fixture.checkpoint(point).unwrap();
        assert_eq!(fixture.visited(), &[point, point]);
    }
}
