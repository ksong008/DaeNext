use std::collections::BTreeMap;
use std::io;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeMapUpdateDiffReport {
    pub entries_inserted: usize,
    pub entries_updated: usize,
    pub entries_deleted: usize,
    pub entries_unchanged: usize,
}

impl RuntimeMapUpdateDiffReport {
    pub const fn entries_changed(self) -> usize {
        self.entries_inserted + self.entries_updated + self.entries_deleted
    }
}

pub fn apply_runtime_map_update_diff<K, V, Current, Desired, Update, Delete>(
    current: Current,
    desired: Desired,
    mut update: Update,
    mut delete: Delete,
) -> io::Result<RuntimeMapUpdateDiffReport>
where
    K: Ord,
    V: Eq,
    Current: IntoIterator<Item = (K, V)>,
    Desired: IntoIterator<Item = (K, V)>,
    Update: FnMut(&K, &V) -> io::Result<()>,
    Delete: FnMut(&K) -> io::Result<()>,
{
    let current = current.into_iter().collect::<BTreeMap<_, _>>();
    let desired = desired.into_iter().collect::<BTreeMap<_, _>>();
    let mut report = RuntimeMapUpdateDiffReport::default();

    for (key, value) in &desired {
        match current.get(key) {
            Some(existing) if existing == value => {
                report.entries_unchanged += 1;
            }
            Some(_) => {
                update(key, value)?;
                report.entries_updated += 1;
            }
            None => {
                update(key, value)?;
                report.entries_inserted += 1;
            }
        }
    }

    for key in current.keys() {
        if !desired.contains_key(key) {
            delete(key)?;
            report.entries_deleted += 1;
        }
    }

    Ok(report)
}
