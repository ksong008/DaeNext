use super::*;

#[derive(Clone)]
struct GroupCandidateRow {
    node: Value,
    latency_ms: Option<i64>,
    alive: bool,
}

pub(super) struct GroupMaterializedCandidateSummary {
    pub(super) count: usize,
    pub(super) sample_nodes: Vec<Value>,
    pub(super) current_node: Value,
    pub(super) best_node: Value,
    best_latency_ms: Option<i64>,
    best_order: usize,
}

impl GroupMaterializedCandidateSummary {
    fn new() -> Self {
        Self {
            count: 0,
            sample_nodes: Vec::new(),
            current_node: Value::Null,
            best_node: Value::Null,
            best_latency_ms: None,
            best_order: usize::MAX,
        }
    }

    fn push_unique(
        &mut self,
        seen_tags: &mut HashSet<String>,
        candidate: GroupCandidateRow,
        sample_limit: usize,
    ) {
        let tag = runtime_node_tag(&candidate.node);
        if !seen_tags.insert(tag) {
            return;
        }

        let order = self.count;
        self.count = self.count.saturating_add(1);
        if self.current_node.is_null() {
            self.current_node = candidate.node.clone();
        }
        if self.sample_nodes.len() < sample_limit {
            self.sample_nodes.push(candidate.node.clone());
        }
        let Some(latency_ms) = candidate.latency_ms.filter(|_| candidate.alive) else {
            return;
        };
        let replace_best = match self.best_latency_ms {
            Some(current_latency) => {
                latency_ms < current_latency
                    || (latency_ms == current_latency && order < self.best_order)
            }
            None => true,
        };
        if replace_best {
            self.best_latency_ms = Some(latency_ms);
            self.best_order = order;
            self.best_node = candidate.node.clone();
            self.current_node = candidate.node;
        }
    }
}

pub(super) fn group_materialized_candidate_summary(
    conn: &Connection,
    group_id: i64,
    sample_limit: usize,
) -> io::Result<GroupMaterializedCandidateSummary> {
    let mut summary = GroupMaterializedCandidateSummary::new();
    let mut seen_tags = HashSet::<String>::new();

    let mut direct_stmt = conn
        .prepare(
            "SELECT n.id, n.link, n.name, n.address, n.protocol, n.tag, n.subscription_id,
                    l.latency_ms, COALESCE(l.alive, 0)
             FROM nodes n
             JOIN group_nodes gn ON gn.node_id = n.id
             LEFT JOIN node_latency_results l ON l.node_id = n.id
             WHERE gn.group_id = ?1
             ORDER BY n.id",
        )
        .map_err(sqlite_io_error)?;
    let direct_rows = direct_stmt
        .query_map(params![group_id], group_candidate_row_value)
        .map_err(sqlite_io_error)?;
    for row in direct_rows {
        summary.push_unique(&mut seen_tags, row.map_err(sqlite_io_error)?, sample_limit);
    }

    let mut subscription_stmt = conn
        .prepare(
            "SELECT s.id, gs.name_filter_regex
             FROM subscriptions s
             JOIN group_subscriptions gs ON gs.subscription_id = s.id
             WHERE gs.group_id = ?1
             ORDER BY s.id",
        )
        .map_err(sqlite_io_error)?;
    let subscription_rows = subscription_stmt
        .query_map(params![group_id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?))
        })
        .map_err(sqlite_io_error)?;
    for row in subscription_rows {
        let (subscription_id, name_filter_regex) = row.map_err(sqlite_io_error)?;
        push_subscription_materialized_candidates(
            conn,
            subscription_id,
            name_filter_regex.as_deref(),
            sample_limit,
            &mut seen_tags,
            &mut summary,
        )?;
    }

    Ok(summary)
}

fn push_subscription_materialized_candidates(
    conn: &Connection,
    subscription_id: i64,
    name_filter_regex: Option<&str>,
    sample_limit: usize,
    seen_tags: &mut HashSet<String>,
    summary: &mut GroupMaterializedCandidateSummary,
) -> io::Result<()> {
    let filter = compile_name_filter(name_filter_regex)?;
    let mut stmt = conn
        .prepare(
            "SELECT n.id, n.link, n.name, n.address, n.protocol, n.tag, n.subscription_id,
                    l.latency_ms, COALESCE(l.alive, 0)
             FROM nodes n
             LEFT JOIN node_latency_results l ON l.node_id = n.id
             WHERE n.subscription_id = ?1
             ORDER BY n.id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![subscription_id], group_candidate_row_value)
        .map_err(sqlite_io_error)?;
    for row in rows {
        let candidate = row.map_err(sqlite_io_error)?;
        if node_matches_name_filter(&candidate.node, filter.as_ref()) {
            summary.push_unique(seen_tags, candidate, sample_limit);
        }
    }
    Ok(())
}

fn group_candidate_row_value(row: &rusqlite::Row<'_>) -> rusqlite::Result<GroupCandidateRow> {
    Ok(GroupCandidateRow {
        node: node_row_value(row)?,
        latency_ms: row.get::<_, Option<i64>>(7)?,
        alive: row.get::<_, i64>(8)? != 0,
    })
}
