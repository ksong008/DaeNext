use super::*;

#[derive(Clone)]
struct GroupCandidateRow {
    node: Value,
    latency_ms: Option<i64>,
    alive: bool,
}

#[derive(Clone)]
struct RuntimeGroupSelectionMatcher {
    selected_node_tag: Option<String>,
    selected_link_hash: Option<String>,
}

pub(super) struct GroupMaterializedCandidateSummary {
    pub(super) count: usize,
    pub(super) sample_nodes: Vec<Value>,
    pub(super) current_node: Value,
    pub(super) best_node: Value,
    pub(super) runtime_selected_node: Value,
    runtime_selection: Option<RuntimeGroupSelectionMatcher>,
    best_latency_ms: Option<i64>,
    best_order: usize,
}

impl GroupMaterializedCandidateSummary {
    fn new(runtime_selector: Option<&Value>) -> Self {
        Self {
            count: 0,
            sample_nodes: Vec::new(),
            current_node: Value::Null,
            best_node: Value::Null,
            runtime_selected_node: Value::Null,
            runtime_selection: RuntimeGroupSelectionMatcher::from_snapshot(runtime_selector),
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
        if self.runtime_selected_node.is_null()
            && let Some(selection) = self.runtime_selection.as_ref()
            && selection.matches_node(&candidate.node)
        {
            self.runtime_selected_node = candidate.node.clone();
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

impl RuntimeGroupSelectionMatcher {
    fn from_snapshot(snapshot: Option<&Value>) -> Option<Self> {
        let selected_node_tag = snapshot
            .and_then(|value| value.get("selectedNodeTag"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        let selected_link_hash = snapshot
            .and_then(|value| value.get("selectedLinkHash"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        if selected_node_tag.is_none() && selected_link_hash.is_none() {
            return None;
        }
        Some(Self {
            selected_node_tag,
            selected_link_hash,
        })
    }

    fn matches_node(&self, node: &Value) -> bool {
        if let Some(selected_node_tag) = self.selected_node_tag.as_deref()
            && runtime_node_tag(node) == selected_node_tag
        {
            return true;
        }
        if let Some(selected_link_hash) = self.selected_link_hash.as_deref()
            && node
                .get("link")
                .and_then(Value::as_str)
                .map(runtime_link_hash)
                .as_deref()
                == Some(selected_link_hash)
        {
            return true;
        }
        false
    }
}

pub(super) fn group_materialized_candidate_summary_with_runtime_selection(
    conn: &Connection,
    group_id: i64,
    sample_limit: usize,
    runtime_selector: Option<&Value>,
) -> io::Result<GroupMaterializedCandidateSummary> {
    let mut summary = GroupMaterializedCandidateSummary::new(runtime_selector);
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
