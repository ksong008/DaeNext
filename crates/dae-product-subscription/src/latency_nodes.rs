use std::collections::HashSet;
use std::io;

use rusqlite::{Connection, OptionalExtension, params};

use crate::all_node_ids;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LatencyProbeNode {
    pub id: i64,
    pub link: String,
}

impl LatencyProbeNode {
    pub fn new(id: i64, link: String) -> Self {
        Self { id, link }
    }
}

pub fn latency_probe_link_chunks(
    nodes: &[LatencyProbeNode],
    chunk_size: usize,
) -> Vec<Vec<String>> {
    latency_probe_unique_links(nodes)
        .chunks(chunk_size.max(1))
        .map(|chunk| chunk.to_vec())
        .collect()
}

pub fn latency_probe_unique_link_count(nodes: &[LatencyProbeNode]) -> usize {
    latency_probe_unique_links(nodes).len()
}

pub fn latency_probe_unique_links(nodes: &[LatencyProbeNode]) -> Vec<String> {
    let mut seen = HashSet::with_capacity(nodes.len());
    let mut links = Vec::with_capacity(nodes.len());
    for node in nodes {
        if seen.insert(node.link.as_str()) {
            links.push(node.link.clone());
        }
    }
    links
}

pub fn latency_probe_nodes_for_links(
    nodes: &[LatencyProbeNode],
    links: &[String],
) -> Vec<LatencyProbeNode> {
    let link_set = links.iter().map(String::as_str).collect::<HashSet<_>>();
    nodes
        .iter()
        .filter(|node| link_set.contains(node.link.as_str()))
        .cloned()
        .collect()
}

pub fn latency_probe_nodes_for_ids(
    conn: &Connection,
    ids: &[i64],
) -> io::Result<Vec<LatencyProbeNode>> {
    let target_ids = if ids.is_empty() {
        all_node_ids(conn)?
    } else {
        ids.to_vec()
    };
    let mut nodes = Vec::with_capacity(target_ids.len());
    for id in target_ids {
        let node = conn
            .query_row(
                "SELECT id, link FROM nodes WHERE id = ?1",
                params![id],
                |row| {
                    Ok(LatencyProbeNode::new(
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                    ))
                },
            )
            .optional()
            .map_err(latency_sqlite_io_error)?;
        if let Some(node) = node {
            nodes.push(node);
        }
    }
    Ok(nodes)
}

pub fn current_latency_probe_nodes(
    conn: &Connection,
    nodes: &[LatencyProbeNode],
) -> io::Result<Vec<LatencyProbeNode>> {
    let mut current = Vec::with_capacity(nodes.len());
    for node in nodes {
        if latency_probe_node_identity_exists(conn, node.id, &node.link)? {
            current.push(node.clone());
        }
    }
    Ok(current)
}

fn latency_probe_node_identity_exists(conn: &Connection, id: i64, link: &str) -> io::Result<bool> {
    conn.query_row(
        "SELECT 1 FROM nodes WHERE id = ?1 AND link = ?2",
        params![id, link],
        |_| Ok(()),
    )
    .optional()
    .map(|value| value.is_some())
    .map_err(latency_sqlite_io_error)
}

fn latency_sqlite_io_error(error: rusqlite::Error) -> io::Error {
    io::Error::other(error.to_string())
}
