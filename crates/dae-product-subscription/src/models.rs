use std::path::Path;

use crate::{ParsedNodeLink, SubscriptionContentKind};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscriptionSourceIdentity {
    pub id: i64,
    pub link: String,
    pub tag: Option<String>,
    pub use_proxy: bool,
}

#[derive(Clone, Debug)]
pub struct PreparedSubscriptionNode {
    pub stored_link: String,
    pub parsed: ParsedNodeLink,
}

#[derive(Clone, Debug)]
pub struct RejectedSubscriptionNode {
    pub link: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default)]
pub struct PreparedSubscriptionNodes {
    pub admitted: Vec<PreparedSubscriptionNode>,
    pub invalid: Vec<RejectedSubscriptionNode>,
    pub not_admitted: Vec<RejectedSubscriptionNode>,
}

#[derive(Clone, Debug)]
pub struct PreparedSubscriptionRefresh {
    pub content_kind: SubscriptionContentKind,
    pub source_node_count: usize,
    pub invalid_source_count: usize,
    pub empty: bool,
    pub nodes: PreparedSubscriptionNodes,
    pub persist_content: bool,
}

pub enum PersistedSubscriptionContent<'a> {
    Bytes { path: &'a Path, bytes: &'a [u8] },
    StagedFile { path: &'a Path, staging: &'a Path },
}
