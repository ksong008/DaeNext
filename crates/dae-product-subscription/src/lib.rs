use std::sync::{Mutex, OnceLock};

mod content;
pub mod fetch_error;
mod group_store;
mod group_summary;
mod group_summary_batch;
mod helper_process;
mod helper_protocol;
mod import_result;
mod latency_executor;
mod latency_identity;
mod latency_job_state;
mod latency_nodes;
mod latency_persistence;
mod latency_seen;
mod latency_storage;
mod models;
mod mutations;
mod node_identity;
mod node_view;
mod outcome;
mod parser;
mod persistence;
mod refresh_node_sync;
mod refresh_transaction;
mod runtime_apply;
mod scheduler;
mod source;
mod subscription_view;
mod wire_http;

pub use content::*;
pub use dae_product_core::RuntimeNodeTag;
pub use group_store::*;
pub use group_summary_batch::list_group_summaries_batched;
pub use helper_process::*;
pub use helper_protocol::*;
pub use import_result::*;
pub use latency_executor::*;
pub use latency_identity::*;
pub use latency_job_state::*;
pub use latency_nodes::*;
pub use latency_persistence::*;
pub use latency_seen::*;
pub use latency_storage::*;
pub use models::*;
pub use mutations::*;
pub use node_identity::*;
pub use node_view::*;
pub use outcome::*;
pub use parser::*;
pub use persistence::*;
pub use refresh_node_sync::*;
pub use refresh_transaction::*;
pub use runtime_apply::*;
pub use scheduler::*;
pub use source::*;
pub use subscription_view::*;
pub use wire_http::*;

pub fn subscription_write_guard() -> std::io::Result<std::sync::MutexGuard<'static, ()>> {
    static SUBSCRIPTION_WRITE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    SUBSCRIPTION_WRITE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| std::io::Error::other("subscription write lock poisoned"))
}
