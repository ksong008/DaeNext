use std::collections::HashSet;
use std::io;
use std::path::Path;

use dae_product_core::{DEFAULT_PRODUCT_MODE, SectionKind, product_now_text as now_text};
use dae_product_persistence::{
    ProductUserRecord, apply_state_schema, delete_value_at_path, ensure_state_schema,
    open_state_connection, running_runtime_state, selected_id, set_value_at_path, sqlite_io_error,
};
use dae_product_runtime::{
    build_runtime_config_from_content, prepare_runtime_materialization_plan_with_connection,
};
use dae_product_subscription::{
    apply_group_node_ids, apply_group_subscription_ids, group_policy_params_value,
    replace_group_policy_params, subscription_node_row_value as node_row_value,
    subscription_row_value,
};
use dae_product_http::integer_array;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::{Map, Value, json};

type UserRecord = ProductUserRecord;
const DEFAULT_SUBSCRIPTION_CRON_ENABLE: bool = true;

mod export;
mod import;

pub use export::export_bundle;
pub use import::{ImportBundleOutcome, import_bundle};
