use super::*;

const RUNTIME_OVERVIEW_FEED_CAPACITY: usize = 8;

pub(super) struct ProductRuntimeOverviewTick {
    pub(super) sequence: u64,
    pub(super) reload_count: u64,
    pub(super) payload: Arc<[u8]>,
}

pub(super) fn runtime_overview_feed() -> (
    tokio::sync::broadcast::Sender<Arc<ProductRuntimeOverviewTick>>,
    tokio::sync::broadcast::Receiver<Arc<ProductRuntimeOverviewTick>>,
) {
    tokio::sync::broadcast::channel(RUNTIME_OVERVIEW_FEED_CAPACITY)
}

pub(super) fn runtime_overview_tick(
    app: &AppState,
    sequence: u64,
) -> io::Result<Arc<ProductRuntimeOverviewTick>> {
    let mut delta = runtime_overview_delta_report(app);
    if let Value::Object(delta) = &mut delta {
        delta.insert("sequence".to_owned(), json!(sequence));
    }
    let reload_count = delta["reloadCount"].as_u64().unwrap_or(0);
    let payload = serde_json::to_vec(&delta)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(Arc::new(ProductRuntimeOverviewTick {
        sequence,
        reload_count,
        payload: payload.into(),
    }))
}
