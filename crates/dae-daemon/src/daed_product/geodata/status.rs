use super::*;
pub(in crate::daed_product) use dae_product_control::geodata::geodata_dir_for_web_root;
use dae_product_control::geodata::{
    GeodataResourceIdentity, GeodataStatusCacheEntry,
    geodata_resource_status as domain_geodata_resource_status,
};

const GEODATA_STATUS_STABILITY_ATTEMPTS: usize = 2;

#[cfg(test)]
std::thread_local! {
    static GEODATA_STATUS_PARSE_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn reset_geodata_status_parse_count() {
    GEODATA_STATUS_PARSE_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(super) fn geodata_status_parse_count() -> usize {
    GEODATA_STATUS_PARSE_COUNT.with(std::cell::Cell::get)
}

pub(in crate::daed_product) fn geodata_status(app: &AppState) -> io::Result<Value> {
    let dir = geodata_dir(app);
    for kind in [GeodataKind::Geosite, GeodataKind::Geoip] {
        match app.geodata_updates.acquire(kind) {
            Ok(lease) => {
                super::transaction::recover_geodata_transaction(&dir, &app.state, kind)?;
                drop(lease);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(json!({
        "geosite": geodata_resource_status_cached(app, &dir, GeodataKind::Geosite),
        "geoip": geodata_resource_status_cached(app, &dir, GeodataKind::Geoip),
    }))
}

#[cfg(test)]
pub(super) fn geodata_status_for_dir(dir: &Path) -> io::Result<Value> {
    Ok(json!({
        "geosite": geodata_resource_status(dir, GeodataKind::Geosite),
        "geoip": geodata_resource_status(dir, GeodataKind::Geoip),
    }))
}

fn geodata_resource_status(dir: &Path, kind: GeodataKind) -> Value {
    #[cfg(test)]
    GEODATA_STATUS_PARSE_COUNT.with(|count| count.set(count.get().saturating_add(1)));
    domain_geodata_resource_status(dir, kind)
}

pub(super) fn geodata_dir(app: &AppState) -> PathBuf {
    geodata_dir_for_web_root(&app.web_root)
}

fn geodata_resource_status_cached(app: &AppState, dir: &Path, kind: GeodataKind) -> Value {
    for _ in 0..GEODATA_STATUS_STABILITY_ATTEMPTS {
        let Ok(identity_before) = GeodataResourceIdentity::capture(dir, kind) else {
            return geodata_resource_status(dir, kind);
        };
        if let Ok(cache) = app.geodata_status_cache.lock()
            && let Some(entry) = cache.entry(kind)
            && entry.matches(&identity_before)
        {
            return entry.value().clone();
        }

        let value = geodata_resource_status(dir, kind);
        let Ok(identity_after) = GeodataResourceIdentity::capture(dir, kind) else {
            return value;
        };
        if identity_before == identity_after {
            set_geodata_resource_status_cache_entry(
                &app.geodata_status_cache,
                kind,
                GeodataStatusCacheEntry::new(identity_after, value.clone()),
            );
            return value;
        }
    }
    geodata_resource_status(dir, kind)
}

fn set_geodata_resource_status_cache_entry(
    status_cache: &Arc<Mutex<GeodataStatusCache>>,
    kind: GeodataKind,
    entry: GeodataStatusCacheEntry,
) {
    let Ok(mut cache) = status_cache.lock() else {
        return;
    };
    cache.set_entry(kind, entry);
}

pub(super) fn update_geodata_resource_status_cache(
    context: &ProductGeodataUpdateContext,
    kind: GeodataKind,
    value: Value,
) {
    let Ok(entry) = GeodataStatusCacheEntry::capture(&context.dir, kind, value) else {
        return;
    };
    set_geodata_resource_status_cache_entry(&context.status_cache, kind, entry);
}
