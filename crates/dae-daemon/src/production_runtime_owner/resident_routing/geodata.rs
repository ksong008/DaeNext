use std::{
    collections::BTreeMap,
    env, fs,
    ops::Range,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use dae_config::Param;
use dae_geodata::{
    DomainType, decode_entry_range, load_geoip_bytes, load_geoip_entry_bytes, load_geosite_bytes,
    load_geosite_entry_bytes,
};
use dae_routing::{DomainKey, SharedDomainSet};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::types::{IpPrefix, SharedResidentIpPrefixSet};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct GeodataResolutionReport {
    pub(super) lookups: Vec<GeodataLookup>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct GeodataLookup {
    pub(super) kind: &'static str,
    pub(super) filename: String,
    pub(super) code: String,
    pub(super) attr: Option<String>,
    pub(super) path: Option<PathBuf>,
    pub(super) decode_ok: bool,
    pub(super) fallback_ok: bool,
    pub(super) output_count: usize,
    pub(super) raw_file_bytes: usize,
    pub(super) decoded_entry_bytes: usize,
    pub(super) expanded_string_bytes: usize,
    pub(super) asset_cache_hit: bool,
    pub(super) decoded_entry_cache_hit: bool,
}

#[derive(Debug)]
pub(in crate::production_runtime_owner) struct GeodataResolver {
    asset_dirs: Vec<PathBuf>,
    asset_cache: Mutex<BTreeMap<String, CachedGeodataAsset>>,
    decoded_entry_cache: Mutex<BTreeMap<DecodedEntryCacheKey, CachedDecodedEntry>>,
    shared_domain_sets: Mutex<BTreeMap<SharedSetCacheKey, SharedDomainSet>>,
    shared_prefix_sets: Mutex<BTreeMap<SharedSetCacheKey, SharedResidentIpPrefixSet>>,
}

#[derive(Clone, Debug)]
struct CachedGeodataAsset {
    path: PathBuf,
    data: Arc<[u8]>,
}

#[derive(Clone, Debug)]
struct GeodataAsset {
    path: PathBuf,
    data: Arc<[u8]>,
    cache_hit: bool,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DecodedEntryCacheKey {
    kind: &'static str,
    filename: String,
    code: String,
}

#[derive(Clone, Debug)]
struct CachedDecodedEntry {
    asset: Arc<[u8]>,
    range: Range<usize>,
}

#[derive(Clone, Debug)]
struct DecodedEntry {
    asset: Arc<[u8]>,
    range: Range<usize>,
    cache_hit: bool,
}

impl DecodedEntry {
    fn as_slice(&self) -> &[u8] {
        &self.asset[self.range.clone()]
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SharedSetCacheKey {
    kind: &'static str,
    key: String,
    len: usize,
    digest: [u8; 32],
}

pub(super) fn load_geoip_params(
    resolver: &GeodataResolver,
    filename: &str,
    code: &str,
    geodata_report: &mut GeodataResolutionReport,
) -> Result<Vec<Param>, String> {
    let filename = dat_filename(filename);
    let asset = resolver.read_asset(&filename)?;
    let decoded = resolver.decoded_entry("geoip", &filename, code, &asset)?;
    let loaded = match decoded.as_ref() {
        Some(entry) => load_geoip_entry_bytes(entry.as_slice()),
        None => load_geoip_bytes(asset.data.as_ref(), code),
    }
    .map_err(|err| {
        format!(
            "load geoip {filename}:{code} from {}: {err}",
            asset.path.display()
        )
    })?;
    if loaded.value.inverse_match {
        return Err("not support inverse match yet".to_owned());
    }
    let output_count = loaded.value.cidrs.len();
    let expanded_string_bytes = loaded.value.cidrs.iter().map(String::len).sum();
    geodata_report.lookups.push(GeodataLookup {
        kind: "geoip",
        filename,
        code: code.to_owned(),
        attr: None,
        path: Some(asset.path),
        decode_ok: loaded.decode_ok,
        fallback_ok: loaded.fallback_ok,
        output_count,
        raw_file_bytes: asset.data.len(),
        decoded_entry_bytes: loaded.decoded_entry_bytes,
        expanded_string_bytes,
        asset_cache_hit: asset.cache_hit,
        decoded_entry_cache_hit: decoded.as_ref().is_some_and(|entry| entry.cache_hit),
    });
    Ok(loaded
        .value
        .cidrs
        .into_iter()
        .map(|cidr| Param {
            key: String::new(),
            val: cidr,
            ..Param::default()
        })
        .collect())
}

pub(super) fn load_geosite_params(
    resolver: &GeodataResolver,
    filename: &str,
    code: &str,
    geodata_report: &mut GeodataResolutionReport,
) -> Result<Vec<Param>, String> {
    let filename = dat_filename(filename);
    let (code, attr) = split_geosite_code_attr(code);
    let asset = resolver.read_asset(&filename)?;
    let decoded = resolver.decoded_entry("geosite", &filename, &code, &asset)?;
    let loaded = match decoded.as_ref() {
        Some(entry) => load_geosite_entry_bytes(entry.as_slice()),
        None => load_geosite_bytes(asset.data.as_ref(), &code),
    }
    .map_err(|err| {
        format!(
            "load geosite {filename}:{code} from {}: {err}",
            asset.path.display()
        )
    })?;
    let attr_filter = attr.as_deref();
    let params = loaded
        .value
        .domains
        .into_iter()
        .filter(|domain| {
            attr_filter.is_none_or(|attr| {
                domain
                    .attributes
                    .iter()
                    .any(|item_attr| item_attr.eq_ignore_ascii_case(attr))
            })
        })
        .map(|domain| Param {
            key: match domain.domain_type {
                DomainType::Full => "full",
                DomainType::RootDomain => "suffix",
                DomainType::Plain => "keyword",
                DomainType::Regex => "regex",
            }
            .to_owned(),
            val: domain.value,
            ..Param::default()
        })
        .collect::<Vec<_>>();
    let expanded_string_bytes = params
        .iter()
        .map(|param| param.key.len() + param.val.len())
        .sum();
    geodata_report.lookups.push(GeodataLookup {
        kind: "geosite",
        filename,
        code,
        attr,
        path: Some(asset.path),
        decode_ok: loaded.decode_ok,
        fallback_ok: loaded.fallback_ok,
        output_count: params.len(),
        raw_file_bytes: asset.data.len(),
        decoded_entry_bytes: loaded.decoded_entry_bytes,
        expanded_string_bytes,
        asset_cache_hit: asset.cache_hit,
        decoded_entry_cache_hit: decoded.as_ref().is_some_and(|entry| entry.cache_hit),
    });
    Ok(params)
}

fn dat_filename(filename: &str) -> String {
    if filename.ends_with(".dat") {
        filename.to_owned()
    } else {
        format!("{filename}.dat")
    }
}

fn split_geosite_code_attr(code: &str) -> (String, Option<String>) {
    let (code, attr) = code.split_once('@').unwrap_or((code, ""));
    (code.to_owned(), (!attr.is_empty()).then(|| attr.to_owned()))
}

impl GeodataResolver {
    pub(in crate::production_runtime_owner) fn new(
        asset_dirs: impl IntoIterator<Item = impl Into<PathBuf>>,
    ) -> Self {
        let mut dirs = Vec::new();
        if let Ok(dir) = env::var("DAE_LOCATION_ASSET")
            && !dir.is_empty()
        {
            dirs.push(PathBuf::from(dir));
        }
        dirs.extend(asset_dirs.into_iter().map(Into::into));
        dirs.push(PathBuf::from("/etc/dae"));
        dirs.push(PathBuf::from("/usr/local/share/dae"));
        dirs.push(PathBuf::from("/usr/share/dae"));
        if let Ok(data_home) = env::var("XDG_DATA_HOME") {
            dirs.push(PathBuf::from(data_home).join("dae"));
        } else if let Ok(home) = env::var("HOME") {
            dirs.push(PathBuf::from(home).join(".local/share/dae"));
        }
        if let Ok(data_dirs) = env::var("XDG_DATA_DIRS") {
            dirs.extend(
                data_dirs
                    .split(':')
                    .filter(|dir| !dir.is_empty())
                    .map(|dir| PathBuf::from(dir).join("dae")),
            );
        }
        dirs.dedup();
        Self {
            asset_dirs: dirs,
            asset_cache: Mutex::new(BTreeMap::new()),
            decoded_entry_cache: Mutex::new(BTreeMap::new()),
            shared_domain_sets: Mutex::new(BTreeMap::new()),
            shared_prefix_sets: Mutex::new(BTreeMap::new()),
        }
    }

    pub(in crate::production_runtime_owner) fn shared_domain_set(
        &self,
        key: &str,
        values: Vec<String>,
    ) -> Result<SharedDomainSet, String> {
        let key = DomainKey::try_from(key)
            .map_err(|err| format!("resident shared domain set key: {err}"))?;
        let cache_key = shared_string_set_key("domain", domain_key_name(key), &values);
        if let Some(cached) = self
            .shared_domain_sets
            .lock()
            .map_err(|_| "geodata shared domain set cache lock poisoned".to_owned())?
            .get(&cache_key)
            .cloned()
        {
            return Ok(cached);
        }
        let shared = SharedDomainSet::from_vec(values, key)
            .map_err(|err| format!("build shared resident domain set: {err}"))?;
        self.shared_domain_sets
            .lock()
            .map_err(|_| "geodata shared domain set cache lock poisoned".to_owned())?
            .insert(cache_key, shared.clone());
        Ok(shared)
    }

    pub(super) fn shared_prefix_set(
        &self,
        prefixes: Vec<IpPrefix>,
    ) -> Result<SharedResidentIpPrefixSet, String> {
        let cache_key = shared_prefix_set_key(&prefixes);
        if let Some(cached) = self
            .shared_prefix_sets
            .lock()
            .map_err(|_| "geodata shared prefix set cache lock poisoned".to_owned())?
            .get(&cache_key)
            .cloned()
        {
            return Ok(cached);
        }
        let shared = Arc::from(prefixes);
        self.shared_prefix_sets
            .lock()
            .map_err(|_| "geodata shared prefix set cache lock poisoned".to_owned())?
            .insert(cache_key, Arc::clone(&shared));
        Ok(shared)
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner) fn shared_domain_set_count(&self) -> usize {
        self.shared_domain_sets
            .lock()
            .expect("shared domain set cache lock")
            .len()
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner) fn shared_prefix_set_count(&self) -> usize {
        self.shared_prefix_sets
            .lock()
            .expect("shared prefix set cache lock")
            .len()
    }

    fn read_asset(&self, filename: &str) -> Result<GeodataAsset, String> {
        if let Some(cached) = self
            .asset_cache
            .lock()
            .map_err(|_| "geodata asset cache lock poisoned".to_owned())?
            .get(filename)
            .cloned()
        {
            return Ok(GeodataAsset {
                path: cached.path,
                data: cached.data,
                cache_hit: true,
            });
        }

        let filename_path = Path::new(filename);
        if filename_path.is_absolute() && filename_path.is_file() {
            return self.read_uncached_asset(filename, filename_path);
        }
        for dir in &self.asset_dirs {
            let path = dir.join(filename);
            if !path.is_file() {
                continue;
            }
            return self.read_uncached_asset(filename, &path);
        }
        Err(format!(
            "geodata asset {filename} not found in [{}]",
            self.asset_dirs
                .iter()
                .map(|dir| dir.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }

    fn read_uncached_asset(&self, cache_key: &str, path: &Path) -> Result<GeodataAsset, String> {
        let data = fs::read(path)
            .map(Arc::<[u8]>::from)
            .map_err(|err| format!("read geodata asset {}: {err}", path.display()))?;
        let cached = CachedGeodataAsset {
            path: path.to_path_buf(),
            data,
        };
        self.asset_cache
            .lock()
            .map_err(|_| "geodata asset cache lock poisoned".to_owned())?
            .insert(cache_key.to_owned(), cached.clone());
        Ok(GeodataAsset {
            path: cached.path,
            data: cached.data,
            cache_hit: false,
        })
    }

    fn decoded_entry(
        &self,
        kind: &'static str,
        filename: &str,
        code: &str,
        asset: &GeodataAsset,
    ) -> Result<Option<DecodedEntry>, String> {
        let key = DecodedEntryCacheKey {
            kind,
            filename: filename.to_owned(),
            code: code.to_owned(),
        };
        if let Some(cached) = self
            .decoded_entry_cache
            .lock()
            .map_err(|_| "geodata decoded-entry cache lock poisoned".to_owned())?
            .get(&key)
            .cloned()
        {
            return Ok(Some(DecodedEntry {
                asset: cached.asset,
                range: cached.range,
                cache_hit: true,
            }));
        }

        let Ok(range) = decode_entry_range(asset.data.as_ref(), code) else {
            return Ok(None);
        };
        let cached = CachedDecodedEntry {
            asset: Arc::clone(&asset.data),
            range,
        };
        self.decoded_entry_cache
            .lock()
            .map_err(|_| "geodata decoded-entry cache lock poisoned".to_owned())?
            .insert(key, cached.clone());
        Ok(Some(DecodedEntry {
            asset: cached.asset,
            range: cached.range,
            cache_hit: false,
        }))
    }
}

fn domain_key_name(key: DomainKey) -> &'static str {
    match key {
        DomainKey::Full => "full",
        DomainKey::Keyword => "keyword",
        DomainKey::Suffix => "suffix",
        DomainKey::Regex => "regex",
    }
}

fn shared_string_set_key(kind: &'static str, key: &str, values: &[String]) -> SharedSetCacheKey {
    let mut hash = Sha256::new();
    for value in values {
        hash.update((value.len() as u64).to_le_bytes());
        hash.update(value.as_bytes());
    }
    SharedSetCacheKey {
        kind,
        key: key.to_owned(),
        len: values.len(),
        digest: hash.finalize().into(),
    }
}

fn shared_prefix_set_key(prefixes: &[IpPrefix]) -> SharedSetCacheKey {
    let mut hash = Sha256::new();
    for prefix in prefixes {
        hash.update(prefix.addr.to_string().as_bytes());
        hash.update([0]);
        hash.update([prefix.bits]);
    }
    SharedSetCacheKey {
        kind: "prefix",
        key: String::new(),
        len: prefixes.len(),
        digest: hash.finalize().into(),
    }
}

pub(super) fn geodata_report_json(report: &GeodataResolutionReport) -> Value {
    let lookup_count = report.lookups.len();
    let asset_cache_hit_count = report
        .lookups
        .iter()
        .filter(|lookup| lookup.asset_cache_hit)
        .count();
    let decoded_entry_cache_hit_count = report
        .lookups
        .iter()
        .filter(|lookup| lookup.decoded_entry_cache_hit)
        .count();
    let raw_file_bytes_read: usize = report
        .lookups
        .iter()
        .filter(|lookup| !lookup.asset_cache_hit)
        .map(|lookup| lookup.raw_file_bytes)
        .sum();
    let raw_file_bytes_seen: usize = report
        .lookups
        .iter()
        .map(|lookup| lookup.raw_file_bytes)
        .sum();
    let decoded_entry_bytes_sum: usize = report
        .lookups
        .iter()
        .map(|lookup| lookup.decoded_entry_bytes)
        .sum();
    let expanded_string_bytes_sum: usize = report
        .lookups
        .iter()
        .map(|lookup| lookup.expanded_string_bytes)
        .sum();
    json!({
        "lookup_count": lookup_count,
        "asset_read_count": lookup_count.saturating_sub(asset_cache_hit_count),
        "asset_cache_hit_count": asset_cache_hit_count,
        "decoded_entry_cache_hit_count": decoded_entry_cache_hit_count,
        "raw_file_bytes_read": raw_file_bytes_read,
        "raw_file_bytes_seen": raw_file_bytes_seen,
        "decoded_entry_bytes_sum": decoded_entry_bytes_sum,
        "expanded_string_bytes_sum": expanded_string_bytes_sum,
        "lookups": report.lookups.iter().map(|lookup| {
            json!({
                "kind": lookup.kind,
                "filename": &lookup.filename,
                "code": &lookup.code,
                "attr": &lookup.attr,
                "path": lookup.path.as_ref().map(|path| path.display().to_string()),
                "decode_ok": lookup.decode_ok,
                "fallback_ok": lookup.fallback_ok,
                "output_count": lookup.output_count,
                "raw_file_bytes": lookup.raw_file_bytes,
                "decoded_entry_bytes": lookup.decoded_entry_bytes,
                "expanded_string_bytes": lookup.expanded_string_bytes,
                "asset_cache_hit": lookup.asset_cache_hit,
                "decoded_entry_cache_hit": lookup.decoded_entry_cache_hit,
            })
        }).collect::<Vec<_>>(),
    })
}
