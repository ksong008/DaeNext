use std::{
    collections::BTreeMap,
    env, fs, io,
    ops::Range,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    ptr::NonNull,
    slice,
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicU64, Ordering},
    },
};

use dae_config::{Function, Param, RoutingRule};
use dae_geodata::{
    DomainType, decode_entry_range, load_geoip_bytes, load_geoip_entry_bytes, load_geosite_bytes,
    load_geosite_entry_bytes,
};
use dae_routing::{DomainKey, IpPrefix, SharedDomainSet, WeakSharedDomainSet};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const DAE_PRODUCT_DIR_NAME: &str = "dae";
const PRODUCT_BINARY_NAME: &str = "daed";

/// Upper bounds for the per-resolver geodata caches.
///
/// Reloads can otherwise accumulate memory monotonically: the asset cache pins
/// full `.dat` file mappings, the decoded-entry cache pins one entry per
/// (file, code) pair (each sharing the asset bytes through an `Arc`), and the
/// shared-set maps pin process-interner entries alive for as long as the
/// resolver lives. Capping each map and evicting the least-recently-used
/// entry bounds that memory; evicted shared sets stay reachable through the
/// routing plan/matcher Arcs, and their now-dead interner entries are
/// reclaimed on the next interner insert.
const GEODATA_ASSET_CACHE_MAX_ENTRIES: usize = 32; // each entry is a full .dat mapping
const GEODATA_DECODED_ENTRY_CACHE_MAX_ENTRIES: usize = 4096; // one per (file, code) decode
const GEODATA_SHARED_SET_CACHE_MAX_ENTRIES: usize = 4096; // one per distinct domain/prefix set

pub type SharedResidentIpPrefixSet = Arc<[IpPrefix]>;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GeodataResolutionReport {
    pub lookups: Vec<GeodataLookup>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeodataLookup {
    pub kind: &'static str,
    pub filename: String,
    pub code: String,
    pub attr: Option<String>,
    pub path: Option<PathBuf>,
    pub decode_ok: bool,
    pub fallback_ok: bool,
    pub output_count: usize,
    pub raw_file_bytes: usize,
    pub decoded_entry_bytes: usize,
    pub expanded_string_bytes: usize,
    pub asset_cache_hit: bool,
    pub decoded_entry_cache_hit: bool,
    pub asset_storage: &'static str,
}

#[derive(Debug)]
pub struct GeodataResolver {
    asset_dirs: Vec<PathBuf>,
    asset_cache: Mutex<BTreeMap<String, CachedGeodataAsset>>,
    decoded_entry_cache: Mutex<BTreeMap<DecodedEntryCacheKey, CachedDecodedEntry>>,
    shared_domain_sets: Mutex<BTreeMap<SharedSetCacheKey, (SharedDomainSet, u64)>>,
    shared_prefix_sets: Mutex<BTreeMap<SharedSetCacheKey, (SharedResidentIpPrefixSet, u64)>>,
    cache_tick: AtomicU64,
}

#[derive(Clone, Debug)]
struct CachedGeodataAsset {
    path: PathBuf,
    data: SharedGeodataBytes,
    last_used: u64,
}

#[derive(Clone, Debug)]
struct GeodataAsset {
    path: PathBuf,
    data: SharedGeodataBytes,
    cache_hit: bool,
}

#[derive(Clone, Debug)]
struct SharedGeodataBytes {
    inner: Arc<GeodataBytes>,
}

#[derive(Debug)]
enum GeodataBytes {
    Mmap(MmapGeodataBytes),
    Owned(Box<[u8]>),
}

#[derive(Debug)]
struct MmapGeodataBytes {
    ptr: NonNull<u8>,
    len: usize,
    file: fs::File,
}

// The mapping is read-only for the process lifetime covered by this value.
unsafe impl Send for MmapGeodataBytes {}
unsafe impl Sync for MmapGeodataBytes {}

impl SharedGeodataBytes {
    fn read(path: &Path) -> Result<Self, String> {
        match MmapGeodataBytes::map_file(path) {
            Ok(mapped) => Ok(Self {
                inner: Arc::new(GeodataBytes::Mmap(mapped)),
            }),
            Err(_) => {
                let data = fs::read(path)
                    .map_err(|err| format!("read geodata asset {}: {err}", path.display()))?;
                let _ = advise_file_dontneed(path);
                Ok(Self {
                    inner: Arc::new(GeodataBytes::Owned(data.into_boxed_slice())),
                })
            }
        }
    }

    fn as_slice(&self) -> &[u8] {
        match self.inner.as_ref() {
            GeodataBytes::Mmap(mapped) => mapped.as_slice(),
            GeodataBytes::Owned(data) => data,
        }
    }

    fn len(&self) -> usize {
        self.as_slice().len()
    }

    fn storage_kind(&self) -> &'static str {
        match self.inner.as_ref() {
            GeodataBytes::Mmap(_) => "mmap",
            GeodataBytes::Owned(_) => "owned",
        }
    }
}

impl MmapGeodataBytes {
    fn map_file(path: &Path) -> io::Result<Self> {
        let file = fs::File::open(path)?;
        let len_u64 = file.metadata()?.len();
        let len = usize::try_from(len_u64).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("geodata asset {} is too large to map", path.display()),
            )
        })?;
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("geodata asset {} is empty", path.display()),
            ));
        }
        let mapped = unsafe {
            // SAFETY: `file` is open for the duration of mmap creation, the mapping
            // is read-only/private, and the returned pointer/length are owned by
            // `MmapGeodataBytes` until `Drop` calls `munmap` exactly once.
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let ptr = NonNull::new(mapped.cast::<u8>())
            .ok_or_else(|| io::Error::other("mmap returned a null pointer"))?;
        Ok(Self { ptr, len, file })
    }

    fn as_slice(&self) -> &[u8] {
        unsafe {
            // SAFETY: `ptr` and `len` come from a successful immutable mmap and
            // stay valid until `Drop` unmaps them after the last shared reference.
            slice::from_raw_parts(self.ptr.as_ptr(), self.len)
        }
    }

    fn advise_dontneed(&self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        unsafe {
            // SAFETY: this advisory call covers the still-live immutable mapping
            // owned by this value. Failure is non-fatal and ignored by callers.
            let _ = libc::madvise(self.ptr.as_ptr().cast(), self.len, libc::MADV_DONTNEED);
        }
        advise_open_file_dontneed(&self.file)
    }
}

impl Drop for MmapGeodataBytes {
    fn drop(&mut self) {
        let _ = self.advise_dontneed();
        unsafe {
            // SAFETY: this value owns the mmap range and `Drop` runs once, so the
            // exact pointer/length returned by mmap are unmapped exactly once.
            libc::munmap(self.ptr.as_ptr().cast(), self.len);
        }
    }
}

fn advise_file_dontneed(path: &Path) -> io::Result<()> {
    let file = fs::File::open(path)?;
    advise_open_file_dontneed(&file)
}

fn advise_open_file_dontneed(file: &fs::File) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let rc = unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = file;
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DecodedEntryCacheKey {
    kind: &'static str,
    filename: String,
    code: String,
}

#[derive(Clone, Debug)]
struct CachedDecodedEntry {
    asset: SharedGeodataBytes,
    range: Range<usize>,
    last_used: u64,
}

#[derive(Clone, Debug)]
struct DecodedEntry {
    asset: SharedGeodataBytes,
    range: Range<usize>,
    cache_hit: bool,
}

impl DecodedEntry {
    fn as_slice(&self) -> &[u8] {
        &self.asset.as_slice()[self.range.clone()]
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SharedSetCacheKey {
    kind: &'static str,
    key: String,
    len: usize,
    digest: [u8; 32],
}

fn shared_domain_set_interner() -> &'static Mutex<BTreeMap<SharedSetCacheKey, WeakSharedDomainSet>>
{
    static INTERNER: OnceLock<Mutex<BTreeMap<SharedSetCacheKey, WeakSharedDomainSet>>> =
        OnceLock::new();
    INTERNER.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn shared_prefix_set_interner() -> &'static Mutex<BTreeMap<SharedSetCacheKey, Weak<[IpPrefix]>>> {
    static INTERNER: OnceLock<Mutex<BTreeMap<SharedSetCacheKey, Weak<[IpPrefix]>>>> =
        OnceLock::new();
    INTERNER.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(crate) fn expand_resident_dns_request_qname_rules_with_resolver(
    rules: &[RoutingRule],
    resolver: &GeodataResolver,
) -> Result<Vec<RoutingRule>, String> {
    expand_resident_dns_qname_rules_with_resolver(rules, resolver, "dns.routing.request qname")
}

pub(crate) fn expand_resident_dns_response_qname_rules_with_resolver(
    rules: &[RoutingRule],
    resolver: &GeodataResolver,
) -> Result<Vec<RoutingRule>, String> {
    expand_resident_dns_qname_rules_with_resolver(rules, resolver, "dns.routing.response qname")
}

fn expand_resident_dns_qname_rules_with_resolver(
    rules: &[RoutingRule],
    resolver: &GeodataResolver,
    context: &str,
) -> Result<Vec<RoutingRule>, String> {
    let mut geodata_report = GeodataResolutionReport::default();
    let mut rules = rules.to_vec();
    for rule in &mut rules {
        for function in &mut rule.and_functions {
            if function.name != "qname" {
                continue;
            }
            expand_resident_dns_qname_function(function, resolver, &mut geodata_report, context)?;
        }
    }
    Ok(rules)
}

fn expand_resident_dns_qname_function(
    function: &mut Function,
    resolver: &GeodataResolver,
    geodata_report: &mut GeodataResolutionReport,
    context: &str,
) -> Result<(), String> {
    let mut expanded = Vec::new();
    for param in &function.params {
        match param.key.as_str() {
            "geosite" => {
                expanded.extend(load_geosite_params(
                    resolver,
                    "geosite",
                    &param.val,
                    geodata_report,
                )?);
            }
            "ext" => {
                let (filename, code) = param.val.split_once(':').ok_or_else(|| {
                    format!(
                        "{context} ext parameter must be file:code, got {}",
                        param.val
                    )
                })?;
                expanded.extend(load_geosite_params(
                    resolver,
                    filename,
                    code,
                    geodata_report,
                )?);
            }
            "geoip" => {
                return Err(format!(
                    "{context} cannot use geoip parameters; use geosite or ext geosite data"
                ));
            }
            _ => expanded.push(param.clone()),
        }
    }
    function.params = expanded;
    Ok(())
}

pub(crate) fn expand_resident_dns_response_ip_params_with_resolver(
    params: &[Param],
    resolver: &GeodataResolver,
) -> Result<Vec<Param>, String> {
    let mut geodata_report = GeodataResolutionReport::default();
    let mut expanded = Vec::new();
    for param in params {
        match param.key.as_str() {
            "geoip" => expanded.extend(load_geoip_params(
                resolver,
                "geoip",
                &param.val,
                &mut geodata_report,
            )?),
            "ext" => {
                let (filename, code) = param.val.split_once(':').ok_or_else(|| {
                    format!(
                        "dns.routing.response ip ext parameter must be file:code, got {}",
                        param.val
                    )
                })?;
                expanded.extend(load_geoip_params(
                    resolver,
                    filename,
                    code,
                    &mut geodata_report,
                )?);
            }
            _ => expanded.push(param.clone()),
        }
    }
    Ok(expanded)
}

pub(crate) fn load_geoip_params(
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
        None => load_geoip_bytes(asset.data.as_slice(), code),
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
        asset_storage: asset.data.storage_kind(),
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

pub(crate) fn load_geosite_params(
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
        None => load_geosite_bytes(asset.data.as_slice(), &code),
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
        asset_storage: asset.data.storage_kind(),
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

fn product_geodata_dir_names(product_binary_name: &str) -> Vec<String> {
    let primary = if product_binary_name.is_empty() {
        DAE_PRODUCT_DIR_NAME
    } else {
        product_binary_name
    };
    vec![primary.to_owned()]
}

fn product_system_geodata_dirs(product_binary_name: &str) -> Vec<PathBuf> {
    product_geodata_dir_names(product_binary_name)
        .into_iter()
        .flat_map(|name| {
            [
                PathBuf::from(format!("/etc/{name}")),
                PathBuf::from(format!("/usr/local/share/{name}")),
                PathBuf::from(format!("/usr/share/{name}")),
            ]
        })
        .collect()
}

fn product_xdg_geodata_dirs(product_binary_name: &str) -> Vec<PathBuf> {
    let product_names = product_geodata_dir_names(product_binary_name);
    let mut dirs = Vec::new();
    if let Ok(data_home) = env::var("XDG_DATA_HOME") {
        dirs.extend(
            product_names
                .iter()
                .map(|name| PathBuf::from(&data_home).join(name)),
        );
    } else if let Ok(home) = env::var("HOME") {
        dirs.extend(
            product_names
                .iter()
                .map(|name| PathBuf::from(&home).join(".local/share").join(name)),
        );
    }
    if let Ok(data_dirs) = env::var("XDG_DATA_DIRS") {
        dirs.extend(
            data_dirs
                .split(':')
                .filter(|dir| !dir.is_empty())
                .flat_map(|dir| {
                    product_names
                        .iter()
                        .map(move |name| PathBuf::from(dir).join(name))
                }),
        );
    }
    dirs
}

impl GeodataResolver {
    pub fn new(asset_dirs: impl IntoIterator<Item = impl Into<PathBuf>>) -> Self {
        let mut dirs = Vec::new();
        if let Ok(dir) = env::var("DAE_LOCATION_ASSET")
            && !dir.is_empty()
        {
            dirs.push(PathBuf::from(dir));
        }
        dirs.extend(asset_dirs.into_iter().map(Into::into));
        dirs.extend(product_system_geodata_dirs(PRODUCT_BINARY_NAME));
        dirs.extend(product_xdg_geodata_dirs(PRODUCT_BINARY_NAME));
        dirs.dedup();
        Self {
            asset_dirs: dirs,
            asset_cache: Mutex::new(BTreeMap::new()),
            decoded_entry_cache: Mutex::new(BTreeMap::new()),
            shared_domain_sets: Mutex::new(BTreeMap::new()),
            shared_prefix_sets: Mutex::new(BTreeMap::new()),
            cache_tick: AtomicU64::new(1),
        }
    }

    /// Monotonic LRU tick shared by all resolver caches. Never returns 0 so a
    /// fresh entry can never collide with an entry's initial `last_used`.
    fn next_cache_tick(&self) -> u64 {
        self.cache_tick.fetch_add(1, Ordering::Relaxed).max(1)
    }

    /// Evict the least-recently-used entry while `map` holds more than `cap`
    /// entries. O(n) per eviction, which is fine: these caches are only
    /// touched during config/geodata resolution, never on the packet path.
    fn evict_lru_entries<K: Ord + Clone, V>(
        &self,
        map: &mut BTreeMap<K, V>,
        cap: usize,
        last_used_of: impl Fn(&V) -> u64,
    ) {
        while map.len() > cap {
            let Some(oldest) = map
                .iter()
                .min_by_key(|(_, value)| last_used_of(value))
                .map(|(key, _)| (*key).clone())
            else {
                break;
            };
            map.remove(&oldest);
        }
    }

    pub(crate) fn shared_domain_set(
        &self,
        key: &str,
        values: Vec<String>,
    ) -> Result<SharedDomainSet, String> {
        let key = DomainKey::try_from(key)
            .map_err(|err| format!("resident shared domain set key: {err}"))?;
        let cache_key = shared_string_set_key("domain", domain_key_name(key), &values);
        if let Some((cached, last_used)) = self
            .shared_domain_sets
            .lock()
            .map_err(|_| "geodata shared domain set cache lock poisoned".to_owned())?
            .get_mut(&cache_key)
        {
            *last_used = self.next_cache_tick();
            return Ok(cached.clone());
        }
        if key == DomainKey::Regex {
            // `regex::Regex` and `RegexSet` own lazy hybrid-DFA cache pools. Those pools retain
            // one cache for every OS thread that has used the matcher. A physical reload replaces
            // the Tokio worker threads, so process-wide interning of the complete regex object
            // made each reload permanently add caches for the dead worker generation. Keep regex
            // sets shared within one resolver/generation, but give every physical generation a
            // fresh cache owner so dropping the generation also drops its retired-thread caches.
            let built = SharedDomainSet::from_vec(values, key)
                .map_err(|err| format!("build shared resident domain set: {err}"))?;
            self.cache_shared_domain_set(cache_key, built.clone())?;
            return Ok(built);
        }
        if let Some(shared) = shared_domain_set_interner()
            .lock()
            .map_err(|_| "process shared domain set interner lock poisoned".to_owned())?
            .get(&cache_key)
            .and_then(WeakSharedDomainSet::upgrade)
        {
            self.cache_shared_domain_set(cache_key, shared.clone())?;
            return Ok(shared);
        }
        let built = SharedDomainSet::from_vec(values, key)
            .map_err(|err| format!("build shared resident domain set: {err}"))?;
        let shared = {
            let mut interner = shared_domain_set_interner()
                .lock()
                .map_err(|_| "process shared domain set interner lock poisoned".to_owned())?;
            interner.retain(|_, shared| shared.upgrade().is_some());
            if let Some(shared) = interner
                .get(&cache_key)
                .and_then(WeakSharedDomainSet::upgrade)
            {
                shared
            } else {
                interner.insert(cache_key.clone(), built.downgrade());
                built
            }
        };
        self.cache_shared_domain_set(cache_key, shared.clone())?;
        Ok(shared)
    }

    /// Insert a shared domain set into the resolver's strong cache, evicting
    /// the least-recently-used entry when the cache is at its cap. Evicting the
    /// resolver's strong reference lets the process interner reclaim its weak
    /// entry (the set stays alive through routing-plan/matcher Arcs).
    fn cache_shared_domain_set(
        &self,
        cache_key: SharedSetCacheKey,
        set: SharedDomainSet,
    ) -> Result<(), String> {
        let mut cache = self
            .shared_domain_sets
            .lock()
            .map_err(|_| "geodata shared domain set cache lock poisoned".to_owned())?;
        cache.insert(cache_key, (set, self.next_cache_tick()));
        self.evict_lru_entries(
            &mut cache,
            GEODATA_SHARED_SET_CACHE_MAX_ENTRIES,
            |(_, last_used)| *last_used,
        );
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn shared_domain_set_for_test(
        &self,
        key: &str,
        values: Vec<String>,
    ) -> Result<SharedDomainSet, String> {
        self.shared_domain_set(key, values)
    }

    pub(crate) fn shared_prefix_set(
        &self,
        prefixes: Vec<IpPrefix>,
    ) -> Result<SharedResidentIpPrefixSet, String> {
        let cache_key = shared_prefix_set_key(&prefixes);
        if let Some((cached, last_used)) = self
            .shared_prefix_sets
            .lock()
            .map_err(|_| "geodata shared prefix set cache lock poisoned".to_owned())?
            .get_mut(&cache_key)
        {
            *last_used = self.next_cache_tick();
            return Ok(Arc::clone(cached));
        }
        if let Some(shared) = shared_prefix_set_interner()
            .lock()
            .map_err(|_| "process shared prefix set interner lock poisoned".to_owned())?
            .get(&cache_key)
            .and_then(Weak::upgrade)
        {
            self.cache_shared_prefix_set(cache_key, Arc::clone(&shared))?;
            return Ok(shared);
        }
        let built: SharedResidentIpPrefixSet = Arc::from(prefixes);
        let shared = {
            let mut interner = shared_prefix_set_interner()
                .lock()
                .map_err(|_| "process shared prefix set interner lock poisoned".to_owned())?;
            interner.retain(|_, shared| shared.strong_count() > 0);
            if let Some(shared) = interner.get(&cache_key).and_then(Weak::upgrade) {
                shared
            } else {
                interner.insert(cache_key.clone(), Arc::downgrade(&built));
                built
            }
        };
        self.cache_shared_prefix_set(cache_key, Arc::clone(&shared))?;
        Ok(shared)
    }

    /// Insert a shared prefix set into the resolver's strong cache with the
    /// same cap/eviction as `cache_shared_domain_set`.
    fn cache_shared_prefix_set(
        &self,
        cache_key: SharedSetCacheKey,
        set: SharedResidentIpPrefixSet,
    ) -> Result<(), String> {
        let mut cache = self
            .shared_prefix_sets
            .lock()
            .map_err(|_| "geodata shared prefix set cache lock poisoned".to_owned())?;
        cache.insert(cache_key, (set, self.next_cache_tick()));
        self.evict_lru_entries(
            &mut cache,
            GEODATA_SHARED_SET_CACHE_MAX_ENTRIES,
            |(_, last_used)| *last_used,
        );
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn shared_domain_set_count(&self) -> usize {
        self.shared_domain_sets
            .lock()
            .expect("shared domain set cache lock")
            .len()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn shared_prefix_set_count(&self) -> usize {
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
            .get_mut(filename)
        {
            cached.last_used = self.next_cache_tick();
            return Ok(GeodataAsset {
                path: cached.path.clone(),
                data: cached.data.clone(),
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
        let data = SharedGeodataBytes::read(path)?;
        let cached = CachedGeodataAsset {
            path: path.to_path_buf(),
            data,
            last_used: self.next_cache_tick(),
        };
        let mut cache = self
            .asset_cache
            .lock()
            .map_err(|_| "geodata asset cache lock poisoned".to_owned())?;
        cache.insert(cache_key.to_owned(), cached.clone());
        self.evict_lru_entries(&mut cache, GEODATA_ASSET_CACHE_MAX_ENTRIES, |entry| {
            entry.last_used
        });
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
            .get_mut(&key)
        {
            cached.last_used = self.next_cache_tick();
            return Ok(Some(DecodedEntry {
                asset: cached.asset.clone(),
                range: cached.range.clone(),
                cache_hit: true,
            }));
        }

        let Ok(range) = decode_entry_range(asset.data.as_slice(), code) else {
            return Ok(None);
        };
        let cached = CachedDecodedEntry {
            asset: asset.data.clone(),
            range,
            last_used: self.next_cache_tick(),
        };
        let mut cache = self
            .decoded_entry_cache
            .lock()
            .map_err(|_| "geodata decoded-entry cache lock poisoned".to_owned())?;
        cache.insert(key, cached.clone());
        self.evict_lru_entries(
            &mut cache,
            GEODATA_DECODED_ENTRY_CACHE_MAX_ENTRIES,
            |entry| entry.last_used,
        );
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
        hash.update(prefix.addr().to_string().as_bytes());
        hash.update([0]);
        hash.update([prefix.bits()]);
    }
    SharedSetCacheKey {
        kind: "prefix",
        key: String::new(),
        len: prefixes.len(),
        digest: hash.finalize().into(),
    }
}

pub fn geodata_report_json(report: &GeodataResolutionReport) -> Value {
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
                "asset_storage": lookup.asset_storage,
            })
        }).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAED_PRODUCT_DIR_NAME: &str = "daed";

    #[test]
    fn geodata_product_dirs_for_daed_prioritize_daed_scope() {
        assert_eq!(
            product_system_geodata_dirs(DAED_PRODUCT_DIR_NAME),
            vec![
                PathBuf::from("/etc/daed"),
                PathBuf::from("/usr/local/share/daed"),
                PathBuf::from("/usr/share/daed"),
            ]
        );
    }

    #[test]
    fn geodata_product_dirs_for_dae_stay_dae_scoped() {
        assert_eq!(
            product_system_geodata_dirs(DAE_PRODUCT_DIR_NAME),
            vec![
                PathBuf::from("/etc/dae"),
                PathBuf::from("/usr/local/share/dae"),
                PathBuf::from("/usr/share/dae"),
            ]
        );
    }

    #[test]
    fn lru_eviction_bounds_a_cache_and_drops_the_oldest_entry() {
        let resolver = GeodataResolver::new(Vec::<PathBuf>::new());
        let mut map = BTreeMap::new();
        for index in 0..8_u64 {
            map.insert(format!("k{index}"), (format!("v{index}"), index));
        }
        resolver.evict_lru_entries(&mut map, 4, |(_, last_used)| *last_used);
        assert_eq!(map.len(), 4);
        assert!(!map.contains_key("k0"), "oldest entry evicted");
        assert!(map.contains_key("k7"), "newest entry retained");
    }

    #[test]
    fn lru_eviction_spares_recently_touched_entries() {
        let resolver = GeodataResolver::new(Vec::<PathBuf>::new());
        let mut map = BTreeMap::new();
        for index in 0..8_u64 {
            map.insert(format!("k{index}"), (format!("v{index}"), index));
        }
        // Touch k0 with a tick strictly newer than every entry so it becomes
        // the most recently used (entry ticks start at 0..7).
        map.get_mut("k0").unwrap().1 = resolver.next_cache_tick() + 64;
        resolver.evict_lru_entries(&mut map, 4, |(_, last_used)| *last_used);
        assert_eq!(map.len(), 4);
        assert!(map.contains_key("k0"), "touched entry survives");
        for evicted in ["k1", "k2", "k3", "k4"] {
            assert!(!map.contains_key(evicted), "{evicted} is the oldest");
        }
        for retained in ["k5", "k6", "k7"] {
            assert!(map.contains_key(retained), "{retained} must survive");
        }
    }

    #[test]
    fn asset_cache_is_capped_and_evicts_least_recently_used() {
        let root =
            std::env::temp_dir().join(format!("daed-geodata-asset-cap-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let resolver = GeodataResolver::new([root.clone()]);
        for index in 0..(GEODATA_ASSET_CACHE_MAX_ENTRIES + 8) {
            let filename = format!("asset-{index}.dat");
            fs::write(root.join(&filename), b"raw").unwrap();
            let asset = resolver.read_asset(&filename).unwrap();
            assert!(!asset.cache_hit, "freshly written asset must miss");
        }
        let first_evicted = {
            let cached = resolver.asset_cache.lock().unwrap();
            assert!(
                cached.len() <= GEODATA_ASSET_CACHE_MAX_ENTRIES,
                "asset cache must stay at its cap: {}",
                cached.len()
            );
            assert!(
                !cached.contains_key("asset-0.dat"),
                "least-recently-used asset must be evicted"
            );
            !cached.contains_key("asset-0.dat")
        };
        assert!(first_evicted);
        // A repeat read of a surviving asset is served from the cache.
        assert!(
            resolver.read_asset("asset-8.dat").unwrap().cache_hit,
            "surviving asset must be served from cache"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn shared_domain_set_strong_cache_reuses_and_evicts_lru() {
        let resolver = GeodataResolver::new(Vec::<PathBuf>::new());
        let first = resolver
            .shared_domain_set_for_test("full", vec!["first.example".to_owned()])
            .unwrap();
        let first_again = resolver
            .shared_domain_set_for_test("full", vec!["first.example".to_owned()])
            .unwrap();
        assert!(
            first.ptr_eq(&first_again),
            "strong cache must reuse the same set"
        );
        // Distinct sets beyond the cap evict the least-recently-used strong
        // reference; the set itself stays reachable through our Arc.
        for index in 0..(GEODATA_SHARED_SET_CACHE_MAX_ENTRIES + 8) {
            let _ = resolver
                .shared_domain_set_for_test("full", vec![format!("set-{index}.example")])
                .unwrap();
        }
        assert!(
            resolver.shared_domain_set_count() <= GEODATA_SHARED_SET_CACHE_MAX_ENTRIES,
            "strong set cache must stay at its cap"
        );
        assert!(first.ptr_eq(&first_again));
    }
}
