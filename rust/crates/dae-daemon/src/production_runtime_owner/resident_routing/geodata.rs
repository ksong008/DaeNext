use std::{
    env, fs,
    path::{Path, PathBuf},
};

use dae_config::Param;
use dae_geodata::{DomainType, load_geoip_bytes, load_geosite_bytes};
use serde_json::{Value, json};

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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct GeodataResolver {
    asset_dirs: Vec<PathBuf>,
}

pub(super) fn load_geoip_params(
    resolver: &GeodataResolver,
    filename: &str,
    code: &str,
    geodata_report: &mut GeodataResolutionReport,
) -> Result<Vec<Param>, String> {
    let filename = dat_filename(filename);
    let (path, data) = resolver.read_asset(&filename)?;
    let loaded = load_geoip_bytes(&data, code).map_err(|err| {
        format!(
            "load geoip {filename}:{code} from {}: {err}",
            path.display()
        )
    })?;
    if loaded.value.inverse_match {
        return Err("not support inverse match yet".to_owned());
    }
    let output_count = loaded.value.cidrs.len();
    geodata_report.lookups.push(GeodataLookup {
        kind: "geoip",
        filename,
        code: code.to_owned(),
        attr: None,
        path: Some(path),
        decode_ok: loaded.decode_ok,
        fallback_ok: loaded.fallback_ok,
        output_count,
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
    let (path, data) = resolver.read_asset(&filename)?;
    let loaded = load_geosite_bytes(&data, &code).map_err(|err| {
        format!(
            "load geosite {filename}:{code} from {}: {err}",
            path.display()
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
    geodata_report.lookups.push(GeodataLookup {
        kind: "geosite",
        filename,
        code,
        attr,
        path: Some(path),
        decode_ok: loaded.decode_ok,
        fallback_ok: loaded.fallback_ok,
        output_count: params.len(),
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
    pub(super) fn new(asset_dirs: impl IntoIterator<Item = impl Into<PathBuf>>) -> Self {
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
        Self { asset_dirs: dirs }
    }

    fn read_asset(&self, filename: &str) -> Result<(PathBuf, Vec<u8>), String> {
        let filename_path = Path::new(filename);
        if filename_path.is_absolute() && filename_path.is_file() {
            return fs::read(filename_path)
                .map(|data| (filename_path.to_path_buf(), data))
                .map_err(|err| format!("read geodata asset {}: {err}", filename_path.display()));
        }
        for dir in &self.asset_dirs {
            let path = dir.join(filename);
            if !path.is_file() {
                continue;
            }
            return fs::read(&path)
                .map(|data| (path.clone(), data))
                .map_err(|err| format!("read geodata asset {}: {err}", path.display()));
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
}

pub(super) fn geodata_report_json(report: &GeodataResolutionReport) -> Value {
    json!({
        "lookup_count": report.lookups.len(),
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
            })
        }).collect::<Vec<_>>(),
        "source": [
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:24.2",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:24.4",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:27.8"
        ],
    })
}
