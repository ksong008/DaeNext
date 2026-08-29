pub const GEOSITE_FILE: &str = "geosite.dat";
pub const GEOIP_FILE: &str = "geoip.dat";
const GEOSITE_DEFAULT_SOURCE_URL: &str =
    "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat";
const GEOIP_DEFAULT_SOURCE_URL: &str =
    "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat";
const GEOSITE_RELEASE_API_URL: &str =
    "https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases/latest";
const GEOIP_RELEASE_API_URL: &str =
    "https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases/latest";
pub const GEODATA_HTTP_HEADER_LIMIT: usize = 64 * 1024;
pub const GEODATA_HTTP_BODY_LIMIT: usize = 64 * 1024 * 1024;
pub const GEODATA_REDIRECT_LIMIT: usize = 5;

mod admission;
mod commit;
mod file;
mod helper;
mod http_wire;
mod source;
mod status;
mod status_cache;
mod transaction;
mod update;

pub use admission::*;
pub use commit::*;
pub use file::*;
pub use helper::*;
pub use http_wire::*;
pub use source::*;
pub use status::*;
pub use status_cache::*;
pub use transaction::*;
pub use update::*;

pub struct GeodataRelease {
    pub version: Option<String>,
    pub download_url: url::Url,
}

pub struct GeodataFileDownload {
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug)]
pub struct GeodataSource {
    pub url: url::Url,
    pub mode: GeodataSourceMode,
    pub use_proxy: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeodataSourceMode {
    ReleaseApi,
    DirectFile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeodataKind {
    Geosite,
    Geoip,
}

impl GeodataKind {
    pub fn file_name(self) -> &'static str {
        match self {
            Self::Geosite => GEOSITE_FILE,
            Self::Geoip => GEOIP_FILE,
        }
    }

    pub fn default_source_url(self) -> &'static str {
        match self {
            Self::Geosite => GEOSITE_DEFAULT_SOURCE_URL,
            Self::Geoip => GEOIP_DEFAULT_SOURCE_URL,
        }
    }

    pub fn legacy_release_api_url(self) -> &'static str {
        match self {
            Self::Geosite => GEOSITE_RELEASE_API_URL,
            Self::Geoip => GEOIP_RELEASE_API_URL,
        }
    }

    pub fn version_file_name(self) -> String {
        format!("{}.version", self.file_name())
    }

    pub fn response_key(self) -> &'static str {
        match self {
            Self::Geosite => "geosite",
            Self::Geoip => "geoip",
        }
    }

    pub fn summarize(
        self,
        data: &[u8],
    ) -> Result<dae_geodata::GeoDataSummary, dae_geodata::GeoDataError> {
        match self {
            Self::Geosite => dae_geodata::summarize_geosite_bytes(data),
            Self::Geoip => dae_geodata::summarize_geoip_bytes(data),
        }
    }
}

impl GeodataSourceMode {
    pub fn response_key(self) -> &'static str {
        match self {
            Self::ReleaseApi => "release",
            Self::DirectFile => "direct",
        }
    }
}
