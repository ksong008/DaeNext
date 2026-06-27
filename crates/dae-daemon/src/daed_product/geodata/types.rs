pub(super) const GEOSITE_FILE: &str = "geosite.dat";
pub(super) const GEOIP_FILE: &str = "geoip.dat";
const GEOSITE_DEFAULT_SOURCE_URL: &str =
    "https://fastly.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat";
const GEOIP_DEFAULT_SOURCE_URL: &str =
    "https://fastly.jsdelivr.net/gh/Loyalsoldier/geoip@release/geoip.dat";
const GEOSITE_RELEASE_API_URL: &str =
    "https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases/latest";
const GEOIP_RELEASE_API_URL: &str =
    "https://api.github.com/repos/Loyalsoldier/geoip/releases/latest";
pub(super) const GEODATA_HTTP_HEADER_LIMIT: usize = 64 * 1024;
pub(super) const GEODATA_HTTP_BODY_LIMIT: usize = 64 * 1024 * 1024;
pub(super) const GEODATA_REDIRECT_LIMIT: usize = 5;

pub(super) struct GeodataRelease {
    pub(super) version: String,
    pub(super) download_url: url::Url,
}

pub(super) struct GeodataFileDownload {
    pub(super) bytes: u64,
    pub(super) sha256: String,
}

#[derive(Clone, Debug)]
pub(super) struct GeodataSource {
    pub(super) url: url::Url,
    pub(super) mode: GeodataSourceMode,
    pub(super) use_proxy: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GeodataSourceMode {
    ReleaseApi,
    DirectFile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::daed_product) enum GeodataKind {
    Geosite,
    Geoip,
}

impl GeodataKind {
    pub(super) fn file_name(self) -> &'static str {
        match self {
            Self::Geosite => GEOSITE_FILE,
            Self::Geoip => GEOIP_FILE,
        }
    }

    pub(super) fn default_source_url(self) -> &'static str {
        match self {
            Self::Geosite => GEOSITE_DEFAULT_SOURCE_URL,
            Self::Geoip => GEOIP_DEFAULT_SOURCE_URL,
        }
    }

    pub(super) fn legacy_release_api_url(self) -> &'static str {
        match self {
            Self::Geosite => GEOSITE_RELEASE_API_URL,
            Self::Geoip => GEOIP_RELEASE_API_URL,
        }
    }

    pub(super) fn version_file_name(self) -> String {
        format!("{}.version", self.file_name())
    }

    pub(super) fn response_key(self) -> &'static str {
        match self {
            Self::Geosite => "geosite",
            Self::Geoip => "geoip",
        }
    }

    pub(super) fn summarize(
        self,
        data: &[u8],
    ) -> Result<dae_geodata::GeoDataSummary, dae_geodata::GeoDataError> {
        match self {
            Self::Geosite => dae_geodata::summarize_geosite_bytes(data),
            Self::Geoip => dae_geodata::summarize_geoip_bytes(data),
        }
    }
}
