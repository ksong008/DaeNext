#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UtlsTemplateMode {
    ExactFixture,
    FamilyApproximation,
    Randomized,
    UnsupportedExactTemplate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UtlsTemplateFamily {
    Chrome,
    Edge,
    Firefox,
    Safari,
    Ios,
    Android,
    Random,
    Browser360,
    Qq,
    Other(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UtlsTemplateValue {
    Exact(String),
    Grease,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UtlsServerNameTemplate {
    Absent,
    Dynamic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UtlsAlpnTemplate {
    Absent,
    DynamicList(Vec<String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UtlsSessionIdTemplate {
    pub len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UtlsPaddingTemplate {
    Absent,
    TargetHandshakeLen(usize),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UtlsTemplateProfile {
    pub fingerprint_name: String,
    pub canonical_name: String,
    pub family: UtlsTemplateFamily,
    pub mode: UtlsTemplateMode,
    pub record_content_type: String,
    pub record_version: String,
    pub record_len: usize,
    pub handshake_type: String,
    pub handshake_len: usize,
    pub legacy_version: String,
    pub random_len: usize,
    pub session_id: UtlsSessionIdTemplate,
    pub cipher_suites: Vec<UtlsTemplateValue>,
    pub compression_methods: Vec<UtlsTemplateValue>,
    pub extension_types: Vec<UtlsTemplateValue>,
    pub sni: UtlsServerNameTemplate,
    pub alpn: UtlsAlpnTemplate,
    pub supported_versions: Vec<UtlsTemplateValue>,
    pub supported_groups: Vec<UtlsTemplateValue>,
    pub ec_point_formats: Vec<UtlsTemplateValue>,
    pub signature_schemes: Vec<UtlsTemplateValue>,
    pub key_share_groups: Vec<UtlsTemplateValue>,
    pub padding: UtlsPaddingTemplate,
}

impl UtlsTemplateValue {
    pub fn exact(value: impl Into<String>) -> Self {
        Self::Exact(value.into())
    }

    pub fn is_grease(&self) -> bool {
        matches!(self, Self::Grease)
    }
}
