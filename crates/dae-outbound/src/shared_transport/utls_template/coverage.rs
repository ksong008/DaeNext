use super::UtlsTemplateMode;
use crate::OutboundError;
use crate::shared_transport::{
    SUPPORTED_UTLS_FINGERPRINTS, UtlsFingerprint, resolve_utls_client_hello_id,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UtlsTemplateCoverage {
    pub supported_fingerprints: usize,
    pub exact_fixtures: usize,
    pub family_approximations: usize,
    pub randomized: usize,
    pub unsupported_exact_templates: usize,
}

pub fn resolve_utls_template_mode(name: &str) -> Result<UtlsTemplateMode, OutboundError> {
    resolve_utls_client_hello_id(name).map(|fingerprint| utls_template_mode(&fingerprint))
}

pub fn utls_template_coverage() -> UtlsTemplateCoverage {
    SUPPORTED_UTLS_FINGERPRINTS.iter().fold(
        UtlsTemplateCoverage::default(),
        |mut coverage, fingerprint| {
            coverage.supported_fingerprints += 1;
            match utls_template_mode(fingerprint) {
                UtlsTemplateMode::ExactFixture => coverage.exact_fixtures += 1,
                UtlsTemplateMode::FamilyApproximation => coverage.family_approximations += 1,
                UtlsTemplateMode::Randomized => coverage.randomized += 1,
                UtlsTemplateMode::UnsupportedExactTemplate => {
                    coverage.unsupported_exact_templates += 1;
                }
            }
            coverage
        },
    )
}

pub fn utls_template_mode_label(mode: UtlsTemplateMode) -> &'static str {
    match mode {
        UtlsTemplateMode::ExactFixture => "ExactFixture",
        UtlsTemplateMode::FamilyApproximation => "FamilyApproximation",
        UtlsTemplateMode::Randomized => "Randomized",
        UtlsTemplateMode::UnsupportedExactTemplate => "UnsupportedExactTemplate",
    }
}

fn utls_template_mode(fingerprint: &UtlsFingerprint) -> UtlsTemplateMode {
    if fingerprint.randomized {
        UtlsTemplateMode::Randomized
    } else {
        UtlsTemplateMode::FamilyApproximation
    }
}

impl Default for UtlsTemplateCoverage {
    fn default() -> Self {
        Self {
            supported_fingerprints: 0,
            exact_fixtures: 0,
            family_approximations: 0,
            randomized: 0,
            unsupported_exact_templates: 0,
        }
    }
}
