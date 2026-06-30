mod coverage;
mod model;
mod normalize;
mod runtime;

pub use coverage::{
    UtlsTemplateCoverage, resolve_utls_template_mode, utls_template_coverage,
    utls_template_mode_label,
};
pub use model::{
    UtlsAlpnTemplate, UtlsPaddingTemplate, UtlsServerNameTemplate, UtlsSessionIdTemplate,
    UtlsTemplateFamily, UtlsTemplateMode, UtlsTemplateProfile, UtlsTemplateValue,
};
pub use normalize::normalize_utls_template_profile;
pub use runtime::{
    UTLS_TEMPLATE_GREASE, UtlsRuntimeTemplate, UtlsRuntimeTemplateCapabilities,
    resolve_utls_runtime_template,
};
