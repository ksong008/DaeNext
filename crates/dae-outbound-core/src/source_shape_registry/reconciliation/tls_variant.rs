use super::{MaterializedSecurity, MaterializedSourceShape, MaterializedTlsFeatures};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MaterializedTlsVariant {
    pub security: MaterializedSecurity,
    pub features: MaterializedTlsFeatures,
}

impl MaterializedTlsVariant {
    pub const fn new(security: MaterializedSecurity, features: MaterializedTlsFeatures) -> Self {
        Self { security, features }
    }
}

impl MaterializedSourceShape {
    pub const fn tls_variant(self) -> MaterializedTlsVariant {
        MaterializedTlsVariant::new(self.security, self.tls_features)
    }
}
