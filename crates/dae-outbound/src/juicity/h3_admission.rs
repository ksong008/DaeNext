pub const QUINN_VERSION: &str = "0.11.9";
pub const H3_VERSION: &str = "0.0.8";
pub const H3_QUINN_VERSION: &str = "0.0.10";
pub const TOKIO_VERSION: &str = "1.52.3";
pub const QUINN_FEATURES: &[&str] = &["runtime-tokio"];
pub const QUINN_CRYPTO_PROVIDER: &str = "quinn-boring";
pub const TOKIO_FEATURES: &[&str] = &["rt", "net", "time", "io-util", "sync"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JuicityH3DependencyAdmission {
    pub quinn_version: &'static str,
    pub h3_version: &'static str,
    pub h3_quinn_version: &'static str,
    pub tokio_version: &'static str,
    pub quinn_endpoint_type: &'static str,
    pub h3_quinn_connection_type: &'static str,
    pub h3_client_builder_type: &'static str,
    pub tokio_runtime_builder_type: &'static str,
    pub quinn_runtime_tokio_feature_admitted: bool,
    pub quinn_boringssl_provider_admitted: bool,
    pub h3_quinn_bridge_admitted: bool,
    pub tokio_runtime_admitted: bool,
    pub dependency_only: bool,
}

pub fn dependency_admission() -> JuicityH3DependencyAdmission {
    JuicityH3DependencyAdmission {
        quinn_version: QUINN_VERSION,
        h3_version: H3_VERSION,
        h3_quinn_version: H3_QUINN_VERSION,
        tokio_version: TOKIO_VERSION,
        quinn_endpoint_type: std::any::type_name::<quinn::Endpoint>(),
        h3_quinn_connection_type: std::any::type_name::<h3_quinn::Connection>(),
        h3_client_builder_type: std::any::type_name::<h3::client::Builder>(),
        tokio_runtime_builder_type: std::any::type_name::<tokio::runtime::Builder>(),
        quinn_runtime_tokio_feature_admitted: QUINN_FEATURES.contains(&"runtime-tokio"),
        quinn_boringssl_provider_admitted: QUINN_CRYPTO_PROVIDER == "quinn-boring",
        h3_quinn_bridge_admitted: true,
        tokio_runtime_admitted: true,
        dependency_only: true,
    }
}
