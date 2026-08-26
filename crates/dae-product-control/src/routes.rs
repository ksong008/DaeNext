#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductApiRoute {
    Health,
    AuthStatus,
    CreateUser,
    IssueToken,
    UserMe,
    PatchUser,
    UpdatePassword,
    GetStorage,
    SetStorage,
    DeleteStorage,
    DefaultResources,
    SelectProfile,
    GetBundle,
    PutBundle,
    GetDaeConfigFile,
    PutDaeConfigFile,
    PreviewDaeConfigFile,
    GeneralState,
    GeneralCacheStats,
    GeneralInterfaces,
    GeodataStatus,
    GeodataSettings,
    SetGeositeSource,
    SetGeoipSource,
    UpdateGeosite,
    UpdateGeoip,
    RuntimeOverview,
    TouchUiSession,
    CloseUiSession,
    RuntimeReload,
    RuntimeStop,
    GetRuntimeLogLevel,
    SetRuntimeLogLevel,
    RuntimeEvents,
    LogEvents,
    Logs,
    ClearLogs,
    GetLogSettings,
    SetLogSettings,
    GetNodeLatencies,
    TestNodeLatencies,
    GetNodeLatencyJob,
    CancelNodeLatencyJob,
    Sections,
    Nodes,
    Subscriptions,
    Groups,
    NotFound,
}

impl ProductApiRoute {
    pub fn requires_authentication(self) -> bool {
        !matches!(
            self,
            Self::Health | Self::AuthStatus | Self::CreateUser | Self::IssueToken
        )
    }
}

pub fn classify_product_api_route(method: &str, path: &str) -> ProductApiRoute {
    match (method, path) {
        ("GET", "/health") => ProductApiRoute::Health,
        ("GET", "/auth/status") => ProductApiRoute::AuthStatus,
        ("POST", "/auth/users") => ProductApiRoute::CreateUser,
        ("POST", "/auth/token") => ProductApiRoute::IssueToken,
        ("GET", "/user/me") => ProductApiRoute::UserMe,
        ("PATCH", "/user/me") => ProductApiRoute::PatchUser,
        ("POST", "/user/me/password") => ProductApiRoute::UpdatePassword,
        ("GET", "/user/me/storage") => ProductApiRoute::GetStorage,
        ("PUT", "/user/me/storage") => ProductApiRoute::SetStorage,
        ("DELETE", "/user/me/storage") => ProductApiRoute::DeleteStorage,
        ("POST", "/user/me/default-resources") => ProductApiRoute::DefaultResources,
        ("POST", "/profiles/select") => ProductApiRoute::SelectProfile,
        ("GET", "/user/me/dae-bundle") => ProductApiRoute::GetBundle,
        ("PUT", "/user/me/dae-bundle") => ProductApiRoute::PutBundle,
        ("GET", "/user/me/dae-config-file") => ProductApiRoute::GetDaeConfigFile,
        ("PUT", "/user/me/dae-config-file") => ProductApiRoute::PutDaeConfigFile,
        ("POST", "/user/me/dae-config-file/preview") => ProductApiRoute::PreviewDaeConfigFile,
        ("GET", "/general/state") => ProductApiRoute::GeneralState,
        ("GET", "/general/cache-stats") => ProductApiRoute::GeneralCacheStats,
        ("GET", "/general/interfaces") => ProductApiRoute::GeneralInterfaces,
        ("GET", "/geodata") => ProductApiRoute::GeodataStatus,
        ("GET", "/geodata/settings") => ProductApiRoute::GeodataSettings,
        ("PATCH", "/geodata/geosite/settings") => ProductApiRoute::SetGeositeSource,
        ("PATCH", "/geodata/geoip/settings") => ProductApiRoute::SetGeoipSource,
        ("POST", "/geodata/geosite/update") => ProductApiRoute::UpdateGeosite,
        ("POST", "/geodata/geoip/update") => ProductApiRoute::UpdateGeoip,
        ("GET", "/runtime/overview") => ProductApiRoute::RuntimeOverview,
        ("POST", "/ui/session") => ProductApiRoute::TouchUiSession,
        ("POST", "/ui/session/close") => ProductApiRoute::CloseUiSession,
        ("POST", "/runtime/reload") => ProductApiRoute::RuntimeReload,
        ("POST", "/runtime/stop") => ProductApiRoute::RuntimeStop,
        ("GET", "/runtime/log-level") => ProductApiRoute::GetRuntimeLogLevel,
        ("PATCH", "/runtime/log-level") => ProductApiRoute::SetRuntimeLogLevel,
        ("GET", "/events/runtime") => ProductApiRoute::RuntimeEvents,
        ("GET", "/events/logs") => ProductApiRoute::LogEvents,
        ("GET", "/logs") => ProductApiRoute::Logs,
        ("DELETE", "/logs") => ProductApiRoute::ClearLogs,
        ("GET", "/logs/settings") => ProductApiRoute::GetLogSettings,
        ("PATCH", "/logs/settings") => ProductApiRoute::SetLogSettings,
        ("GET", "/nodes/latencies") => ProductApiRoute::GetNodeLatencies,
        ("POST", "/nodes/latencies") => ProductApiRoute::TestNodeLatencies,
        ("GET", "/nodes/latencies/job") => ProductApiRoute::GetNodeLatencyJob,
        ("DELETE", "/nodes/latencies/job") => ProductApiRoute::CancelNodeLatencyJob,
        _ if collection_path(path, "/configs")
            || collection_path(path, "/dns")
            || collection_path(path, "/routings") =>
        {
            ProductApiRoute::Sections
        }
        _ if collection_path(path, "/nodes") => ProductApiRoute::Nodes,
        _ if collection_path(path, "/subscriptions") => ProductApiRoute::Subscriptions,
        _ if collection_path(path, "/groups") => ProductApiRoute::Groups,
        _ => ProductApiRoute::NotFound,
    }
}

fn collection_path(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_routes_are_explicit_and_everything_else_requires_authentication() {
        assert!(!classify_product_api_route("POST", "/auth/token").requires_authentication());
        assert!(classify_product_api_route("GET", "/runtime/overview").requires_authentication());
        assert!(classify_product_api_route("GET", "/unknown").requires_authentication());
    }

    #[test]
    fn collections_match_only_at_component_boundaries() {
        assert_eq!(
            classify_product_api_route("GET", "/nodes/7"),
            ProductApiRoute::Nodes
        );
        assert_eq!(
            classify_product_api_route("GET", "/nodes-extra"),
            ProductApiRoute::NotFound
        );
    }
}
