#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PinnedMapAction {
    DeleteAndRetry { map_name: String },
    ReturnError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoaderBackend {
    TcCommandObject,
    RustSyscallMaps,
    AyaUserspace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoaderContract {
    pub default_object_loader: LoaderBackend,
    pub runtime_map_backend: LoaderBackend,
    pub aya_userspace_loader_planned: bool,
    pub c_ebpf_object_fallback_required: bool,
    pub go_fallback_preserved: bool,
    pub param_rewrite_required_before_attach: bool,
}

pub const fn loader_contract() -> LoaderContract {
    LoaderContract {
        default_object_loader: LoaderBackend::TcCommandObject,
        runtime_map_backend: LoaderBackend::RustSyscallMaps,
        aya_userspace_loader_planned: true,
        c_ebpf_object_fallback_required: true,
        go_fallback_preserved: true,
        param_rewrite_required_before_attach: true,
    }
}

pub fn pinned_map_action(error: &str) -> PinnedMapAction {
    let Some(after_prefix) = error.split_once("use pinned map ").map(|(_, after)| after) else {
        return PinnedMapAction::ReturnError;
    };
    let map_name = after_prefix
        .split_once(':')
        .map(|(name, _)| name)
        .unwrap_or(after_prefix)
        .trim();
    if map_name.is_empty() {
        return PinnedMapAction::ReturnError;
    }
    PinnedMapAction::DeleteAndRetry {
        map_name: map_name.to_owned(),
    }
}
