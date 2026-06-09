use super::*;
impl NativeEbpfRuntimeState {
    pub(in crate::production_runtime_owner) fn new() -> Self {
        Self::default()
    }

    pub(in crate::production_runtime_owner) fn peer_attached(&self) -> bool {
        self.peer_attached
    }

    pub(in crate::production_runtime_owner) fn host_attached(&self) -> bool {
        self.host_attached
    }

    pub(in crate::production_runtime_owner) fn cgroup_attached(&self) -> bool {
        self.cgroup_attached
    }

    pub(in crate::production_runtime_owner) fn lan_attached(&self) -> bool {
        self.lan_attached
    }

    pub(in crate::production_runtime_owner) fn loaded_map_id(&self, name: &str) -> Option<u32> {
        #[cfg(feature = "native-ebpf")]
        {
            self.loaded_map_ids.get(name).copied().or_else(|| {
                let truncated = truncated_bpf_name(name);
                (truncated != name)
                    .then(|| self.loaded_map_ids.get(&truncated).copied())
                    .flatten()
            })
        }
        #[cfg(not(feature = "native-ebpf"))]
        {
            let _ = name;
            None
        }
    }

    pub(in crate::production_runtime_owner) fn pin_root(&self) -> Option<&Path> {
        #[cfg(feature = "native-ebpf")]
        {
            self.pin_root.as_deref()
        }
        #[cfg(not(feature = "native-ebpf"))]
        {
            let _ = self;
            None
        }
    }

    pub(in crate::production_runtime_owner) fn reset(&mut self) {
        #[cfg(feature = "native-ebpf")]
        {
            self.loaded.take();
            self.loaded_map_ids.clear();
            if let Some(pin_root) = self.pin_root.take() {
                let _ = std::fs::remove_dir_all(pin_root);
            }
        }
        self.peer_attached = false;
        self.lan_attached = false;
        self.host_attached = false;
        self.cgroup_attached = false;
    }
}
