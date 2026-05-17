#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CoreFlip {
    value: u8,
}

impl CoreFlip {
    pub fn get(self) -> u8 {
        self.value & 1
    }

    pub fn flip(&mut self) {
        self.value = self.value & 1 ^ 1;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReloadCoreState {
    pub is_reload: bool,
    pub bpf_ejected: bool,
    pub defer_func_count: usize,
    pub flip: u8,
}

impl ReloadCoreState {
    pub fn new(is_reload: bool, core_flip: &mut CoreFlip) -> Self {
        if is_reload {
            core_flip.flip();
        }
        Self {
            is_reload,
            bpf_ejected: false,
            defer_func_count: if is_reload { 1 } else { 2 },
            flip: core_flip.get(),
        }
    }

    pub fn eject_bpf(&mut self) {
        if !self.bpf_ejected && !self.is_reload {
            self.defer_func_count = self.defer_func_count.saturating_sub(1);
        }
        self.bpf_ejected = true;
    }

    pub fn inject_bpf(&mut self) {
        if self.bpf_ejected {
            self.bpf_ejected = false;
            self.defer_func_count += 1;
        }
    }
}
