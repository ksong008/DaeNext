use crate::abi::{
    BASIC_FEATURE_VERSION, BPF_LOOP_FEATURE_VERSION, BPF_TIMER_FEATURE_VERSION,
    CHECKSUM_FEATURE_VERSION, SK_ASSIGN_FEATURE_VERSION,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl Version {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn kernel_code(self) -> u32 {
        let patch = self.patch.min(255) as u32;
        ((self.major as u32 & 0xff) << 16) | ((self.minor as u32 & 0xff) << 8) | patch
    }

    pub fn display_string(self) -> String {
        if self.patch == 0 {
            format!("v{}.{}", self.major, self.minor)
        } else {
            format!("v{}.{}.{}", self.major, self.minor, self.patch)
        }
    }

    pub fn missing_features(self, lan_configured: bool, wan_configured: bool) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self < BASIC_FEATURE_VERSION {
            missing.push("basic");
        }
        if self < CHECKSUM_FEATURE_VERSION {
            missing.push("checksum");
        }
        if lan_configured && self < SK_ASSIGN_FEATURE_VERSION {
            missing.push("sk_assign_for_lan");
        }
        if wan_configured && self < BPF_TIMER_FEATURE_VERSION {
            missing.push("bpf_timer_for_wan");
        }
        if self < BPF_LOOP_FEATURE_VERSION {
            missing.push("bpf_loop");
        }
        missing
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeatureGateReport {
    pub version: Version,
    pub lan_configured: bool,
    pub wan_configured: bool,
    pub missing: Vec<&'static str>,
}

impl FeatureGateReport {
    pub fn new(version: Version, lan_configured: bool, wan_configured: bool) -> Self {
        let missing = version.missing_features(lan_configured, wan_configured);
        Self {
            version,
            lan_configured,
            wan_configured,
            missing,
        }
    }

    pub fn allowed(&self) -> bool {
        self.missing.is_empty()
    }
}
