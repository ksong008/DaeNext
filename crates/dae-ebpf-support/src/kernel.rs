use crate::abi::{
    BASIC_FEATURE_VERSION, BPF_LOOP_FEATURE_VERSION, BPF_TIMER_FEATURE_VERSION,
    CHECKSUM_FEATURE_VERSION, SK_ASSIGN_FEATURE_VERSION,
};
use std::io;

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

    pub fn parse_release(release: &str) -> Result<Self, String> {
        let release = release.trim();
        let mut components = release
            .split(|ch: char| !ch.is_ascii_digit())
            .filter(|component| !component.is_empty());
        let major = parse_component(components.next(), release, "major")?;
        let minor = parse_component(components.next(), release, "minor")?;
        let patch = components
            .next()
            .map(|component| {
                component
                    .parse::<u16>()
                    .map_err(|err| format!("invalid kernel patch in {release:?}: {err}"))
            })
            .transpose()?
            .unwrap_or(0);
        Ok(Self::new(major, minor, patch))
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

fn parse_component(component: Option<&str>, release: &str, name: &str) -> Result<u16, String> {
    component
        .ok_or_else(|| format!("kernel release {release:?} is missing {name} component"))?
        .parse::<u16>()
        .map_err(|err| format!("invalid kernel {name} in {release:?}: {err}"))
}

pub fn current_kernel_version() -> io::Result<Version> {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")?;
    Version::parse_release(&release).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kernel_release_extracts_numeric_prefix() {
        assert_eq!(
            Version::parse_release("6.8.12-300.fc40.x86_64").unwrap(),
            Version::new(6, 8, 12)
        );
        assert_eq!(
            Version::parse_release("5.15-generic").unwrap(),
            Version::new(5, 15, 0)
        );
    }

    #[test]
    fn feature_gate_requires_lan_and_wan_specific_features_only_when_configured() {
        let base = Version::new(5, 14, 0);
        assert_eq!(
            FeatureGateReport::new(base, true, false).missing,
            vec!["bpf_loop"]
        );
        assert_eq!(
            FeatureGateReport::new(base, false, true).missing,
            vec!["bpf_timer_for_wan", "bpf_loop"]
        );
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
