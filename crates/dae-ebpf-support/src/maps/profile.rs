#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RuntimeMapProfile {
    LowMemory,
    #[default]
    Balanced,
    HighPerformance,
}

const LOW_MEMORY_CAPACITIES: [(&str, u32); 5] = [
    ("cookie_pid_map", 8_192),
    ("domain_routing_map", 8_192),
    ("redirect_track", 8_192),
    ("routing_tuples_map", 16_384),
    ("udp_conn_state_map", 16_384),
];

const BALANCED_CAPACITIES: [(&str, u32); 5] = [
    ("cookie_pid_map", 32_768),
    ("domain_routing_map", 32_768),
    ("redirect_track", 32_768),
    ("routing_tuples_map", 65_536),
    ("udp_conn_state_map", 65_536),
];

const HIGH_PERFORMANCE_CAPACITIES: [(&str, u32); 5] = [
    ("cookie_pid_map", 65_536),
    ("domain_routing_map", 65_536),
    ("redirect_track", 65_536),
    ("routing_tuples_map", 131_072),
    ("udp_conn_state_map", 131_072),
];

impl RuntimeMapProfile {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "low" | "low-memory" => Some(Self::LowMemory),
            "balanced" | "standard" => Some(Self::Balanced),
            "high" | "high-performance" => Some(Self::HighPerformance),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::LowMemory => "low-memory",
            Self::Balanced => "balanced",
            Self::HighPerformance => "high-performance",
        }
    }

    pub const fn max_entries_overrides(self) -> &'static [(&'static str, u32)] {
        match self {
            Self::LowMemory => &LOW_MEMORY_CAPACITIES,
            Self::Balanced => &BALANCED_CAPACITIES,
            Self::HighPerformance => &HIGH_PERFORMANCE_CAPACITIES,
        }
    }
}
