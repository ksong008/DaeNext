#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum VlessUdp443Policy {
    #[default]
    Reject,
    Allow,
    Skip,
}

impl VlessUdp443Policy {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "reject" => Some(Self::Reject),
            "allow" => Some(Self::Allow),
            "skip" => Some(Self::Skip),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::Allow => "allow",
            Self::Skip => "skip",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct VlessMuxOptions {
    pub concurrency: Option<i16>,
    pub xudp_concurrency: Option<i16>,
    pub udp443: Option<VlessUdp443Policy>,
}

impl VlessMuxOptions {
    pub fn tcp_limit(self) -> Option<usize> {
        self.concurrency
            .filter(|value| *value >= 0)
            .map(|value| value.max(128) as usize)
    }

    pub fn tcp_enabled(self) -> bool {
        self.concurrency.is_none_or(|value| value >= 0)
    }

    pub fn xudp_enabled(self, tcp_enabled: bool) -> bool {
        match self.xudp_concurrency {
            Some(0) => tcp_enabled,
            Some(value) => value > 0,
            None => self.concurrency.is_none() || tcp_enabled,
        }
    }
}
