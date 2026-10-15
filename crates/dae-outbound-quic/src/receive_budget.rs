/// Connection-wide stream receive credit, separate from DATAGRAM queues.
/// Quinn's default per-stream window is retained for individual stream BDP.
/// Credit bounds unread stream bytes; it is not a bound on total endpoint RSS.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum QuicReceiveBudget {
    LowMemory,
    #[default]
    Balanced,
    HighPerformance,
}

impl QuicReceiveBudget {
    pub const fn bytes(self) -> u32 {
        match self {
            Self::LowMemory => 8 * 1024 * 1024,
            Self::Balanced => 32 * 1024 * 1024,
            Self::HighPerformance => 64 * 1024 * 1024,
        }
    }

    pub fn apply(self, transport: &mut quinn::TransportConfig) {
        transport.receive_window(self.bytes().into());
    }
}
