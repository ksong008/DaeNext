pub use dae_outbound_core::hysteria2::{contract, port_hopping};

#[cfg(any(test, feature = "test-support"))]
mod dataplane;
#[cfg(any(test, feature = "test-support"))]
mod quic_loopback;
#[cfg(any(test, feature = "test-support"))]
pub mod tls {
    pub use dae_outbound_quic::hysteria2::tls::*;
}
#[cfg(any(test, feature = "test-support"))]
pub mod underlay {
    pub use dae_outbound_quic::hysteria2::underlay::*;
}
#[cfg(any(test, feature = "test-support"))]
pub mod wire {
    pub use dae_outbound_quic::hysteria2::wire::*;
}

pub use dae_outbound_quic::hysteria2::*;

#[cfg(any(test, feature = "test-support"))]
pub use dataplane::{
    DEFAULT_TRUE_QUIC_LINK, DEFAULT_TRUE_QUIC_PORT_HOP_ITERATIONS,
    DEFAULT_TRUE_QUIC_SUBSCRIPTION_TAG, DEFAULT_TRUE_QUIC_UDP_HOP_INTERVAL_MS,
    DEFAULT_TRUE_QUIC_UNDERLAY_MARK, Hysteria2TrueQuicDataplaneOptions,
    Hysteria2TrueQuicDataplaneReport, default_true_quic_options_with_timeout_ms,
    run_true_quic_dataplane_smoke,
};

#[cfg(any(test, feature = "test-support"))]
pub use quic_loopback::{
    Hysteria2QuicLoopbackOptions, Hysteria2QuicLoopbackReport, run_hysteria2_quic_loopback_smoke,
};
