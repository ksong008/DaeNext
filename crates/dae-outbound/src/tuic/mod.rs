pub use dae_outbound_core::tuic::contract;

#[cfg(any(test, feature = "test-support"))]
mod dataplane;
#[cfg(any(test, feature = "test-support"))]
mod quic_loopback;
#[cfg(any(test, feature = "test-support"))]
pub mod runtime {
    pub use dae_outbound_quic::tuic::runtime::*;
}
#[cfg(any(test, feature = "test-support"))]
pub mod tls {
    pub use dae_outbound_quic::tuic::tls::*;
}
#[cfg(any(test, feature = "test-support"))]
pub mod underlay {
    pub use dae_outbound_quic::tuic::underlay::*;
}
#[cfg(any(test, feature = "test-support"))]
pub mod wire {
    pub use dae_outbound_quic::tuic::wire::*;
}

pub use dae_outbound_quic::tuic::*;

#[cfg(any(test, feature = "test-support"))]
pub use dataplane::{
    DEFAULT_DISABLE_SNI_PROBE_LINK, DEFAULT_TRUE_QUIC_LINK, DEFAULT_TRUE_QUIC_SUBSCRIPTION_TAG,
    DEFAULT_TRUE_QUIC_UNDERLAY_MARK, TuicTrueQuicDataplaneOptions, TuicTrueQuicDataplaneReport,
    default_true_quic_options_with_timeout_ms, run_true_quic_dataplane_smoke,
};

#[cfg(any(test, feature = "test-support"))]
pub use quic_loopback::{
    DEFAULT_TUIC_PASSWORD, DEFAULT_TUIC_UUID, TuicQuicLoopbackOptions, TuicQuicLoopbackReport,
    run_tuic_quic_loopback_smoke,
};
