mod envelope;
mod fixed_target;

pub use self::envelope::UdpExchangeResult;
pub use self::fixed_target::{
    UdpFixedTargetExpectation, UdpFixedTargetPayload, UdpFixedTargetValidation,
    UdpResponseDropReason, UdpResponseIdentityEvidence, UdpResponseIdentityToken,
    UdpSessionFixedTarget,
};

#[cfg(test)]
mod tests;
