mod envelope;
mod fixed_target;

pub(super) use self::envelope::UdpExchangeResult;
pub(super) use self::fixed_target::{
    UdpFixedTargetExpectation, UdpFixedTargetPayload, UdpFixedTargetValidation,
    UdpResponseDropReason, UdpResponseIdentityEvidence, UdpResponseIdentityToken,
};

#[cfg(test)]
mod tests;
