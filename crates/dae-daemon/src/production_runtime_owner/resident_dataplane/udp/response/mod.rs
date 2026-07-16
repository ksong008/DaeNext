mod envelope;
mod fixed_target;

pub(super) use self::envelope::UdpExchangeResult;
pub(super) use self::fixed_target::{
    UdpFixedTargetPayload, UdpFixedTargetValidation, UdpResponseDropReason,
    UdpResponseIdentityEvidence, UdpResponseIdentityToken,
};

#[cfg(test)]
mod tests;
