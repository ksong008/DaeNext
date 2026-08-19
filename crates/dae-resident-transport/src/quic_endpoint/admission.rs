use std::num::NonZeroUsize;
use std::sync::OnceLock;

use dae_runtime_control::{
    AbsoluteDeadline, ChargedOwnerBytes, OwnerAdmissionMetrics, OwnerAdmissionRejection,
    OwnerCancellationSignal, OwnerReservation, OwnerResourceBudget, PhysicalOwnerAdmission,
};
use serde_json::{Value, json};

use super::charge::QuicEndpointCharge;

static ADMISSION: OnceLock<PhysicalOwnerAdmission> = OnceLock::new();

pub(super) enum ReserveQuicEndpointError {
    Configuration,
    Admission(OwnerAdmissionRejection),
}

#[derive(Clone, Copy)]
pub struct QuicEndpointAdmissionContext<'a> {
    deadline: AbsoluteDeadline,
    cancellation: &'a OwnerCancellationSignal,
}

impl<'a> QuicEndpointAdmissionContext<'a> {
    pub const fn new(
        deadline: AbsoluteDeadline,
        cancellation: &'a OwnerCancellationSignal,
    ) -> Self {
        Self {
            deadline,
            cancellation,
        }
    }
}

pub fn configure_quic_endpoint_admission(budget: OwnerResourceBudget) -> Result<(), String> {
    let admission = ADMISSION.get_or_init(|| PhysicalOwnerAdmission::new(budget));
    let configured = admission.metrics().budget;
    if configured != budget {
        return Err(format!(
            "QUIC Endpoint admission budget already configured as count={} bytes={}, requested count={} bytes={}",
            configured.max_active_owners(),
            configured.max_charged_bytes(),
            budget.max_active_owners(),
            budget.max_charged_bytes(),
        ));
    }
    Ok(())
}

fn admission() -> Result<&'static PhysicalOwnerAdmission, String> {
    ADMISSION
        .get()
        .ok_or_else(|| "QUIC Endpoint admission budget is not configured".to_owned())
}

pub(super) fn reserve_quic_endpoint(
    charge: QuicEndpointCharge,
    context: QuicEndpointAdmissionContext<'_>,
) -> Result<OwnerReservation, String> {
    let charged_bytes = usize::try_from(charge.total_bytes)
        .map_err(|_| "QUIC Endpoint charge does not fit the platform address space".to_owned())?;
    let charged_bytes = NonZeroUsize::new(charged_bytes)
        .ok_or_else(|| "QUIC Endpoint charge must be nonzero".to_owned())?;
    admission()?
        .try_reserve(
            ChargedOwnerBytes::new(charged_bytes),
            context.deadline,
            context.cancellation,
        )
        .map_err(admission_rejection_message)
}

pub(super) async fn reserve_quic_endpoint_until(
    charge: QuicEndpointCharge,
    context: QuicEndpointAdmissionContext<'_>,
) -> Result<OwnerReservation, ReserveQuicEndpointError> {
    let charged_bytes = usize::try_from(charge.total_bytes).map_err(|_| {
        ReserveQuicEndpointError::Admission(OwnerAdmissionRejection::LimitsExceeded {
            count: false,
            charged_bytes: true,
        })
    })?;
    let charged_bytes = NonZeroUsize::new(charged_bytes).ok_or(
        ReserveQuicEndpointError::Admission(OwnerAdmissionRejection::LimitsExceeded {
            count: false,
            charged_bytes: true,
        }),
    )?;
    admission()
        .map_err(|_| ReserveQuicEndpointError::Configuration)?
        .reserve_until(
            ChargedOwnerBytes::new(charged_bytes),
            context.deadline,
            context.cancellation,
        )
        .await
        .map_err(ReserveQuicEndpointError::Admission)
}

fn admission_rejection_message(rejection: OwnerAdmissionRejection) -> String {
    match rejection {
        OwnerAdmissionRejection::Cancelled(reason) => {
            format!("QUIC Endpoint admission cancelled: {reason:?}")
        }
        OwnerAdmissionRejection::Draining(reason) => {
            format!("QUIC Endpoint admission is draining: {reason:?}")
        }
        OwnerAdmissionRejection::Closed(reason) => {
            format!("QUIC Endpoint admission is closed: {reason:?}")
        }
        OwnerAdmissionRejection::LimitsExceeded {
            count,
            charged_bytes,
        } => format!(
            "QUIC Endpoint resource budget exceeded (count={count}, charged_bytes={charged_bytes})"
        ),
    }
}

pub(super) fn admission_snapshot() -> Value {
    match admission() {
        Ok(admission) => admission_metrics_json(admission.metrics()),
        Err(_) => json!({
            "enforced": true,
            "scope": "process-wide",
            "configured": false,
        }),
    }
}

fn admission_metrics_json(metrics: OwnerAdmissionMetrics) -> Value {
    json!({
        "enforced": true,
        "scope": "process-wide",
        "activeOwners": metrics.active_owners,
        "activeChargedBytes": metrics.active_charged_bytes,
        "highWaterOwners": metrics.high_water_owners,
        "highWaterChargedBytes": metrics.high_water_charged_bytes,
        "cumulativeAdmitted": metrics.cumulative_admitted,
        "rejectedByCount": metrics.rejected_by_count,
        "rejectedByChargedBytes": metrics.rejected_by_charged_bytes,
        "rejectedWhileDraining": metrics.rejected_while_draining,
        "budget": {
            "maxActiveOwners": metrics.budget.max_active_owners().get(),
            "maxChargedBytes": metrics.budget.max_charged_bytes().get(),
        },
    })
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    fn test_admission(max_active: usize, max_bytes: usize) -> PhysicalOwnerAdmission {
        PhysicalOwnerAdmission::new(OwnerResourceBudget::new(
            NonZeroUsize::new(max_active).unwrap(),
            NonZeroUsize::new(max_bytes).unwrap(),
        ))
    }

    fn reserve(
        admission: &PhysicalOwnerAdmission,
        bytes: usize,
    ) -> Result<OwnerReservation, OwnerAdmissionRejection> {
        admission.try_reserve(
            ChargedOwnerBytes::new(NonZeroUsize::new(bytes).unwrap()),
            AbsoluteDeadline::from_now(Instant::now(), Duration::from_secs(1)),
            &OwnerCancellationSignal::new(),
        )
    }

    #[test]
    fn count_and_charged_bytes_are_independent_limits() {
        let count_limited = test_admission(1, 1_000);
        let first = reserve(&count_limited, 10).unwrap();
        assert!(matches!(
            reserve(&count_limited, 10),
            Err(OwnerAdmissionRejection::LimitsExceeded {
                count: true,
                charged_bytes: false,
            })
        ));
        drop(first);

        let byte_limited = test_admission(10, 15);
        let first = reserve(&byte_limited, 10).unwrap();
        assert!(matches!(
            reserve(&byte_limited, 10),
            Err(OwnerAdmissionRejection::LimitsExceeded {
                count: false,
                charged_bytes: true,
            })
        ));
        drop(first);
        assert_eq!(byte_limited.metrics().active_charged_bytes, 0);
    }
}
