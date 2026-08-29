use super::*;

pub(in crate::daed_product) type RuntimeReconciler =
    dae_product_control::runtime::ProductRuntimeReconciler<
        AppliedRuntimeReload,
        CoordinatedRuntimeReloadError,
    >;
pub(in crate::daed_product) type RuntimeReconcileRequest =
    dae_product_control::runtime::ProductRuntimeReconcileRequest<
        AppliedRuntimeReload,
        CoordinatedRuntimeReloadError,
    >;
pub(in crate::daed_product) type RuntimeReconcileAdmission =
    dae_product_control::runtime::ProductRuntimeReconcileAdmission<
        AppliedRuntimeReload,
        CoordinatedRuntimeReloadError,
    >;

#[cfg(test)]
#[path = "runtime_reconcile/tests.rs"]
mod tests;
