use super::*;

const SUBSCRIPTION_PREPARE_HELPER_TASK_NAME: &str = "daed-subscript";

mod command;

pub(in crate::daed_product) use command::run_subscription_prepare_helper_command;
#[cfg(not(test))]
pub(super) use dae_product_subscription::{
    SubscriptionHelperOutcome, prepare_subscription_with_helper,
};
