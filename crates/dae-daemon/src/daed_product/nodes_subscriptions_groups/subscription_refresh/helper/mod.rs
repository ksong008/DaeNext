use super::*;

const SUBSCRIPTION_PREPARE_HELPER_TASK_NAME: &str = "daed-subscript";
#[cfg_attr(test, allow(dead_code))]
const SUBSCRIPTION_PREPARE_HELPER_SO_MARK_ENV: &str = "DAED_CONTROL_HELPER_SO_MARK";

mod command;
#[cfg_attr(test, allow(dead_code))]
mod process;
mod protocol;

pub(in crate::daed_product) use command::run_subscription_prepare_helper_command;
#[cfg(not(test))]
pub(super) use process::{SubscriptionHelperOutcome, prepare_subscription_with_helper};
