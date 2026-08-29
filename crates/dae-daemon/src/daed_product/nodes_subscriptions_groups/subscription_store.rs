use super::*;

pub(super) struct SubscriptionTagConflict;

impl SubscriptionTagConflict {
    pub(super) fn matches(error: &rusqlite::Error) -> bool {
        dae_product_subscription::SubscriptionTagConflict::matches(error)
    }

    pub(super) fn response() -> HttpResponse {
        HttpResponse::json(
            409,
            json!({
                "error": "a subscription with this tag already exists; update it or choose a different tag",
                "errorCode": "subscription_tag_conflict",
                "retryable": false,
            }),
        )
    }
}

pub(super) use dae_product_subscription::subscription_tag_exists;

pub(super) use dae_product_subscription::subscription_write_guard;
