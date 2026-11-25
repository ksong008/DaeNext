#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use super::super::*;

    #[test]
    fn effective_dae_netns_id_uses_latest_success_summary() {
        let steps = vec![
            json!({
                "name": "assign-production-netns-id-summary",
                "status": "pass",
                "detail": {"effective_dae_netns_id": 51},
            }),
            json!({
                "name": "assign-production-netns-id-summary",
                "status": "pass",
                "detail": {"effective_dae_netns_id": 52},
            }),
        ];
        assert_eq!(effective_dae_netns_id(&steps, 49), 52);
    }
}
