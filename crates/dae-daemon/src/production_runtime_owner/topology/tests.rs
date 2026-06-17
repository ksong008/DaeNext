#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use super::super::*;

    #[test]
    fn parses_used_netns_ids_from_ip_output() {
        let used = parse_used_netns_ids(
            "nsid 49 \nnsid 12 current-nsid unassigned \ninvalid\nnsid not-a-number\n",
        );
        assert!(used.contains(&49));
        assert!(used.contains(&12));
        assert!(!used.contains(&0));
    }

    #[test]
    fn effective_dae_netns_id_uses_latest_success_summary() {
        let steps = vec![
            json!({
                "name": "assign-production-netns-id-summary",
                "status": "pass",
                "effective_dae_netns_id": 51,
            }),
            json!({
                "name": "assign-production-netns-id-summary",
                "status": "pass",
                "effective_dae_netns_id": 52,
            }),
        ];
        assert_eq!(effective_dae_netns_id(&steps, 49), 52);
    }

    #[test]
    fn netns_id_auto_uses_newly_assigned_id() {
        let before = BTreeSet::from([49]);
        let after = BTreeSet::from([49, 50]);
        assert_eq!(new_netns_id_after_auto(&before, &after), Some(50));
    }
}
