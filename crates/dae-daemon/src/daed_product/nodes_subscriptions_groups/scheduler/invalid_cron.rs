use super::*;

#[derive(Debug, Default)]
pub(super) struct InvalidCronLogTracker {
    reported: HashMap<i64, String>,
}

impl InvalidCronLogTracker {
    pub(super) fn take_changed(
        &mut self,
        current: &[InvalidScheduledSubscriptionCron],
    ) -> Vec<InvalidScheduledSubscriptionCron> {
        let active_ids = current.iter().map(|item| item.id).collect::<HashSet<_>>();
        self.reported.retain(|id, _| active_ids.contains(id));

        let mut changed = Vec::new();
        for invalid in current {
            if self.reported.get(&invalid.id) != Some(&invalid.error) {
                changed.push(invalid.clone());
            }
            self.reported.insert(invalid.id, invalid.error.clone());
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invalid(id: i64, error: &str) -> InvalidScheduledSubscriptionCron {
        InvalidScheduledSubscriptionCron {
            id,
            error: error.to_owned(),
        }
    }

    #[test]
    fn unchanged_cron_errors_are_reported_once_until_recovery() {
        let mut tracker = InvalidCronLogTracker::default();
        assert_eq!(tracker.take_changed(&[invalid(1, "first")]).len(), 1);
        assert!(tracker.take_changed(&[invalid(1, "first")]).is_empty());

        let changed = tracker.take_changed(&[invalid(1, "second")]);
        assert_eq!(changed, vec![invalid(1, "second")]);

        assert!(tracker.take_changed(&[]).is_empty());
        assert_eq!(tracker.take_changed(&[invalid(1, "second")]).len(), 1);
    }

    #[test]
    fn cron_error_tracking_is_independent_per_subscription() {
        let mut tracker = InvalidCronLogTracker::default();
        assert_eq!(
            tracker
                .take_changed(&[invalid(1, "bad-a"), invalid(2, "bad-b")])
                .len(),
            2
        );
        assert_eq!(
            tracker.take_changed(&[invalid(1, "bad-c"), invalid(2, "bad-b")]),
            vec![invalid(1, "bad-c")]
        );
    }
}
