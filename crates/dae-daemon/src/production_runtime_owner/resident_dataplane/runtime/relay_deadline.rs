use std::pin::Pin;
use std::time::Duration;

use tokio::time::{self, Sleep};

pub(crate) fn resident_relay_idle_deadline(timeout: Duration) -> Sleep {
    time::sleep(timeout)
}

pub(crate) fn reset_resident_relay_idle_deadline(deadline: Pin<&mut Sleep>, timeout: Duration) {
    deadline.reset(time::Instant::now() + timeout);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn relay_idle_deadline_can_be_reset_without_polling() {
        let timeout = Duration::from_millis(30);
        let deadline = resident_relay_idle_deadline(timeout);
        tokio::pin!(deadline);

        time::sleep(Duration::from_millis(20)).await;
        reset_resident_relay_idle_deadline(deadline.as_mut(), timeout);
        assert!(
            time::timeout(Duration::from_millis(15), &mut deadline)
                .await
                .is_err()
        );
        time::timeout(Duration::from_millis(30), &mut deadline)
            .await
            .expect("reset relay idle deadline did not expire");
    }
}
