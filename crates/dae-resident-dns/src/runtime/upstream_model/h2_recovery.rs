use std::time::{Duration, Instant};

#[derive(Debug, Default)]
pub struct ResidentDnsH2Recovery {
    retry_after: Option<Instant>,
}

impl ResidentDnsH2Recovery {
    pub fn should_attempt(&mut self, now: Instant) -> bool {
        match self.retry_after {
            Some(retry_after) if now < retry_after => false,
            Some(_) => {
                self.retry_after = None;
                true
            }
            None => true,
        }
    }

    pub fn record_failure(&mut self, now: Instant, cooldown: Duration) {
        self.retry_after = now.checked_add(cooldown).or(Some(now));
    }

    pub fn record_success(&mut self) {
        self.retry_after = None;
    }
}

#[cfg(all(test, feature = "dns-runtime-tests"))]
mod tests;
