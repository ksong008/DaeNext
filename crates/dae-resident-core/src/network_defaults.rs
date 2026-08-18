use std::time::Duration;

pub const RESIDENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const RESIDENT_TCP_CANDIDATE_ATTEMPT_DELAY: Duration = Duration::from_millis(250);
pub const RESIDENT_TCP_CANDIDATE_MAX_IN_FLIGHT: usize = 2;
pub const RESIDENT_UDP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(8);
