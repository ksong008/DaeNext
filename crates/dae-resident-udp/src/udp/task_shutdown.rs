use tokio::task::JoinHandle;

use super::RESIDENT_RUNTIME_FORCED_TASK_JOIN_GRACE;

pub struct ResidentOwnedTaskShutdown<T> {
    pub output: Option<T>,
    pub joined: bool,
    pub forced: bool,
    pub cancelled: bool,
    pub panicked: bool,
    pub error: Option<String>,
}

impl<T> ResidentOwnedTaskShutdown<T> {
    pub fn status(&self) -> &'static str {
        if self.completed_safely() {
            "pass"
        } else {
            "fail"
        }
    }

    pub fn safety_status(&self) -> &'static str {
        self.status()
    }

    pub fn graceful(&self) -> bool {
        self.completed_safely() && !self.forced
    }

    pub fn completion_mode(&self) -> &'static str {
        if !self.completed_safely() {
            "incomplete"
        } else if self.forced {
            "forced-bounded"
        } else if self.graceful() {
            "graceful"
        } else {
            "completed-degraded"
        }
    }

    fn completed_safely(&self) -> bool {
        self.joined && !self.panicked && (!self.cancelled || self.forced)
    }
}

pub async fn shutdown_resident_owned_task<T>(
    task: &mut JoinHandle<T>,
    deadline: tokio::time::Instant,
) -> ResidentOwnedTaskShutdown<T> {
    match tokio::time::timeout_at(deadline, &mut *task).await {
        Ok(result) => completed_task_shutdown(result, false),
        Err(_) => {
            task.abort();
            let forced_deadline =
                tokio::time::Instant::now() + RESIDENT_RUNTIME_FORCED_TASK_JOIN_GRACE;
            match tokio::time::timeout_at(forced_deadline, &mut *task).await {
                Ok(result) => completed_task_shutdown(result, true),
                Err(_) => ResidentOwnedTaskShutdown {
                    output: None,
                    joined: false,
                    forced: true,
                    cancelled: false,
                    panicked: false,
                    error: Some(format!(
                        "task did not join within {}ms after abort",
                        RESIDENT_RUNTIME_FORCED_TASK_JOIN_GRACE.as_millis()
                    )),
                },
            }
        }
    }
}

fn completed_task_shutdown<T>(
    result: Result<T, tokio::task::JoinError>,
    forced: bool,
) -> ResidentOwnedTaskShutdown<T> {
    match result {
        Ok(output) => ResidentOwnedTaskShutdown {
            output: Some(output),
            joined: true,
            forced,
            cancelled: false,
            panicked: false,
            error: None,
        },
        Err(error) => ResidentOwnedTaskShutdown {
            output: None,
            joined: true,
            forced,
            cancelled: error.is_cancelled(),
            panicked: error.is_panic(),
            error: Some(error.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pending_task_is_aborted_and_joined_with_bounded_evidence() {
        let mut task = tokio::spawn(std::future::pending::<()>());

        let shutdown = shutdown_resident_owned_task(&mut task, tokio::time::Instant::now()).await;

        assert_eq!(shutdown.status(), "pass");
        assert_eq!(shutdown.safety_status(), "pass");
        assert!(!shutdown.graceful());
        assert_eq!(shutdown.completion_mode(), "forced-bounded");
        assert!(shutdown.joined);
        assert!(shutdown.forced);
        assert!(shutdown.cancelled);
    }

    #[tokio::test]
    async fn completed_task_keeps_graceful_completion() {
        let mut task = tokio::spawn(async { 7_u8 });

        let shutdown = shutdown_resident_owned_task(
            &mut task,
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
        )
        .await;

        assert_eq!(shutdown.output, Some(7));
        assert!(shutdown.graceful());
        assert_eq!(shutdown.completion_mode(), "graceful");
    }

    #[tokio::test]
    async fn panicked_task_is_reaped_without_being_reported_safe() {
        let mut task = tokio::spawn(async { panic!("injected owned task panic") });

        let shutdown = shutdown_resident_owned_task(
            &mut task,
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
        )
        .await;

        assert!(shutdown.joined);
        assert!(shutdown.panicked);
        assert_eq!(shutdown.status(), "fail");
        assert_eq!(shutdown.safety_status(), "fail");
        assert!(!shutdown.graceful());
        assert_eq!(shutdown.completion_mode(), "incomplete");
    }
}
