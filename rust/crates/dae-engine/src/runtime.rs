use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::EngineError;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EngineOptions {
    pub subscription_config_dir: Option<String>,
    pub check_network_links: Vec<String>,
}

pub struct Engine {
    sender: SyncSender<ReloadMessage>,
    receiver: Mutex<Option<Receiver<ReloadMessage>>>,
    exit: Arc<(Mutex<bool>, Condvar)>,
    options: EngineOptions,
}

enum ReloadMessage {
    Reload {
        response: SyncSender<Result<(), EngineError>>,
    },
    Stop,
}

impl Engine {
    pub fn new(options: EngineOptions) -> Self {
        let (sender, receiver) = mpsc::sync_channel(0);
        Self {
            sender,
            receiver: Mutex::new(Some(receiver)),
            exit: Arc::new((Mutex::new(true), Condvar::new())),
            options,
        }
    }

    pub fn options(&self) -> &EngineOptions {
        &self.options
    }

    pub fn run(&self, dry: bool) -> Result<(), EngineError> {
        if dry {
            self.run_dry()
        } else {
            Err(EngineError::Parse(
                "normal tproxy runtime is deferred past stage 6".to_owned(),
            ))
        }
    }

    pub fn run_dry(&self) -> Result<(), EngineError> {
        let receiver = self
            .receiver
            .lock()
            .unwrap()
            .take()
            .ok_or(EngineError::AlreadyRunning)?;
        self.set_exit(false);

        while let Ok(message) = receiver.recv() {
            match message {
                ReloadMessage::Reload { response } => {
                    let _ = response.send(Ok(()));
                }
                ReloadMessage::Stop => break,
            }
        }

        self.set_exit(true);
        Ok(())
    }

    pub fn reload_with_timeout(&self, timeout: Duration) -> Result<(), EngineError> {
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        let message = ReloadMessage::Reload {
            response: response_tx,
        };
        self.send_with_timeout(message, timeout)
            .map_err(|_| EngineError::ContextDeadlineExceeded)?;
        response_rx
            .recv_timeout(timeout)
            .map_err(|_| EngineError::ContextDeadlineExceeded)?
    }

    pub fn stop(&self, timeout: Duration) -> Result<(), EngineError> {
        self.send_with_timeout(ReloadMessage::Stop, timeout)
            .map_err(|_| EngineError::TimeoutSendingShutdown)?;
        self.wait_exit(timeout)
    }

    fn send_with_timeout(
        &self,
        mut message: ReloadMessage,
        timeout: Duration,
    ) -> Result<(), ReloadMessage> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.sender.try_send(message) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Full(returned)) => {
                    if Instant::now() >= deadline {
                        return Err(returned);
                    }
                    message = returned;
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(TrySendError::Disconnected(returned)) => return Err(returned),
            }
        }
    }

    fn wait_exit(&self, timeout: Duration) -> Result<(), EngineError> {
        let (lock, condvar) = &*self.exit;
        let mut exited = lock.lock().unwrap();
        let deadline = Instant::now() + timeout;
        while !*exited {
            let now = Instant::now();
            if now >= deadline {
                return Err(EngineError::TimeoutWaitingForShutdown);
            }
            let wait_for = deadline.saturating_duration_since(now);
            let (guard, result) = condvar.wait_timeout(exited, wait_for).unwrap();
            exited = guard;
            if result.timed_out() && !*exited {
                return Err(EngineError::TimeoutWaitingForShutdown);
            }
        }
        Ok(())
    }

    fn set_exit(&self, value: bool) {
        let (lock, condvar) = &*self.exit;
        let mut exited = lock.lock().unwrap();
        *exited = value;
        condvar.notify_all();
    }
}
