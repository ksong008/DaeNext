use super::*;

pub(super) struct LatencyProbeHelperProcess {
    child: std::process::Child,
    stdout_reader: Option<thread::JoinHandle<()>>,
    stderr_reader: Option<thread::JoinHandle<String>>,
    reaped: bool,
}

impl LatencyProbeHelperProcess {
    pub(super) fn new(child: std::process::Child) -> Self {
        Self {
            child,
            stdout_reader: None,
            stderr_reader: None,
            reaped: false,
        }
    }

    pub(super) fn child_mut(&mut self) -> &mut std::process::Child {
        &mut self.child
    }

    pub(super) fn set_readers(
        &mut self,
        stdout_reader: thread::JoinHandle<()>,
        stderr_reader: thread::JoinHandle<String>,
    ) {
        self.stdout_reader = Some(stdout_reader);
        self.stderr_reader = Some(stderr_reader);
    }

    pub(super) fn terminate_and_wait(&mut self) -> Option<std::process::ExitStatus> {
        let _ = self.child.kill();
        let status = self.child.wait().ok();
        self.reaped = status.is_some();
        status
    }

    pub(super) fn mark_reaped(&mut self) {
        self.reaped = true;
    }

    pub(super) fn join_readers(&mut self) -> String {
        if let Some(reader) = self.stdout_reader.take() {
            let _ = reader.join();
        }
        self.stderr_reader
            .take()
            .and_then(|reader| reader.join().ok())
            .unwrap_or_default()
    }
}

impl Drop for LatencyProbeHelperProcess {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.reaped = true;
        }
        let _ = self.join_readers();
    }
}

pub(super) fn spawn_bounded_stdout_reader(
    stdout: impl Read + Send + 'static,
    sender: std::sync::mpsc::SyncSender<Result<String, String>>,
    line_limit: usize,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = io::BufReader::new(stdout);
        loop {
            let mut line = String::new();
            let read = reader
                .by_ref()
                .take(line_limit.saturating_add(1) as u64)
                .read_line(&mut line);
            let message = match read {
                Ok(0) => return,
                Ok(_) if line.len() > line_limit => Err(format!(
                    "latency probe helper stdout line exceeds {line_limit} bytes"
                )),
                Ok(_) => Ok(line),
                Err(err) => Err(format!("read latency probe helper stdout: {err}")),
            };
            let stop = message.is_err();
            if sender.send(message).is_err() || stop {
                return;
            }
        }
    })
}

pub(super) fn spawn_bounded_stderr_reader(
    stderr: impl Read + Send + 'static,
    limit: usize,
) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = io::BufReader::new(stderr)
            .take(limit.saturating_add(1) as u64)
            .read_to_end(&mut bytes);
        if bytes.len() > limit {
            bytes.truncate(limit);
            bytes.extend_from_slice(b"\n[stderr truncated]");
        }
        String::from_utf8_lossy(&bytes).into_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdout_reader_rejects_oversized_lines_without_unbounded_growth() {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let reader = spawn_bounded_stdout_reader(io::Cursor::new(vec![b'x'; 33]), sender, 32);
        let message = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(message.unwrap_err().contains("exceeds 32 bytes"));
        reader.join().unwrap();
    }

    #[test]
    fn stderr_reader_truncates_to_its_configured_limit() {
        let reader = spawn_bounded_stderr_reader(io::Cursor::new(vec![b'x'; 33]), 32);
        let output = reader.join().unwrap();
        assert!(output.starts_with(&"x".repeat(32)));
        assert!(output.ends_with("[stderr truncated]"));
    }

    #[test]
    fn process_guard_reaps_an_unfinished_child() {
        let child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        drop(LatencyProbeHelperProcess::new(child));
        let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
        assert_eq!(result, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    }
}
