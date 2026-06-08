fn run_candidate_command(
    binary_source: &Path,
    args: &[&str],
    path_arg: Option<&Path>,
) -> io::Result<Output> {
    const MAX_ATTEMPTS: usize = 20;
    for attempt in 0..MAX_ATTEMPTS {
        let mut command = Command::new(binary_source);
        command.args(args);
        if let Some(path_arg) = path_arg {
            command.arg(path_arg);
        }
        match command.output() {
            Err(err) if err.raw_os_error() == Some(libc::ETXTBSY) && attempt + 1 < MAX_ATTEMPTS => {
                thread::sleep(Duration::from_millis(10));
            }
            result => return result,
        }
    }
    unreachable!("candidate command retry loop always returns")
}

fn bounded_command_output(bytes: &[u8]) -> String {
    const MAX_OUTPUT_BYTES: usize = 4000;
    String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_OUTPUT_BYTES)]).into_owned()
}
