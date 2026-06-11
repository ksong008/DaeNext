use dae_core_types::reload::{RELOAD_DONE, RELOAD_ERROR, RELOAD_PROCESSING, RELOAD_SEND};

use crate::CliError;

pub const PID_FILE_PATH: &str = "/var/run/dae.pid";
pub const SIGNAL_PROGRESS_FILE_PATH: &str = "/var/run/dae.progress";
pub const ABORT_FILE: &str = "/var/run/dae.abort";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReloadProgress {
    Send,
    Processing,
    Done,
    Error,
}

impl ReloadProgress {
    pub fn byte(self) -> u8 {
        match self {
            Self::Send => RELOAD_SEND,
            Self::Processing => RELOAD_PROCESSING,
            Self::Done => RELOAD_DONE,
            Self::Error => RELOAD_ERROR,
        }
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            RELOAD_SEND => Some(Self::Send),
            RELOAD_PROCESSING => Some(Self::Processing),
            RELOAD_DONE => Some(Self::Done),
            RELOAD_ERROR => Some(Self::Error),
            _ => None,
        }
    }
}

pub fn parse_progress_content(content: impl AsRef<[u8]>) -> Result<(u8, String), CliError> {
    let content = String::from_utf8_lossy(content.as_ref()).into_owned();
    let (first_line, rest) = content.split_once('\n').unwrap_or((&content, ""));
    if first_line.len() != 1 {
        return Err(CliError::Progress(format!("unexpected format: {content}")));
    }
    Ok((first_line.as_bytes()[0], rest.to_owned()))
}
