use std::{
    fs,
    io::{self, Read, Seek, SeekFrom},
};

/// Reads the newest lines first without retaining the complete log file.
pub struct ReverseFileLineReader {
    file: fs::File,
    offset: u64,
    block: [u8; 8192],
    available: usize,
    finished: bool,
    terminated: bool,
    max_line_bytes: usize,
}

impl ReverseFileLineReader {
    pub fn new(file: std::io::Take<fs::File>, max_line_bytes: usize) -> Self {
        let offset = file.limit();
        Self {
            file: file.into_inner(),
            offset,
            block: [0; 8192],
            available: 0,
            finished: false,
            terminated: false,
            max_line_bytes: max_line_bytes.max(1),
        }
    }

    pub fn metadata(&self) -> io::Result<fs::Metadata> {
        self.file.metadata()
    }

    pub fn read_line(&mut self, line: &mut Vec<u8>) -> io::Result<bool> {
        line.clear();
        if self.finished {
            return Ok(false);
        }
        let mut oversized = false;
        loop {
            if self.available == 0 {
                if self.offset == 0 {
                    self.finished = true;
                    if oversized {
                        line.clear();
                    }
                    line.reverse();
                    return Ok(!line.is_empty());
                }
                let read = self.offset.min(self.block.len() as u64) as usize;
                self.offset -= read as u64;
                self.file.seek(SeekFrom::Start(self.offset))?;
                self.file.read_exact(&mut self.block[..read])?;
                self.available = read;
            }
            self.available -= 1;
            let byte = self.block[self.available];
            if byte == b'\n' {
                if oversized {
                    line.clear();
                }
                line.reverse();
                self.terminated = true;
                return Ok(true);
            }
            if !oversized {
                if line.len() < self.max_line_bytes - usize::from(self.terminated) {
                    line.push(byte);
                } else {
                    oversized = true;
                    line.clear();
                }
            }
        }
    }
}
