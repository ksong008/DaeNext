use super::*;
impl TlsRecordReader {
    pub(super) fn read_one(
        &mut self,
        conn: &mut ClientConnection,
        tcp: &mut ResidentTcpStream,
    ) -> Result<TlsDriveOutcome, String> {
        let mut progressed = false;
        while self.header.len() < TLS_RECORD_HEADER_LEN {
            let mut byte = [0_u8; 1];
            match tcp.read(&mut byte) {
                Ok(0) => return Ok(TlsDriveOutcome::Progressed(progressed)),
                Ok(_) => {
                    self.header.push(byte[0]);
                    progressed = true;
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) =>
                {
                    return Ok(TlsDriveOutcome::Progressed(progressed));
                }
                Err(err) => return Err(format!("read VLESS TLS record header: {err}")),
            }
        }
        let record_type = self.header[0];
        if !matches!(record_type, 20 | 21 | 22 | 23) {
            return Err(format!(
                "unexpected VLESS TLS record type while driving proxy TLS: {record_type}"
            ));
        }
        let body_len = *self
            .body_len
            .get_or_insert_with(|| u16::from_be_bytes([self.header[3], self.header[4]]) as usize);
        if body_len > TLS_RECORD_MAX_PAYLOAD_LEN {
            return Err(format!("VLESS TLS record too large: {body_len} bytes"));
        }
        while self.body.len() < body_len {
            let need = body_len - self.body.len();
            let mut buf = [0_u8; 4096];
            let want = need.min(buf.len());
            match tcp.read(&mut buf[..want]) {
                Ok(0) => return Ok(TlsDriveOutcome::Progressed(progressed)),
                Ok(read) => {
                    self.body.extend_from_slice(&buf[..read]);
                    progressed = true;
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) =>
                {
                    return Ok(TlsDriveOutcome::Progressed(progressed));
                }
                Err(err) => return Err(format!("read VLESS TLS record body: {err}")),
            }
        }
        let mut record = Vec::with_capacity(TLS_RECORD_HEADER_LEN + body_len);
        record.extend_from_slice(&self.header);
        record.extend_from_slice(&self.body);
        let record_header_hex = hex_prefix(&record[..TLS_RECORD_HEADER_LEN], TLS_RECORD_HEADER_LEN);
        let record_body_prefix_hex = hex_prefix(&record[TLS_RECORD_HEADER_LEN..], 16.min(body_len));
        self.header.clear();
        self.body.clear();
        self.body_len = None;

        let mut cursor = Cursor::new(record.as_slice());
        conn.read_tls(&mut cursor)
            .map_err(|err| format!("feed VLESS TLS record: {err}"))?;
        match conn.process_new_packets() {
            Ok(_) => Ok(TlsDriveOutcome::Progressed(true)),
            Err(err) => Ok(TlsDriveOutcome::DecryptErrorRawRecord {
                record,
                error: format!(
                    "process VLESS TLS record: {err}; tls_record_header={record_header_hex} tls_record_body_prefix={record_body_prefix_hex}"
                ),
            }),
        }
    }
}

pub(super) fn hex_prefix(bytes: &[u8], limit: usize) -> String {
    let take = bytes.len().min(limit);
    let mut out = String::with_capacity(take * 2);
    for byte in &bytes[..take] {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}
