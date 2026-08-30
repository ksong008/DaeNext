use bytes::BytesMut;
use dae_outbound_stream::anytls::{AnyTlsFrame, contract as anytls_contract};
use dae_resident_core::RESIDENT_TCP_IDLE_TIMEOUT;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time;

#[cfg(not(feature = "test-anytls-legacy-frame-reader"))]
const ANYTLS_FRAME_READ_CHUNK_SIZE: usize = 32 * 1024;

pub struct AnyTlsFrameReader {
    #[cfg(not(feature = "test-anytls-legacy-frame-reader"))]
    buffered: BytesMut,
}

#[allow(clippy::derivable_impls)]
impl Default for AnyTlsFrameReader {
    fn default() -> Self {
        Self {
            #[cfg(not(feature = "test-anytls-legacy-frame-reader"))]
            buffered: BytesMut::with_capacity(ANYTLS_FRAME_READ_CHUNK_SIZE),
        }
    }
}

impl AnyTlsFrameReader {
    pub async fn read_frame(
        &mut self,
        client: &mut (impl AsyncRead + Unpin),
    ) -> Result<AnyTlsFrame, String> {
        let mut data = BytesMut::new();
        let (cmd, sid) = self.read_into(client, &mut data).await?;
        Ok(AnyTlsFrame {
            cmd,
            sid,
            data: data.to_vec(),
        })
    }

    pub async fn read_into(
        &mut self,
        client: &mut (impl AsyncRead + Unpin),
        data: &mut BytesMut,
    ) -> Result<(u8, u32), String> {
        #[cfg(feature = "test-anytls-legacy-frame-reader")]
        {
            return read_anytls_frame_into_legacy(client, data).await;
        }

        #[cfg(not(feature = "test-anytls-legacy-frame-reader"))]
        loop {
            if self.buffered.len() >= anytls_contract::HEADER_OVERHEAD_SIZE {
                let len = u16::from_be_bytes([self.buffered[5], self.buffered[6]]) as usize;
                let frame_len = anytls_contract::HEADER_OVERHEAD_SIZE + len;
                if self.buffered.len() >= frame_len {
                    let frame = self.buffered.split_to(frame_len);
                    data.clear();
                    data.reserve(len);
                    data.extend_from_slice(&frame[anytls_contract::HEADER_OVERHEAD_SIZE..]);
                    return Ok((
                        frame[0],
                        u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]),
                    ));
                }
            }

            let needed = if self.buffered.len() >= anytls_contract::HEADER_OVERHEAD_SIZE {
                let len = u16::from_be_bytes([self.buffered[5], self.buffered[6]]) as usize;
                (anytls_contract::HEADER_OVERHEAD_SIZE + len) - self.buffered.len()
            } else {
                ANYTLS_FRAME_READ_CHUNK_SIZE
            };
            let read_limit = needed.clamp(1, ANYTLS_FRAME_READ_CHUNK_SIZE);
            self.buffered.reserve(read_limit);
            let mut limited = client.take(read_limit as u64);
            let read = time::timeout(
                RESIDENT_TCP_IDLE_TIMEOUT,
                limited.read_buf(&mut self.buffered),
            )
            .await
            .map_err(|_| "read AnyTLS frame: timeout".to_owned())?
            .map_err(|err| format!("read AnyTLS frame: {err}"))?;
            if read == 0 {
                return Err("read AnyTLS frame: early eof".to_owned());
            }
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn buffered_len(&self) -> usize {
        #[cfg(not(feature = "test-anytls-legacy-frame-reader"))]
        {
            self.buffered.len()
        }
        #[cfg(feature = "test-anytls-legacy-frame-reader")]
        {
            0
        }
    }
}

#[cfg(feature = "test-anytls-legacy-frame-reader")]
async fn read_anytls_frame_into_legacy(
    client: &mut (impl AsyncRead + Unpin),
    data: &mut BytesMut,
) -> Result<(u8, u32), String> {
    let mut header = [0_u8; anytls_contract::HEADER_OVERHEAD_SIZE];
    read_anytls_exact_legacy(client, &mut header, "read AnyTLS frame header").await?;
    let len = u16::from_be_bytes([header[5], header[6]]) as usize;
    data.clear();
    data.reserve(len);
    let mut limited = client.take(len as u64);
    while data.len() < len {
        let read = time::timeout(RESIDENT_TCP_IDLE_TIMEOUT, limited.read_buf(data))
            .await
            .map_err(|_| "read AnyTLS frame data: timeout".to_owned())?
            .map_err(|err| format!("read AnyTLS frame data: {err}"))?;
        if read == 0 {
            return Err("read AnyTLS frame data: early eof".to_owned());
        }
    }
    Ok((
        header[0],
        u32::from_be_bytes([header[1], header[2], header[3], header[4]]),
    ))
}

#[cfg(feature = "test-anytls-legacy-frame-reader")]
async fn read_anytls_exact_legacy(
    client: &mut (impl AsyncRead + Unpin),
    buffer: &mut [u8],
    label: &str,
) -> Result<(), String> {
    let mut offset = 0;
    while offset < buffer.len() {
        let read = time::timeout(
            RESIDENT_TCP_IDLE_TIMEOUT,
            client.read(&mut buffer[offset..]),
        )
        .await
        .map_err(|_| format!("{label}: timeout"))?
        .map_err(|err| format!("{label}: {err}"))?;
        if read == 0 {
            return Err(format!("{label}: early eof"));
        }
        offset += read;
    }
    Ok(())
}
