use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

const HTTP_CONNECT_HEAD_LIMIT: usize = 8 * 1024;
const HTTP_CONNECT_PEEK_CHUNK: usize = 512;

pub(crate) async fn read_plain_http_connect_head_without_overread(
    stream: &mut TcpStream,
) -> Result<Vec<u8>, String> {
    let mut head = Vec::with_capacity(HTTP_CONNECT_PEEK_CHUNK);
    let mut delimiter_match = 0_u8;
    let mut peek = [0_u8; HTTP_CONNECT_PEEK_CHUNK];

    loop {
        let available = stream
            .peek(&mut peek)
            .await
            .map_err(|err| format!("peek HTTP CONNECT response: {err}"))?;
        if available == 0 {
            return Err("incomplete HTTP CONNECT response".to_owned());
        }

        let mut consume = available;
        let mut complete = false;
        for (index, byte) in peek[..available].iter().copied().enumerate() {
            delimiter_match = next_delimiter_match(delimiter_match, byte);
            if delimiter_match == 4 {
                consume = index + 1;
                complete = true;
                break;
            }
        }

        if head.len().saturating_add(consume) > HTTP_CONNECT_HEAD_LIMIT {
            return Err("HTTP CONNECT response too large".to_owned());
        }
        stream
            .read_exact(&mut peek[..consume])
            .await
            .map_err(|err| format!("read HTTP CONNECT response: {err}"))?;
        head.extend_from_slice(&peek[..consume]);

        if complete {
            return Ok(head);
        }
    }
}

fn next_delimiter_match(state: u8, byte: u8) -> u8 {
    match (state, byte) {
        (0, b'\r') => 1,
        (1, b'\n') => 2,
        (1, b'\r') => 1,
        (2, b'\r') => 3,
        (3, b'\n') => 4,
        (3, b'\r') => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delimiter_state_handles_chunk_boundaries() {
        let mut state = 0;
        for byte in b"HTTP/1.1 200 OK\r\nHeader: value\r\n\r\n" {
            state = next_delimiter_match(state, *byte);
        }
        assert_eq!(state, 4);
    }
}
