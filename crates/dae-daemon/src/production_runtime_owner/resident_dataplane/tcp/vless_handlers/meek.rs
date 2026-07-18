use super::*;
use crate::production_runtime_owner::resident_dataplane::MeekTransportResourceProfile;
#[cfg(test)]
use crate::production_runtime_owner::resident_dataplane::ResidentRuntimeProfile;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MeekResponseFraming {
    ContentLength(usize),
    Chunked,
    CloseDelimited,
}

#[derive(Debug)]
struct MeekResponseHead {
    framing: MeekResponseFraming,
}

struct MeekBodyReader<'a, R> {
    client: &'a mut R,
    buffered: VecDeque<u8>,
    deadline: dae_runtime_control::AbsoluteDeadline,
    wire_bytes: usize,
    wire_limit: usize,
}

pub(crate) fn meek_options_from_proxy(
    selection: &TcpProxySelection,
    peer: SocketAddr,
    original_dst: SocketAddr,
) -> MeekRoundTripOptions {
    MeekRoundTripOptions {
        url: format!(
            "https://{}{}",
            selection.proxy.stream_host, selection.proxy.stream_path
        ),
        host: selection.proxy.stream_host.clone(),
        path: selection.proxy.stream_path.clone(),
        session_tag: format!("{}|{}|{}", selection.proxy.graph_id, peer, original_dst).into_bytes(),
    }
}

pub(crate) async fn meek_round_trip_async(
    proxy: &ResidentProxyPlan,
    options: &MeekRoundTripOptions,
    body: &[u8],
) -> Result<Vec<u8>, String> {
    let resources = MeekTransportResourceProfile::selected();
    if body.len() > dae_outbound::shared_transport::contract::MEEK_MAX_WRITE {
        return Err(format!(
            "Meek polling request body exceeds the selected limit ({})",
            dae_outbound::shared_transport::contract::MEEK_MAX_WRITE
        ));
    }
    let request = meek_http_request(options, body);
    let request_header_bytes = request.len().saturating_sub(body.len());
    if request_header_bytes > resources.response_header_bytes() {
        return Err(format!(
            "Meek polling request header exceeds the selected limit ({})",
            resources.response_header_bytes()
        ));
    }

    let deadline =
        dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), RESIDENT_CONNECT_TIMEOUT);
    let remaining = meek_deadline_remaining(deadline, "open Meek TLS carrier")?;
    let mut client = time::timeout(remaining, open_async_resident_tls_client(proxy))
        .await
        .map_err(|_| "open Meek TLS carrier deadline elapsed".to_owned())??;
    let negotiated_alpn = client.negotiated_alpn().map(<[u8]>::to_vec);
    match negotiated_alpn.as_deref() {
        None | Some(b"http/1.1") => {}
        Some(protocol) => {
            client.shutdown().await;
            return Err(format!(
                "Meek HTTP/1.1 carrier negotiated unsupported ALPN {}",
                String::from_utf8_lossy(protocol)
            ));
        }
    }

    let result = async {
        let remaining = meek_deadline_remaining(deadline, "write Meek polling request")?;
        time::timeout(
            remaining,
            client.write_plain_all(&request, "write Meek polling request"),
        )
        .await
        .map_err(|_| "write Meek polling request deadline elapsed".to_owned())??;
        read_meek_http_response_body_async(&mut client, deadline, resources).await
    }
    .await;
    if let Some(remaining) = deadline.remaining_at(Instant::now()) {
        let _ = time::timeout(remaining, client.shutdown()).await;
    }
    result
}

fn meek_deadline_remaining(
    deadline: dae_runtime_control::AbsoluteDeadline,
    operation: &str,
) -> Result<Duration, String> {
    deadline
        .remaining_at(Instant::now())
        .ok_or_else(|| format!("{operation} deadline elapsed"))
}

pub(crate) async fn read_meek_http_response_body_async<R>(
    client: &mut R,
    deadline: dae_runtime_control::AbsoluteDeadline,
    resources: MeekTransportResourceProfile,
) -> Result<Vec<u8>, String>
where
    R: AsyncRead + Unpin,
{
    let mut data = Vec::new();
    let mut buf = [0_u8; 1024];
    let head_end = loop {
        let read = read_meek_bytes(client, &mut buf, deadline, "read Meek response head").await?;
        if read == 0 {
            return Err("Meek response closed before header".to_owned());
        }
        data.extend_from_slice(&buf[..read]);
        if let Some(index) = data.windows(4).position(|window| window == b"\r\n\r\n") {
            let head_end = index + 4;
            if head_end > resources.response_header_bytes() {
                return Err(format!(
                    "Meek response header exceeds the selected limit ({})",
                    resources.response_header_bytes()
                ));
            }
            break head_end;
        }
        if data.len() > resources.response_header_bytes() {
            return Err(format!(
                "Meek response header exceeds the selected limit ({})",
                resources.response_header_bytes()
            ));
        }
    };
    let head = MeekResponseHead::parse(&data[..head_end], resources.response_body_bytes())?;
    let wire_bytes = data.len();
    let body_prefix = data.split_off(head_end);
    let reader = MeekBodyReader {
        client,
        buffered: VecDeque::from(body_prefix),
        deadline,
        wire_bytes,
        wire_limit: resources.response_wire_bytes(),
    };
    match head.framing {
        MeekResponseFraming::ContentLength(length) => reader.read_content_length(length).await,
        MeekResponseFraming::Chunked => reader.read_chunked(resources.response_body_bytes()).await,
        MeekResponseFraming::CloseDelimited => {
            reader
                .read_close_delimited(resources.response_body_bytes())
                .await
        }
    }
}

async fn read_meek_bytes<R>(
    client: &mut R,
    buf: &mut [u8],
    deadline: dae_runtime_control::AbsoluteDeadline,
    operation: &str,
) -> Result<usize, String>
where
    R: AsyncRead + Unpin,
{
    let remaining = meek_deadline_remaining(deadline, operation)?;
    time::timeout(remaining, client.read(buf))
        .await
        .map_err(|_| format!("{operation} deadline elapsed"))?
        .map_err(|error| format!("{operation}: {error}"))
}

impl MeekResponseHead {
    fn parse(head: &[u8], body_limit: usize) -> Result<Self, String> {
        validate_http_status(head, 200)
            .map_err(|error| format!("validate Meek response: {error}"))?;
        let text = std::str::from_utf8(head)
            .map_err(|error| format!("Meek response head utf8: {error}"))?;
        let mut content_length = None;
        let mut transfer_encodings = Vec::new();
        for line in text.split("\r\n").skip(1) {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if name.eq_ignore_ascii_case("content-length") {
                if content_length.is_some() {
                    return Err("Meek response contains duplicate Content-Length".to_owned());
                }
                let parsed = value
                    .trim()
                    .parse::<usize>()
                    .map_err(|error| format!("parse Meek response Content-Length: {error}"))?;
                if parsed > body_limit {
                    return Err(format!(
                        "Meek response body exceeds the selected limit ({body_limit})"
                    ));
                }
                content_length = Some(parsed);
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                transfer_encodings.extend(
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|encoding| !encoding.is_empty())
                        .map(str::to_ascii_lowercase),
                );
            }
        }
        if !transfer_encodings.is_empty() {
            if content_length.is_some() {
                return Err(
                    "Meek response cannot combine Transfer-Encoding and Content-Length".to_owned(),
                );
            }
            if transfer_encodings.as_slice() != ["chunked"] {
                return Err("Meek response uses an unsupported Transfer-Encoding".to_owned());
            }
            return Ok(Self {
                framing: MeekResponseFraming::Chunked,
            });
        }
        Ok(Self {
            framing: content_length.map_or(
                MeekResponseFraming::CloseDelimited,
                MeekResponseFraming::ContentLength,
            ),
        })
    }
}

impl<R> MeekBodyReader<'_, R>
where
    R: AsyncRead + Unpin,
{
    async fn fill(&mut self, operation: &str) -> Result<usize, String> {
        let mut buf = [0_u8; 1024];
        let read = read_meek_bytes(self.client, &mut buf, self.deadline, operation).await?;
        self.wire_bytes = self.wire_bytes.saturating_add(read);
        if self.wire_bytes > self.wire_limit {
            return Err(format!(
                "Meek response wire bytes exceed the selected limit ({})",
                self.wire_limit
            ));
        }
        self.buffered.extend(&buf[..read]);
        Ok(read)
    }

    async fn read_content_length(mut self, length: usize) -> Result<Vec<u8>, String> {
        if self.buffered.len() > length {
            return Err("Meek response contains bytes beyond Content-Length".to_owned());
        }
        let mut body = Vec::with_capacity(length);
        body.extend(self.buffered.drain(..));
        while body.len() < length {
            let read = self.fill("read Meek response body").await?;
            if read == 0 {
                return Err("Meek response closed before Content-Length was satisfied".to_owned());
            }
            let remaining = length - body.len();
            if self.buffered.len() > remaining {
                return Err("Meek response contains bytes beyond Content-Length".to_owned());
            }
            body.extend(self.buffered.drain(..));
        }
        Ok(body)
    }

    async fn read_close_delimited(mut self, body_limit: usize) -> Result<Vec<u8>, String> {
        let mut body = Vec::new();
        loop {
            if body.len().saturating_add(self.buffered.len()) > body_limit {
                return Err(format!(
                    "Meek response body exceeds the selected limit ({body_limit})"
                ));
            }
            body.extend(self.buffered.drain(..));
            if self.fill("read close-delimited Meek response body").await? == 0 {
                return Ok(body);
            }
        }
    }

    async fn read_chunked(mut self, body_limit: usize) -> Result<Vec<u8>, String> {
        let mut body = Vec::new();
        loop {
            let size_line = self.read_line("read Meek chunk size").await?;
            let size_text = size_line
                .split_once(';')
                .map_or(size_line.as_str(), |(size, _)| size)
                .trim();
            let size = usize::from_str_radix(size_text, 16)
                .map_err(|error| format!("parse Meek response chunk size: {error}"))?;
            if size == 0 {
                loop {
                    if self.read_line("read Meek chunk trailer").await?.is_empty() {
                        return Ok(body);
                    }
                }
            }
            if body.len().saturating_add(size) > body_limit {
                return Err(format!(
                    "Meek response body exceeds the selected limit ({body_limit})"
                ));
            }
            self.read_exact_into(&mut body, size).await?;
            let ending = self.read_exact(2, "read Meek chunk terminator").await?;
            if ending.as_slice() != b"\r\n" {
                return Err("Meek response chunk is missing its terminating CRLF".to_owned());
            }
        }
    }

    async fn read_line(&mut self, operation: &str) -> Result<String, String> {
        loop {
            let contiguous = self.buffered.make_contiguous();
            if let Some(index) = contiguous.windows(2).position(|window| window == b"\r\n") {
                let line = self.buffered.drain(..index).collect::<Vec<_>>();
                self.buffered.drain(..2);
                return String::from_utf8(line)
                    .map_err(|error| format!("{operation} is not valid UTF-8: {error}"));
            }
            if self.buffered.len() > 1024 {
                return Err(format!("{operation} exceeds the line limit (1024)"));
            }
            if self.fill(operation).await? == 0 {
                return Err(format!("{operation} closed before CRLF"));
            }
        }
    }

    async fn read_exact_into(&mut self, output: &mut Vec<u8>, length: usize) -> Result<(), String> {
        let bytes = self.read_exact(length, "read Meek chunk data").await?;
        output.extend_from_slice(&bytes);
        Ok(())
    }

    async fn read_exact(&mut self, length: usize, operation: &str) -> Result<Vec<u8>, String> {
        while self.buffered.len() < length {
            if self.fill(operation).await? == 0 {
                return Err(format!("{operation} closed before completion"));
            }
        }
        Ok(self.buffered.drain(..length).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn read_test_response(response: &[u8]) -> Result<Vec<u8>, String> {
        let (mut client, mut server) = tokio::io::duplex(response.len().max(64));
        let response = response.to_vec();
        let writer = tokio::spawn(async move {
            server.write_all(&response).await.unwrap();
            server.shutdown().await.unwrap();
        });
        let result = read_meek_http_response_body_async(
            &mut client,
            dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), Duration::from_secs(1)),
            MeekTransportResourceProfile::from_runtime_profile(ResidentRuntimeProfile::LowMemory),
        )
        .await;
        writer.await.unwrap();
        result
    }

    #[test]
    fn meek_response_head_selects_strict_bounded_framing() {
        assert_eq!(
            MeekResponseHead::parse(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n", 8)
                .unwrap()
                .framing,
            MeekResponseFraming::ContentLength(7)
        );
        assert_eq!(
            MeekResponseHead::parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", 8,)
                .unwrap()
                .framing,
            MeekResponseFraming::Chunked
        );
        assert_eq!(
            MeekResponseHead::parse(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", 8)
                .unwrap()
                .framing,
            MeekResponseFraming::CloseDelimited
        );
    }

    #[test]
    fn meek_response_head_rejects_ambiguous_or_oversized_framing() {
        assert!(
            MeekResponseHead::parse(
                b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
                8,
            )
            .unwrap_err()
            .contains("cannot combine")
        );
        assert!(
            MeekResponseHead::parse(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n", 8)
                .unwrap_err()
                .contains("selected limit")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn meek_response_reader_decodes_chunked_and_close_delimited_bodies() {
        assert_eq!(
            read_test_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\nX-End: yes\r\n\r\n",
            )
            .await
            .unwrap(),
            b"abcde"
        );
        assert_eq!(
            read_test_response(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nclose-body")
                .await
                .unwrap(),
            b"close-body"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn meek_response_reader_rejects_short_or_trailing_content_length() {
        let short = read_test_response(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc")
            .await
            .unwrap_err();
        assert!(short.contains("before Content-Length"), "{short}");

        let trailing = read_test_response(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcd")
            .await
            .unwrap_err();
        assert!(trailing.contains("beyond Content-Length"), "{trailing}");
    }
}
