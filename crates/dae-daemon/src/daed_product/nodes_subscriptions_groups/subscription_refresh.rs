use super::*;
pub(crate) fn refresh_subscription_from_remote(state: &Path, id: i64) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let Some(link) = conn
        .query_row(
            "SELECT link FROM subscriptions WHERE id = ?1",
            params![id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite_io_error)?
    else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "subscription not found",
        ));
    };
    let fetched_at = now_text();
    match fetch_subscription_content(&link) {
        Ok(content) => {
            let links = subscription_links_from_content(&content);
            let node_import_result = replace_subscription_nodes(&conn, id, &links)?;
            conn.execute(
                "UPDATE subscriptions SET updated_at = ?1, status = ?2, info = ?3 WHERE id = ?4",
                params![
                    fetched_at,
                    "fetched",
                    format!("{} node links fetched by Rust daed", links.len()),
                    id
                ],
            )
            .map_err(sqlite_io_error)?;
            Ok(json!({
                "link": link,
                "fetched": true,
                "fetchedAt": fetched_at,
                "nodeImportResult": node_import_result,
            }))
        }
        Err(err) => {
            conn.execute(
                "UPDATE subscriptions SET updated_at = ?1, status = ?2, info = ?3 WHERE id = ?4",
                params![fetched_at, "fetch_error", err.to_string(), id],
            )
            .map_err(sqlite_io_error)?;
            Ok(json!({
                "link": link,
                "fetched": false,
                "fetchedAt": fetched_at,
                "nodeImportResult": [{
                    "link": link,
                    "error": err.to_string(),
                    "node": Value::Null
                }],
            }))
        }
    }
}

pub(crate) fn replace_subscription_nodes(
    conn: &Connection,
    subscription_id: i64,
    links: &[String],
) -> io::Result<Vec<Value>> {
    let existing_nodes = existing_subscription_nodes(conn, subscription_id)?;
    let preserved_ids = preserved_subscription_node_ids(conn, subscription_id)?;
    let mut preserved_name_counts = HashMap::<String, usize>::new();
    let mut preserved_by_name = HashMap::<String, ExistingSubscriptionNode>::new();
    for node in existing_nodes
        .iter()
        .filter(|node| preserved_ids.contains(&node.id))
    {
        *preserved_name_counts.entry(node.name.clone()).or_default() += 1;
        preserved_by_name.insert(node.name.clone(), node.clone());
    }

    let mut candidates = Vec::<(String, ParsedNodeLink)>::new();
    let mut incoming_name_counts = HashMap::<String, usize>::new();
    for link in links {
        let parsed = parse_node_link(link.as_str(), None);
        *incoming_name_counts.entry(parsed.name.clone()).or_default() += 1;
        candidates.push((link.clone(), parsed));
    }

    for node in existing_nodes
        .iter()
        .filter(|node| !preserved_ids.contains(&node.id))
    {
        conn.execute(
            "DELETE FROM group_nodes WHERE node_id = ?1",
            params![node.id],
        )
        .map_err(sqlite_io_error)?;
        conn.execute(
            "DELETE FROM node_latency_results WHERE node_id = ?1",
            params![node.id],
        )
        .map_err(sqlite_io_error)?;
        conn.execute("DELETE FROM nodes WHERE id = ?1", params![node.id])
            .map_err(sqlite_io_error)?;
    }

    let mut out = Vec::new();
    let mut reused_preserved = HashSet::<i64>::new();
    for (link, parsed) in candidates {
        if incoming_name_counts.get(&parsed.name).copied().unwrap_or(0) == 1
            && preserved_name_counts
                .get(&parsed.name)
                .copied()
                .unwrap_or(0)
                == 1
            && let Some(preserved) = preserved_by_name.get(&parsed.name)
            && reused_preserved.insert(preserved.id)
        {
            if !subscription_node_changed(preserved, &link, &parsed) {
                out.push(json!({
                    "link": link,
                    "error": Value::Null,
                    "node": {"id": preserved.id}
                }));
                continue;
            }
            match conn.execute(
                "UPDATE nodes
                         SET link = ?1,
                             name = ?2,
                             address = ?3,
                             protocol = ?4,
                             tag = NULL,
                             subscription_id = ?5
                         WHERE id = ?6",
                params![
                    link,
                    parsed.name,
                    parsed.address,
                    parsed.protocol,
                    subscription_id,
                    preserved.id
                ],
            ) {
                Ok(_) => {
                    conn.execute(
                        "DELETE FROM node_latency_results WHERE node_id = ?1",
                        params![preserved.id],
                    )
                    .map_err(sqlite_io_error)?;
                    bump_group_versions_for_node(conn, preserved.id)?;
                    out.push(json!({
                        "link": link,
                        "error": Value::Null,
                        "node": {"id": preserved.id}
                    }));
                    continue;
                }
                Err(err) => {
                    out.push(json!({
                        "link": link,
                        "error": err.to_string(),
                        "node": Value::Null
                    }));
                    continue;
                }
            }
        }

        if subscription_node_link_exists(conn, subscription_id, &link)? {
            out.push(json!({
                "link": link,
                "error": "node duplicated",
                "node": Value::Null
            }));
            continue;
        }
        match conn.execute(
            "INSERT INTO nodes(link, name, address, protocol, tag, subscription_id) VALUES(?1, ?2, ?3, ?4, NULL, ?5)",
            params![link, parsed.name, parsed.address, parsed.protocol, subscription_id],
        ) {
            Ok(_) => {
                let id = conn.last_insert_rowid();
                out.push(json!({
                    "link": link,
                    "error": Value::Null,
                    "node": {"id": id}
                }));
            }
            Err(err) => out.push(json!({
                "link": link,
                "error": err.to_string(),
                "node": Value::Null
            })),
        }
    }
    bump_group_versions_for_subscription(conn, subscription_id)?;
    Ok(out)
}

#[derive(Clone)]
pub(crate) struct ExistingSubscriptionNode {
    pub(super) id: i64,
    pub(super) link: String,
    pub(super) name: String,
    pub(super) address: String,
    pub(super) protocol: String,
}

pub(crate) fn subscription_node_changed(
    current: &ExistingSubscriptionNode,
    next_link: &str,
    next: &ParsedNodeLink,
) -> bool {
    current.link != next_link
        || current.name != next.name
        || current.address != next.address
        || current.protocol != next.protocol
}

pub(crate) fn existing_subscription_nodes(
    conn: &Connection,
    subscription_id: i64,
) -> io::Result<Vec<ExistingSubscriptionNode>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, link, name, address, protocol
             FROM nodes
             WHERE subscription_id = ?1
             ORDER BY id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![subscription_id], |row| {
            Ok(ExistingSubscriptionNode {
                id: row.get(0)?,
                link: row.get(1)?,
                name: row.get(2)?,
                address: row.get(3)?,
                protocol: row.get(4)?,
            })
        })
        .map_err(sqlite_io_error)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(sqlite_io_error)?);
    }
    Ok(out)
}

pub(crate) fn preserved_subscription_node_ids(
    conn: &Connection,
    subscription_id: i64,
) -> io::Result<HashSet<i64>> {
    let mut stmt = conn
        .prepare(
            "SELECT DISTINCT n.id
             FROM nodes n
             JOIN group_nodes gn ON gn.node_id = n.id
             WHERE n.subscription_id = ?1",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![subscription_id], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)?;
    let mut out = HashSet::new();
    for row in rows {
        out.insert(row.map_err(sqlite_io_error)?);
    }
    Ok(out)
}

pub(crate) fn subscription_node_link_exists(
    conn: &Connection,
    subscription_id: i64,
    link: &str,
) -> io::Result<bool> {
    conn.query_row(
        "SELECT COUNT(*) FROM nodes WHERE subscription_id = ?1 AND link = ?2",
        params![subscription_id, link],
        |row| row.get::<_, i64>(0),
    )
    .map(|count| count > 0)
    .map_err(sqlite_io_error)
}

pub(crate) fn bump_group_versions_for_node(conn: &Connection, node_id: i64) -> io::Result<()> {
    conn.execute(
        "UPDATE groups
         SET version = version + 1
         WHERE id IN (SELECT group_id FROM group_nodes WHERE node_id = ?1)",
        params![node_id],
    )
    .map_err(sqlite_io_error)?;
    Ok(())
}

pub(crate) fn bump_group_versions_for_subscription(
    conn: &Connection,
    subscription_id: i64,
) -> io::Result<()> {
    conn.execute(
        "UPDATE groups
         SET version = version + 1
         WHERE id IN (
             SELECT group_id FROM group_subscriptions WHERE subscription_id = ?1
         )",
        params![subscription_id],
    )
    .map_err(sqlite_io_error)?;
    Ok(())
}

pub(crate) fn subscription_links_from_content(content: &str) -> Vec<String> {
    let direct = node_links_from_text(content);
    if !direct.is_empty() {
        return direct;
    }
    let compact = content.split_whitespace().collect::<String>();
    for candidate in [
        compact.clone(),
        compact.replace('-', "+").replace('_', "/"),
        format!("{compact}{}", "=".repeat((4 - compact.len() % 4) % 4)),
    ] {
        if let Ok(decoded) = STANDARD.decode(candidate.as_bytes()) {
            let decoded = String::from_utf8_lossy(&decoded);
            let links = node_links_from_text(&decoded);
            if !links.is_empty() {
                return links;
            }
        }
    }
    Vec::new()
}

pub(crate) fn node_links_from_text(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| line.contains("://"))
        .map(str::to_owned)
        .collect()
}

pub(crate) fn fetch_subscription_content(link: &str) -> io::Result<String> {
    let url = url::Url::parse(link)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    match url.scheme() {
        "http" => fetch_http_url(&url, false),
        "https" => fetch_http_url(&url, true),
        scheme => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported subscription scheme: {scheme}"),
        )),
    }
}

pub(crate) fn fetch_http_url(url: &url::Url, tls: bool) -> io::Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing host"))?;
    let port = url.port_or_known_default().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "missing port for subscription")
    })?;
    let mut path = url.path().to_owned();
    if path.is_empty() {
        path = "/".to_owned();
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: daed-rust-native/0.1\r\nAccept: text/plain, application/octet-stream, */*\r\nConnection: close\r\n\r\n"
    );
    let stream = connect_tcp_endpoint(host, port, Duration::from_secs(10))?;
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.set_write_timeout(Some(Duration::from_secs(20)))?;
    let response = if tls {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let server_name = ServerName::try_from(host.to_owned()).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid tls server name: {err}"),
            )
        })?;
        let conn = ClientConnection::new(config, server_name)
            .map_err(|err| io::Error::other(format!("tls connect: {err}")))?;
        let mut tls_stream = rustls::StreamOwned::new(conn, stream);
        tls_stream.write_all(request.as_bytes())?;
        tls_stream.flush()?;
        let mut response = Vec::new();
        tls_stream.read_to_end(&mut response)?;
        response
    } else {
        let mut stream = stream;
        stream.write_all(request.as_bytes())?;
        stream.flush()?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        response
    };
    http_response_body(&response)
}

pub(crate) fn http_response_body(response: &[u8]) -> io::Result<String> {
    let split = find_subsequence(response, b"\r\n\r\n")
        .or_else(|| find_subsequence(response, b"\n\n"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing http headers"))?;
    let header_end = if response.get(split..split + 4) == Some(b"\r\n\r\n") {
        split + 4
    } else {
        split + 2
    };
    let headers = String::from_utf8_lossy(&response[..split]);
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(0);
    if !(200..300).contains(&status) {
        return Err(io::Error::other(format!(
            "subscription fetch returned HTTP {status}"
        )));
    }
    let mut body = response[header_end..].to_vec();
    if headers
        .lines()
        .any(|line| line.to_ascii_lowercase().trim() == "transfer-encoding: chunked")
    {
        body = decode_chunked_body(&body)?;
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

pub(crate) fn decode_chunked_body(body: &[u8]) -> io::Result<Vec<u8>> {
    let mut index = 0;
    let mut out = Vec::new();
    while index < body.len() {
        let Some(line_end) = find_subsequence(&body[index..], b"\r\n") else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid chunked body",
            ));
        };
        let size_text = String::from_utf8_lossy(&body[index..index + line_end]);
        let size_text = size_text.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid chunk size: {err}"),
            )
        })?;
        index += line_end + 2;
        if size == 0 {
            break;
        }
        if index + size > body.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated chunked body",
            ));
        }
        out.extend_from_slice(&body[index..index + size]);
        index += size + 2;
    }
    Ok(out)
}
