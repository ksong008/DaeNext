use super::*;

const SUBSCRIPTION_HTTP_HEADER_LIMIT: usize = 128 * 1024;
const SUBSCRIPTION_MAX_BYTES: usize = 8 * 1024 * 1024;
const SUBSCRIPTION_PERSIST_DIR: &str = "persist.d";

#[derive(Clone, Debug)]
struct SubscriptionSource {
    link: String,
    tag: Option<String>,
}

pub(crate) fn refresh_subscription_from_remote(
    state: &Path,
    config_dir: &Path,
    id: i64,
) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let Some(source) = conn
        .query_row(
            "SELECT link, tag FROM subscriptions WHERE id = ?1",
            params![id],
            |row| {
                Ok(SubscriptionSource {
                    link: row.get(0)?,
                    tag: row.get(1)?,
                })
            },
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
    match fetch_subscription_content(config_dir, source.tag.as_deref(), &source.link) {
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
                "link": source.link,
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
                "link": source.link,
                "fetched": false,
                "fetchedAt": fetched_at,
                "nodeImportResult": [{
                    "link": source.link,
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
    let mut existing_name_counts = HashMap::<String, usize>::new();
    let mut existing_by_name = HashMap::<String, ExistingSubscriptionNode>::new();
    for node in &existing_nodes {
        *existing_name_counts.entry(node.name.clone()).or_default() += 1;
        existing_by_name.insert(node.name.clone(), node.clone());
    }
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

    let mut reusable_by_name = HashMap::<String, ExistingSubscriptionNode>::new();
    for (name, incoming_count) in &incoming_name_counts {
        if *incoming_count != 1 {
            continue;
        }
        if preserved_name_counts.get(name).copied().unwrap_or(0) == 1 {
            if let Some(node) = preserved_by_name.get(name) {
                reusable_by_name.insert(name.clone(), node.clone());
            }
        } else if existing_name_counts.get(name).copied().unwrap_or(0) == 1
            && let Some(node) = existing_by_name.get(name)
        {
            reusable_by_name.insert(name.clone(), node.clone());
        }
    }
    let reusable_ids = reusable_by_name
        .values()
        .map(|node| node.id)
        .collect::<HashSet<_>>();

    for node in existing_nodes
        .iter()
        .filter(|node| !reusable_ids.contains(&node.id) && !preserved_ids.contains(&node.id))
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
    let mut reused_nodes = HashSet::<i64>::new();
    for (link, parsed) in candidates {
        if let Some(preserved) = reusable_by_name.get(&parsed.name)
            && reused_nodes.insert(preserved.id)
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
    if let Some(links) = sip008_links_from_content(content) {
        return links;
    }
    let direct = node_links_from_text(content);
    if !direct.is_empty() {
        return direct;
    }
    let compact = content.split_whitespace().collect::<String>();
    for candidate in [
        compact.clone(),
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
    for candidate in [
        compact.clone(),
        compact.trim_end_matches('=').to_owned(),
        compact.replace('+', "-").replace('/', "_"),
    ] {
        if let Ok(decoded) = URL_SAFE_NO_PAD.decode(candidate.as_bytes()) {
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

pub(crate) fn sip008_links_from_content(content: &str) -> Option<Vec<String>> {
    let value: Value = serde_json::from_str(content).ok()?;
    if value.get("version").and_then(Value::as_i64) != Some(1) {
        return None;
    }
    let servers = value.get("servers")?.as_array()?;
    let mut links = Vec::with_capacity(servers.len());
    for server in servers {
        if let Some(link) = sip008_server_to_ss_link(server) {
            links.push(link);
        }
    }
    Some(links)
}

fn sip008_server_to_ss_link(server: &Value) -> Option<String> {
    let host = server.get("server")?.as_str()?.trim();
    let port = server.get("server_port")?.as_u64()?;
    let method = server.get("method")?.as_str()?;
    let password = server.get("password")?.as_str()?;
    if host.is_empty() || port > u16::MAX as u64 || method.is_empty() {
        return None;
    }
    let mut url = url::Url::parse(&format!("ss://{}", format_host_port(host, port as u16))).ok()?;
    url.set_username(method).ok()?;
    url.set_password(Some(password)).ok()?;
    let plugin = server.get("plugin").and_then(Value::as_str).unwrap_or("");
    let plugin_opts = server
        .get("plugin_opts")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !plugin.is_empty() || !plugin_opts.is_empty() {
        let plugin_value = if plugin.is_empty() {
            plugin_opts.to_owned()
        } else if plugin_opts.is_empty() {
            plugin.to_owned()
        } else {
            format!("{plugin};{plugin_opts}")
        };
        url.query_pairs_mut().append_pair("plugin", &plugin_value);
    }
    if let Some(remarks) = server.get("remarks").and_then(Value::as_str)
        && !remarks.is_empty()
    {
        url.set_fragment(Some(remarks));
    }
    Some(url.to_string())
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.starts_with('[') || !host.contains(':') {
        format!("{host}:{port}")
    } else {
        format!("[{host}]:{port}")
    }
}

pub(crate) fn fetch_subscription_content(
    config_dir: &Path,
    tag: Option<&str>,
    link: &str,
) -> io::Result<String> {
    let url = url::Url::parse(link)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    match url.scheme() {
        "http" => fetch_http_url(&url, false),
        "https" => fetch_http_url(&url, true),
        "file" => read_subscription_file(&subscription_file_path(config_dir, &url)?),
        "http-file" | "https-file" => {
            let persist_path = persist_subscription_path(config_dir, tag)?;
            let fetch_url = url_with_scheme(&url, url.scheme().trim_end_matches("-file"))?;
            let fetched = match fetch_url.scheme() {
                "http" => fetch_http_url(&fetch_url, false),
                "https" => fetch_http_url(&fetch_url, true),
                scheme => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsupported subscription scheme: {scheme}"),
                )),
            };
            match fetched {
                Ok(content) => {
                    write_persisted_subscription(&persist_path, content.as_bytes())?;
                    Ok(content)
                }
                Err(fetch_err) => read_subscription_file(&persist_path).map_err(|read_err| {
                    io::Error::new(
                        read_err.kind(),
                        format!(
                            "fetch failed: {}; persisted subscription fallback failed: {}",
                            fetch_err, read_err
                        ),
                    )
                }),
            }
        }
        scheme => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported subscription scheme: {scheme}"),
        )),
    }
}

fn url_with_scheme(url: &url::Url, scheme: &str) -> io::Result<url::Url> {
    let prefix = format!("{}:", url.scheme());
    let rest = url.as_str().strip_prefix(&prefix).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid subscription scheme prefix",
        )
    })?;
    url::Url::parse(&format!("{scheme}:{rest}"))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))
}

pub(crate) fn subscription_file_path(config_dir: &Path, url: &url::Url) -> io::Result<PathBuf> {
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not support absolute path"))?;
    let mut path = confined_config_path(config_dir, host)?;
    push_confined_relative(&mut path, url.path().trim_start_matches('/'))?;
    Ok(path)
}

fn persist_subscription_path(config_dir: &Path, tag: Option<&str>) -> io::Result<PathBuf> {
    let tag = tag
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "subscription tag is required for http-file/https-file subscription",
            )
        })?;
    if tag == "." || tag == ".." || tag.contains('/') || tag.contains('\\') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("subscription tag {tag:?} cannot be used as a persist filename"),
        ));
    }
    let mut path = confined_config_path(config_dir, SUBSCRIPTION_PERSIST_DIR)?;
    push_confined_relative(&mut path, &format!("{tag}.sub"))?;
    Ok(path)
}

fn confined_config_path(config_dir: &Path, first: &str) -> io::Result<PathBuf> {
    let mut path = config_dir.to_path_buf();
    push_confined_relative(&mut path, first)?;
    Ok(path)
}

fn push_confined_relative(path: &mut PathBuf, relative: &str) -> io::Result<()> {
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(part) => path.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "subscription path escapes config directory",
                ));
            }
        }
    }
    Ok(())
}

fn read_subscription_file(path: &Path) -> io::Result<String> {
    let file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    if metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "subscription file cannot be a directory: {}",
                path.display()
            ),
        ));
    }
    reject_open_subscription_file_permissions(path, &metadata)?;
    let mut reader = io::BufReader::new(file);
    let buffer = reader.fill_buf()?;
    if buffer.first() == Some(&b'@') {
        let mut instruction = String::new();
        reader.read_line(&mut instruction)?;
    }
    let bytes = read_all_limited(&mut reader, subscription_http_body_limit())?;
    Ok(String::from_utf8_lossy(bytes.trim_ascii()).into_owned())
}

#[cfg(unix)]
fn reject_open_subscription_file_permissions(
    path: &Path,
    metadata: &fs::Metadata,
) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o037 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "permissions {mode:04o} for '{}' are too open; requires the file is not group-writable and not accessible by others; suggest 0640 or 0600",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_open_subscription_file_permissions(
    _path: &Path,
    _metadata: &fs::Metadata,
) -> io::Result<()> {
    Ok(())
}

fn write_persisted_subscription(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let Some(parent) = path.parent() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "persisted subscription path has no parent",
        ));
    };
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn read_all_limited<R: Read>(reader: &mut R, limit: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        let next_len = out.len().checked_add(read).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "subscription size overflow")
        })?;
        if next_len > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("subscription exceeds {limit} bytes"),
            ));
        }
        out.extend_from_slice(&buf[..read]);
    }
    Ok(out)
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
    let user_agent = subscription_user_agent();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\nAccept: text/plain, application/octet-stream, */*\r\nConnection: close\r\n\r\n"
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
        read_subscription_http_response(&mut tls_stream)?
    } else {
        let mut stream = stream;
        stream.write_all(request.as_bytes())?;
        stream.flush()?;
        read_subscription_http_response(&mut stream)?
    };
    http_response_body(&response)
}

fn subscription_user_agent() -> String {
    format!(
        "dae/{} (like v2rayA/1.0 WebRequestHelper) (like v2rayN/1.0 WebRequestHelper)",
        env!("CARGO_PKG_VERSION")
    )
}

fn read_subscription_http_response<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    read_subscription_http_response_with_limit(reader, subscription_http_body_limit())
}

pub(crate) fn read_subscription_http_response_with_limit<R: Read>(
    reader: &mut R,
    body_limit: usize,
) -> io::Result<Vec<u8>> {
    let response_limit = subscription_http_response_limit(body_limit)?;
    let mut response = Vec::new();
    let mut buf = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        let next_len = response.len().checked_add(read).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "subscription response size overflow",
            )
        })?;
        if next_len > response_limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("subscription response exceeds {response_limit} bytes"),
            ));
        }
        response.extend_from_slice(&buf[..read]);
    }
    Ok(response)
}

pub(crate) fn http_response_body(response: &[u8]) -> io::Result<String> {
    http_response_body_with_limit(response, subscription_http_body_limit())
}

pub(crate) fn http_response_body_with_limit(
    response: &[u8],
    body_limit: usize,
) -> io::Result<String> {
    let split = find_subsequence(response, b"\r\n\r\n")
        .or_else(|| find_subsequence(response, b"\n\n"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing http headers"))?;
    if split > SUBSCRIPTION_HTTP_HEADER_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "subscription response headers exceed {} bytes",
                SUBSCRIPTION_HTTP_HEADER_LIMIT
            ),
        ));
    }
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
    if body.len() > body_limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("subscription response body exceeds {body_limit} bytes"),
        ));
    }
    if headers
        .lines()
        .any(|line| line.to_ascii_lowercase().trim() == "transfer-encoding: chunked")
    {
        body = decode_chunked_body_with_limit(&body, body_limit)?;
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

#[cfg(test)]
pub(crate) fn decode_chunked_body(body: &[u8]) -> io::Result<Vec<u8>> {
    decode_chunked_body_with_limit(body, subscription_http_body_limit())
}

pub(crate) fn decode_chunked_body_with_limit(
    body: &[u8],
    body_limit: usize,
) -> io::Result<Vec<u8>> {
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
        let next_len = out.len().checked_add(size).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "decoded chunked body size overflow",
            )
        })?;
        if next_len > body_limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("decoded subscription body exceeds {body_limit} bytes"),
            ));
        }
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
        let data_end = index + size;
        if body.get(data_end..data_end + 2) != Some(b"\r\n") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked body chunk missing trailing CRLF",
            ));
        }
        index = data_end + 2;
    }
    Ok(out)
}

fn subscription_http_body_limit() -> usize {
    SUBSCRIPTION_MAX_BYTES
}

fn subscription_http_response_limit(body_limit: usize) -> io::Result<usize> {
    SUBSCRIPTION_HTTP_HEADER_LIMIT
        .checked_add(body_limit)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "subscription response limit overflow",
            )
        })
}
