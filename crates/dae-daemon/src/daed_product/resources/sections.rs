use super::*;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SectionKind {
    Config,
    Dns,
    Routing,
}

impl SectionKind {
    pub(in crate::daed_product) fn from_path(path: &str) -> Option<Self> {
        if path == "/configs" || path.starts_with("/configs/") {
            Some(Self::Config)
        } else if path == "/dns" || path.starts_with("/dns/") {
            Some(Self::Dns)
        } else if path == "/routings" || path.starts_with("/routings/") {
            Some(Self::Routing)
        } else {
            None
        }
    }

    pub(in crate::daed_product) fn prefix(self) -> &'static str {
        match self {
            Self::Config => "/configs",
            Self::Dns => "/dns",
            Self::Routing => "/routings",
        }
    }

    pub(in crate::daed_product) fn table(self) -> &'static str {
        match self {
            Self::Config => "configs",
            Self::Dns => "dns",
            Self::Routing => "routings",
        }
    }

    pub(in crate::daed_product) fn value_column(self) -> &'static str {
        match self {
            Self::Config => "global",
            Self::Dns => "dns",
            Self::Routing => "routing",
        }
    }

    pub(in crate::daed_product) fn request_value_key(self) -> &'static str {
        match self {
            Self::Config => "global",
            Self::Dns => "dns",
            Self::Routing => "routing",
        }
    }

    pub(in crate::daed_product) fn default_name(self) -> &'static str {
        match self {
            Self::Config => "global",
            Self::Dns => "dns",
            Self::Routing => "routing",
        }
    }
}

pub(crate) fn api_section_preview(request: &HttpRequest, api_path: &str) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    if api_path == "/configs/parsed" {
        let global = if let Some(parsed_global) = body.get("parsedGlobal") {
            render_global_config_text(parsed_global)
        } else {
            body.get("global")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| DEFAULT_GLOBAL_RESOURCE_TEXT.to_owned())
        };
        let parsed = normalize_global_result(Some(&global));
        return HttpResponse::json(
            200,
            json!({
                "global": global,
                "parsedGlobal": parsed.value,
                "parseStatus": parsed.parse_status,
                "parseError": parsed.parse_error,
            }),
        );
    }
    if api_path == "/dns/parsed" {
        let raw = body.get("dns").and_then(Value::as_str).unwrap_or("");
        return HttpResponse::json(200, parsed_dns_value(raw));
    }
    let raw = body.get("routing").and_then(Value::as_str).unwrap_or("");
    HttpResponse::json(200, parsed_routing_value(raw))
}

pub(crate) fn list_sections(
    state: &Path,
    request: &HttpRequest,
    kind: SectionKind,
) -> HttpResponse {
    let result = if request_summary_enabled(request) {
        list_section_summaries_value(state, kind)
    } else {
        list_sections_value(state, kind)
    };
    match result {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(crate) fn request_summary_enabled(request: &HttpRequest) -> bool {
    request
        .query
        .get("summary")
        .and_then(|values| values.first())
        .and_then(|value| parse_boolish(value))
        .unwrap_or(false)
}

pub(crate) fn list_section_summaries_value(state: &Path, kind: SectionKind) -> io::Result<Value> {
    let conn = open_state_connection(state)?;
    let sql = format!(
        "SELECT id, name, selected, version FROM {} ORDER BY id",
        kind.table()
    );
    let mut stmt = conn.prepare(&sql).map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(section_summary_resource(
                row.get(0)?,
                row.get::<_, Option<String>>(1)?
                    .unwrap_or_else(|| kind.default_name().to_owned()),
                row.get::<_, i64>(2)? != 0,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(json!({"items": items}))
}

pub(crate) fn list_sections_value(state: &Path, kind: SectionKind) -> io::Result<Value> {
    let conn = open_state_connection(state)?;
    let sql = format!(
        "SELECT id, name, {}, selected, version FROM {} ORDER BY id",
        kind.value_column(),
        kind.table()
    );
    let mut stmt = conn.prepare(&sql).map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(section_resource(
                kind,
                row.get(0)?,
                row.get::<_, Option<String>>(1)?
                    .unwrap_or_else(|| kind.default_name().to_owned()),
                row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                row.get::<_, i64>(3)? != 0,
                row.get::<_, i64>(4)?,
            ))
        })
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(json!({"items": items}))
}

pub(crate) fn section_summary_resource(
    id: i64,
    name: String,
    selected: bool,
    version: i64,
) -> Value {
    json!({
        "id": id,
        "name": name,
        "selected": selected,
        "version": version,
        "parseStatus": "ok",
        "parseError": Value::Null,
    })
}

pub(crate) fn get_section(state: &Path, kind: SectionKind, id: i64) -> HttpResponse {
    match get_section_value(state, kind, id) {
        Ok(Some(value)) => HttpResponse::json(200, value),
        Ok(None) => HttpResponse::json(404, json!({"error": "resource not found"})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(crate) fn get_section_value(
    state: &Path,
    kind: SectionKind,
    id: i64,
) -> io::Result<Option<Value>> {
    let conn = open_state_connection(state)?;
    let sql = format!(
        "SELECT id, name, {}, selected, version FROM {} WHERE id = ?1",
        kind.value_column(),
        kind.table()
    );
    conn.query_row(&sql, params![id], |row| {
        Ok(section_resource(
            kind,
            row.get(0)?,
            row.get::<_, Option<String>>(1)?
                .unwrap_or_else(|| kind.default_name().to_owned()),
            row.get::<_, Option<String>>(2)?.unwrap_or_default(),
            row.get::<_, i64>(3)? != 0,
            row.get::<_, i64>(4)?,
        ))
    })
    .optional()
    .map_err(sqlite_io_error)
}

pub(crate) fn create_section(
    state: &Path,
    request: &HttpRequest,
    kind: SectionKind,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or(kind.default_name());
    let value = match validated_section_request_value(kind, &body) {
        Ok(value) => value,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let sql = format!(
        "INSERT INTO {}(name, {}, selected, version) VALUES(?1, ?2, 0, 0)",
        kind.table(),
        kind.value_column()
    );
    if let Err(err) = conn.execute(&sql, params![name, value]) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    let id = conn.last_insert_rowid();
    get_section(state, kind, id).with_status(201)
}

pub(crate) fn update_section(
    state: &Path,
    request: &HttpRequest,
    kind: SectionKind,
    id: i64,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let requested_value = if body.get(kind.request_value_key()).is_some()
        || (kind == SectionKind::Config && body.get("parsedGlobal").is_some())
    {
        match validated_section_request_value(kind, &body) {
            Ok(value) => Some(value),
            Err(err) => return HttpResponse::json(400, json!({"error": err})),
        }
    } else {
        None
    };
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Some(name) = body.get("name").and_then(Value::as_str) {
        let sql = format!(
            "UPDATE {} SET name = ?1, version = version + 1 WHERE id = ?2",
            kind.table()
        );
        if let Err(err) = conn.execute(&sql, params![name, id]) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
    }
    if let Some(value) = requested_value {
        let sql = format!(
            "UPDATE {} SET {} = ?1, version = version + 1 WHERE id = ?2",
            kind.table(),
            kind.value_column()
        );
        if let Err(err) = conn.execute(&sql, params![value, id]) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
    }
    get_section(state, kind, id)
}

pub(crate) fn delete_section(state: &Path, kind: SectionKind, id: i64) -> HttpResponse {
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let exists_sql = format!("SELECT 1 FROM {} WHERE id = ?1", kind.table());
    match conn
        .query_row(&exists_sql, params![id], |row| row.get::<_, i64>(0))
        .optional()
    {
        Ok(Some(_)) => {}
        Ok(None) => return HttpResponse::json(404, json!({"error": "resource not found"})),
        Err(err) => return HttpResponse::json(400, json!({"error": err.to_string()})),
    }
    match running_section_references_id(&conn, kind, id) {
        Ok(true) => {
            return HttpResponse::json(400, json!({"error": "running resource cannot be deleted"}));
        }
        Ok(false) => {}
        Err(err) => return HttpResponse::json(400, json!({"error": err.to_string()})),
    }
    let sql = format!("DELETE FROM {} WHERE id = ?1", kind.table());
    match conn.execute(&sql, params![id]) {
        Ok(removed) => HttpResponse::json(200, json!({"removed": removed})),
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

pub(crate) fn section_request_value(kind: SectionKind, body: &Value) -> String {
    if kind == SectionKind::Config
        && let Some(parsed_global) = body.get("parsedGlobal")
    {
        return render_global_config_text(parsed_global);
    }
    body.get(kind.request_value_key())
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_default()
}

fn validated_section_request_value(kind: SectionKind, body: &Value) -> Result<String, String> {
    let value = section_request_value(kind, body);
    if kind == SectionKind::Config {
        let complete = format!("{value}\nrouting {{ fallback: direct }}\n");
        build_runtime_config_from_content(&complete)
            .map_err(|err| format!("invalid rendered global config: {err}"))?;
    }
    Ok(value)
}

pub(crate) fn section_resource(
    kind: SectionKind,
    id: i64,
    name: String,
    raw: String,
    selected: bool,
    version: i64,
) -> Value {
    match kind {
        SectionKind::Config => {
            let parsed = normalize_global_result(Some(&raw));
            json!({
                "id": id,
                "name": name,
                "global": display_global_config_text(&raw),
                "selected": selected,
                "version": version,
                "parseStatus": parsed.parse_status,
                "parseError": parsed.parse_error,
                "parsedGlobal": parsed.value,
            })
        }
        SectionKind::Dns => {
            let mut value = parsed_dns_value(&raw);
            if let Value::Object(map) = &mut value {
                map.insert("id".to_owned(), json!(id));
                map.insert("name".to_owned(), json!(name));
                map.insert("dns".to_owned(), json!(raw));
                map.insert("selected".to_owned(), json!(selected));
                map.insert("version".to_owned(), json!(version));
            }
            value
        }
        SectionKind::Routing => {
            let mut value = parsed_routing_value(&raw);
            if let Value::Object(map) = &mut value {
                map.insert("id".to_owned(), json!(id));
                map.insert("name".to_owned(), json!(name));
                map.insert("routing".to_owned(), json!(raw));
                map.insert("selected".to_owned(), json!(selected));
                map.insert("version".to_owned(), json!(version));
            }
            value
        }
    }
}
