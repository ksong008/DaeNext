use super::*;

pub(in crate::daed_product) fn build_runtime_config_from_content(
    content: &str,
) -> Result<Config, String> {
    let sections = parse_config(content).map_err(|err| err.to_string())?;
    build_config(&sections).map_err(|err| err.to_string())
}

pub(in crate::daed_product) fn materialize_runtime(
    state: &Path,
    config_dir: Option<&Path>,
    dry: bool,
) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let config = selected_section_raw(&conn, SectionKind::Config)?;
    let dns = selected_section_raw(&conn, SectionKind::Dns)?;
    let routing = selected_section_raw(&conn, SectionKind::Routing)?;
    let groups = list_groups_value(state)?;
    let nodes = list_all_nodes_value(state)?;
    let generated_at = now_text();
    let content = render_generated_config(
        &generated_at,
        config.as_ref(),
        dns.as_ref(),
        routing.as_ref(),
        &groups,
        &nodes,
    )?;
    let output_path = config_dir.map(|dir| dir.join("runtime").join("generated.dae"));
    if !dry {
        if let Some(path) = &output_path {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, &content)?;
            set_private_runtime_file_permissions(path)?;
            set_metadata(state, "last_generated_config_path", &path_string(path))?;
        }
        set_metadata(state, "last_materialized_at", &generated_at)?;
        conn.execute("DELETE FROM systems", [])
            .map_err(sqlite_io_error)?;
        conn.execute(
            "INSERT INTO systems(running, running_config_version, running_dns_version, running_routing_version, running_group_version_sum, running_group_ids, running_config_id, running_dns_id, running_routing_id)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                1_i64,
                config.as_ref().map(|(_, _, _, version)| *version).unwrap_or(0),
                dns.as_ref().map(|(_, _, _, version)| *version).unwrap_or(0),
                routing.as_ref().map(|(_, _, _, version)| *version).unwrap_or(0),
                group_version_sum(&conn)?,
                group_ids_text(&conn)?,
                config.as_ref().map(|(id, _, _, _)| *id),
                dns.as_ref().map(|(id, _, _, _)| *id),
                routing.as_ref().map(|(id, _, _, _)| *id),
            ],
        )
        .map_err(sqlite_io_error)?;
        set_metadata(state, "runtime_running", "true")?;
        clear_geodata_reload_pending(state)?;
    }
    let content_len = content.len();
    let mut report = Map::new();
    report.insert("filename".to_owned(), json!("generated.dae"));
    report.insert(
        "path".to_owned(),
        json!(output_path.as_ref().map(|path| path_string(path))),
    );
    report.insert("bytes".to_owned(), json!(content_len));
    report.insert("contentIncluded".to_owned(), json!(dry));
    if dry {
        report.insert("content".to_owned(), json!(content));
    }
    report.insert("generatedAt".to_owned(), json!(generated_at));
    report.insert(
        "selected".to_owned(),
        json!({
            "configId": config.as_ref().map(|(id, _, _, _)| *id),
            "dnsId": dns.as_ref().map(|(id, _, _, _)| *id),
            "routingId": routing.as_ref().map(|(id, _, _, _)| *id),
        }),
    );
    report.insert(
        "groups".to_owned(),
        json!(groups["items"].as_array().map(Vec::len).unwrap_or(0)),
    );
    report.insert(
        "nodes".to_owned(),
        json!(nodes["items"].as_array().map(Vec::len).unwrap_or(0)),
    );
    Ok(Value::Object(report))
}
