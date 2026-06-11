use super::*;

pub(in crate::daed_product) fn selected_section_raw(
    conn: &Connection,
    kind: SectionKind,
) -> io::Result<Option<(i64, String, String, i64)>> {
    let sql = format!(
        "SELECT id, name, {}, version FROM {} WHERE selected = 1 ORDER BY id LIMIT 1",
        kind.value_column(),
        kind.table()
    );
    let selected = conn
        .query_row(&sql, [], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .optional()
        .map_err(sqlite_io_error)?;
    if selected.is_some() {
        return Ok(selected);
    }
    let sql = format!(
        "SELECT id, name, {}, version FROM {} ORDER BY id LIMIT 1",
        kind.value_column(),
        kind.table()
    );
    conn.query_row(&sql, [], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })
    .optional()
    .map_err(sqlite_io_error)
}

pub(in crate::daed_product) fn selected_id(
    conn: &Connection,
    kind: SectionKind,
) -> io::Result<Option<i64>> {
    let sql = format!(
        "SELECT id FROM {} WHERE selected = 1 ORDER BY id LIMIT 1",
        kind.table()
    );
    conn.query_row(&sql, [], |row| row.get::<_, i64>(0))
        .optional()
        .map_err(sqlite_io_error)
}

pub(in crate::daed_product) fn group_version_sum(conn: &Connection) -> io::Result<i64> {
    conn.query_row("SELECT COALESCE(SUM(version), 0) FROM groups", [], |row| {
        row.get(0)
    })
    .map_err(sqlite_io_error)
}

pub(in crate::daed_product) fn group_ids_text(conn: &Connection) -> io::Result<String> {
    let mut stmt = conn
        .prepare("SELECT id FROM groups ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)?;
    let mut ids = Vec::new();
    for row in rows {
        ids.push(row.map_err(sqlite_io_error)?.to_string());
    }
    Ok(ids.join(","))
}
