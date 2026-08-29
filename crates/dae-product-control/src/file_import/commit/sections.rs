use super::*;
use rusqlite::Transaction;

pub(super) struct ImportedSection {
    pub(super) id: i64,
    pub(super) name: String,
    pub(super) value: String,
    pub(super) version: i64,
}

pub(super) fn upsert_imported_section(
    tx: &Transaction<'_>,
    kind: SectionKind,
    name: &str,
    value: &str,
) -> io::Result<ImportedSection> {
    let select_sql = format!(
        "SELECT id, version FROM {} WHERE name = ?1 ORDER BY id LIMIT 1",
        kind.table()
    );
    let existing = tx
        .query_row(&select_sql, params![name], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })
        .optional()
        .map_err(sqlite_io_error)?;
    let (id, version) = if let Some((id, version)) = existing {
        let update_sql = format!(
            "UPDATE {} SET {} = ?1, version = version + 1 WHERE id = ?2",
            kind.table(),
            kind.value_column()
        );
        tx.execute(&update_sql, params![value, id])
            .map_err(sqlite_io_error)?;
        (id, version.saturating_add(1))
    } else {
        let insert_sql = format!(
            "INSERT INTO {}(name, {}, selected, version) VALUES(?1, ?2, 0, 0)",
            kind.table(),
            kind.value_column()
        );
        tx.execute(&insert_sql, params![name, value])
            .map_err(sqlite_io_error)?;
        (tx.last_insert_rowid(), 0)
    };
    Ok(ImportedSection {
        id,
        name: name.to_owned(),
        value: value.to_owned(),
        version,
    })
}

pub(super) fn select_imported_section(
    tx: &Transaction<'_>,
    kind: SectionKind,
    id: i64,
) -> io::Result<()> {
    let exists_sql = format!("SELECT 1 FROM {} WHERE id = ?1", kind.table());
    let exists = tx
        .query_row(&exists_sql, params![id], |row| row.get::<_, i64>(0))
        .optional()
        .map_err(sqlite_io_error)?
        .is_some();
    if !exists {
        return Err(invalid_dae_file(format!(
            "imported {} resource {id} disappeared before selection",
            kind.table()
        )));
    }
    let clear_sql = format!("UPDATE {} SET selected = 0", kind.table());
    let set_sql = format!("UPDATE {} SET selected = 1 WHERE id = ?1", kind.table());
    tx.execute(&clear_sql, []).map_err(sqlite_io_error)?;
    tx.execute(&set_sql, params![id]).map_err(sqlite_io_error)?;
    Ok(())
}
