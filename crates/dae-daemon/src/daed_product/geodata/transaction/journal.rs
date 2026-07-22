use super::files::{remove_file_if_exists, sync_directory};
use super::*;
use serde::{Deserialize, Serialize};

const GEODATA_JOURNAL_FORMAT_VERSION: u32 = 1;
const GEODATA_JOURNAL_MAX_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(in crate::daed_product::geodata) enum GeodataJournalPhase {
    Activating,
    FilesActivated,
    RollingBack,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::daed_product::geodata) struct GeodataUpdateJournal {
    format_version: u32,
    kind: String,
    pub(in crate::daed_product::geodata) phase: GeodataJournalPhase,
    pub(super) data_stage: String,
    pub(super) version_stage: String,
    pub(super) data_backup: Option<String>,
    pub(super) version_backup: Option<String>,
    pub(super) external_input_version_before: Option<i64>,
    #[serde(default)]
    pub(super) geodata_input_version_before: Option<i64>,
}

impl GeodataUpdateJournal {
    pub(in crate::daed_product::geodata) fn new(
        kind: GeodataKind,
        data_stage: &Path,
        version_stage: &Path,
        data_backup: Option<&Path>,
        version_backup: Option<&Path>,
        external_input_version_before: Option<i64>,
        geodata_input_version_before: Option<i64>,
    ) -> io::Result<Self> {
        let journal = Self {
            format_version: GEODATA_JOURNAL_FORMAT_VERSION,
            kind: kind.response_key().to_owned(),
            phase: GeodataJournalPhase::Activating,
            data_stage: artifact_file_name(data_stage)?,
            version_stage: artifact_file_name(version_stage)?,
            data_backup: data_backup.map(artifact_file_name).transpose()?,
            version_backup: version_backup.map(artifact_file_name).transpose()?,
            external_input_version_before,
            geodata_input_version_before,
        };
        journal.validate(kind)?;
        Ok(journal)
    }

    pub(super) fn validate(&self, expected_kind: GeodataKind) -> io::Result<()> {
        if self.format_version != GEODATA_JOURNAL_FORMAT_VERSION {
            return Err(invalid_journal("unsupported geodata journal format"));
        }
        if self.kind != expected_kind.response_key() {
            return Err(invalid_journal("geodata journal kind mismatch"));
        }
        validate_artifact_name(&self.data_stage, expected_kind, "download")?;
        validate_artifact_name(&self.version_stage, expected_kind, "version")?;
        if let Some(name) = self.data_backup.as_deref() {
            validate_artifact_name(name, expected_kind, "data-backup")?;
        }
        if let Some(name) = self.version_backup.as_deref() {
            validate_artifact_name(name, expected_kind, "version-backup")?;
        }
        if self
            .external_input_version_before
            .is_some_and(|value| value < 0)
        {
            return Err(invalid_journal(
                "geodata journal external input version is negative",
            ));
        }
        if self
            .geodata_input_version_before
            .is_some_and(|value| value < 0)
        {
            return Err(invalid_journal(
                "geodata journal geodata input version is negative",
            ));
        }
        Ok(())
    }

    pub(super) fn artifact_path(&self, dir: &Path, name: &str) -> PathBuf {
        dir.join(name)
    }

    pub(super) fn artifact_paths(&self, dir: &Path) -> Vec<PathBuf> {
        let mut paths = vec![
            self.artifact_path(dir, &self.data_stage),
            self.artifact_path(dir, &self.version_stage),
        ];
        if let Some(name) = self.data_backup.as_deref() {
            paths.push(self.artifact_path(dir, name));
        }
        if let Some(name) = self.version_backup.as_deref() {
            paths.push(self.artifact_path(dir, name));
        }
        paths
    }
}

pub(super) fn read_geodata_journal(
    dir: &Path,
    kind: GeodataKind,
) -> io::Result<Option<GeodataUpdateJournal>> {
    let path = geodata_journal_path(dir, kind);
    let metadata = match fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if metadata.len() > GEODATA_JOURNAL_MAX_BYTES {
        return Err(invalid_journal("geodata journal exceeds size limit"));
    }
    let journal: GeodataUpdateJournal = serde_json::from_slice(&fs::read(&path)?)
        .map_err(|error| invalid_journal(format!("parse geodata update journal: {error}")))?;
    journal.validate(kind)?;
    Ok(Some(journal))
}

pub(in crate::daed_product::geodata) fn write_geodata_journal(
    dir: &Path,
    kind: GeodataKind,
    journal: &GeodataUpdateJournal,
) -> io::Result<()> {
    journal.validate(kind)?;
    let path = geodata_journal_path(dir, kind);
    let next = geodata_journal_next_path(dir, kind);
    let bytes = serde_json::to_vec(journal).map_err(io::Error::other)?;
    if bytes.len() as u64 > GEODATA_JOURNAL_MAX_BYTES {
        return Err(invalid_journal("geodata journal exceeds size limit"));
    }
    let write_result = (|| {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&next)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&next, &path)?;
        sync_directory(dir)
    })();
    if write_result.is_err() {
        let _ = remove_file_if_exists(&next);
    }
    write_result
}

pub(super) fn remove_geodata_journal_durable(dir: &Path, kind: GeodataKind) -> io::Result<()> {
    remove_file_if_exists(&geodata_journal_path(dir, kind))?;
    remove_file_if_exists(&geodata_journal_next_path(dir, kind))?;
    sync_directory(dir)
}

pub(super) fn remove_geodata_journal_next(dir: &Path, kind: GeodataKind) -> io::Result<()> {
    remove_file_if_exists(&geodata_journal_next_path(dir, kind))
}

fn geodata_journal_path(dir: &Path, kind: GeodataKind) -> PathBuf {
    dir.join(format!(".{}.update-journal.json", kind.file_name()))
}

fn geodata_journal_next_path(dir: &Path, kind: GeodataKind) -> PathBuf {
    dir.join(format!(".{}.update-journal.next", kind.file_name()))
}

fn artifact_file_name(path: &Path) -> io::Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| invalid_journal("geodata transaction artifact has no UTF-8 filename"))
}

fn validate_artifact_name(name: &str, kind: GeodataKind, purpose: &str) -> io::Result<()> {
    let path = Path::new(name);
    let mut components = path.components();
    let single_normal_component =
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
    let expected_prefix = format!(".{}.{}.tmp.", kind.file_name(), purpose);
    if !single_normal_component || !name.starts_with(&expected_prefix) {
        return Err(invalid_journal(format!(
            "invalid geodata transaction artifact name: {name}"
        )));
    }
    Ok(())
}

fn invalid_journal(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
