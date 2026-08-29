use super::super::transaction::{
    GeodataCommitResult, GeodataJournalPhase, GeodataTransactionCheckpoint, GeodataUpdateJournal,
    PreparedGeodataGeneration, RuntimeInputVersions, commit_geodata_generation_with_checkpoints,
    recover_geodata_transaction, write_geodata_journal,
};
use super::*;
use dae_product_control::geodata::{sha256_file, summarize_geodata_file};

mod faults;
mod recovery;

struct GeodataTransactionFixture {
    dir: PathBuf,
    state: PathBuf,
    coordinator: ProductGeodataUpdateCoordinator,
    data_stage: PathBuf,
    summary: dae_geodata::GeoDataSummary,
    sha256: String,
    old_data: Vec<u8>,
    new_data: Vec<u8>,
}

impl GeodataTransactionFixture {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "daed-product-geodata-transaction-{label}-{}",
            fastrand::u64(..)
        ));
        fs::create_dir_all(&dir).unwrap();
        let state = dir.join("daed.db");
        ensure_state_schema(&state).unwrap();
        let old_data = geosite_payload("old", &["old.example"]);
        let new_data = geosite_payload("new", &["one.example", "two.example"]);
        fs::write(dir.join(GEOSITE_FILE), &old_data).unwrap();
        fs::write(
            dir.join(GeodataKind::Geosite.version_file_name()),
            "old-tag\n",
        )
        .unwrap();
        let coordinator = ProductGeodataUpdateCoordinator::default();
        let data_stage = coordinator
            .reserve_staging_path(&dir, GeodataKind::Geosite, "download")
            .unwrap();
        write_synced(&data_stage, &new_data);
        let summary = summarize_geodata_file(GeodataKind::Geosite, &data_stage).unwrap();
        let sha256 = sha256_file(&data_stage).unwrap();
        Self {
            dir,
            state,
            coordinator,
            data_stage,
            summary,
            sha256,
            old_data,
            new_data,
        }
    }

    fn commit(
        &self,
        external_input_version_before: Option<i64>,
        checkpoints: &mut dyn FaultCheckpoints<GeodataTransactionCheckpoint>,
    ) -> io::Result<GeodataCommitResult> {
        commit_geodata_generation_with_checkpoints(
            &self.coordinator,
            &self.state,
            &self.dir,
            GeodataKind::Geosite,
            PreparedGeodataGeneration {
                data_stage: self.data_stage.clone(),
                version: "new-tag".to_owned(),
                summary: self.summary,
                sha256: self.sha256.clone(),
                input_versions_before: self.input_versions(external_input_version_before),
            },
            checkpoints,
        )
    }

    fn prepare_crash_journal(
        &self,
        external_input_version_before: Option<i64>,
    ) -> (GeodataUpdateJournal, PathBuf) {
        let version_stage = self
            .coordinator
            .reserve_staging_path(&self.dir, GeodataKind::Geosite, "version")
            .unwrap();
        write_synced(&version_stage, b"new-tag\n");
        let data_backup = self
            .coordinator
            .reserve_staging_path(&self.dir, GeodataKind::Geosite, "data-backup")
            .unwrap();
        copy_synced(&self.dir.join(GEOSITE_FILE), &data_backup);
        let version_backup = self
            .coordinator
            .reserve_staging_path(&self.dir, GeodataKind::Geosite, "version-backup")
            .unwrap();
        copy_synced(
            &self.dir.join(GeodataKind::Geosite.version_file_name()),
            &version_backup,
        );
        fs::File::open(&self.dir).unwrap().sync_all().unwrap();
        let journal = GeodataUpdateJournal::new(
            GeodataKind::Geosite,
            &self.data_stage,
            &version_stage,
            Some(&data_backup),
            Some(&version_backup),
            external_input_version_before,
            self.input_versions(external_input_version_before)
                .map(|versions| versions.geodata),
        )
        .unwrap();
        write_geodata_journal(&self.dir, GeodataKind::Geosite, &journal).unwrap();
        (journal, version_stage)
    }

    fn input_versions(&self, external: Option<i64>) -> Option<RuntimeInputVersions> {
        external.map(|external| {
            let conn = open_state_connection(&self.state).unwrap();
            RuntimeInputVersions {
                external,
                geodata: current_runtime_geodata_input_version(&conn).unwrap(),
            }
        })
    }

    fn assert_old_generation(&self) {
        assert_eq!(
            fs::read(self.dir.join(GEOSITE_FILE)).unwrap(),
            self.old_data
        );
        assert_eq!(
            fs::read_to_string(self.dir.join(GeodataKind::Geosite.version_file_name())).unwrap(),
            "old-tag\n"
        );
    }

    fn assert_new_generation(&self) {
        assert_eq!(
            fs::read(self.dir.join(GEOSITE_FILE)).unwrap(),
            self.new_data
        );
        assert_eq!(
            fs::read_to_string(self.dir.join(GeodataKind::Geosite.version_file_name())).unwrap(),
            "new-tag\n"
        );
    }

    fn cleanup(self) {
        fs::remove_dir_all(self.dir).unwrap();
    }
}

struct FailCheckpoint {
    point: GeodataTransactionCheckpoint,
}

impl FaultCheckpoints<GeodataTransactionCheckpoint> for FailCheckpoint {
    fn checkpoint(&mut self, point: GeodataTransactionCheckpoint) -> io::Result<()> {
        if point == self.point {
            Err(io::Error::other(format!("injected {point:?} failure")))
        } else {
            Ok(())
        }
    }
}

struct PassCheckpoints;

impl FaultCheckpoints<GeodataTransactionCheckpoint> for PassCheckpoints {
    fn checkpoint(&mut self, _point: GeodataTransactionCheckpoint) -> io::Result<()> {
        Ok(())
    }
}

fn geosite_payload(category: &str, domains: &[&str]) -> Vec<u8> {
    let mut entry = vec![field_string(1, &format!("geosite:{category}"))];
    entry.extend(
        domains
            .iter()
            .map(|domain| field_message(2, message([field_string(2, domain)]))),
    );
    message([field_message(1, message(entry))])
}

fn write_synced(path: &Path, value: &[u8]) {
    fs::write(path, value).unwrap();
    fs::File::open(path).unwrap().sync_all().unwrap();
}

fn copy_synced(source: &Path, destination: &Path) {
    fs::copy(source, destination).unwrap();
    fs::File::open(destination).unwrap().sync_all().unwrap();
}
