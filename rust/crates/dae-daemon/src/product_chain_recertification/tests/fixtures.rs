use super::*;
pub(super) fn write_fixture_file(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

pub(super) fn write_candidate_service_contract(path: &Path, resident_dataplane_ready: bool) {
    write_candidate_service_contract_value(
        path,
        &candidate_service_contract_value(resident_dataplane_ready),
    );
}

mod service_contract;
pub(super) use self::service_contract::*;
mod service_contract_resident_runtime;
pub(super) use self::service_contract_resident_runtime::*;
mod service_contract_control_plane;
pub(super) use self::service_contract_control_plane::*;
mod service_contract_datapath;
pub(super) use self::service_contract_datapath::*;
mod service_contract_fingerprint;
pub(super) use self::service_contract_fingerprint::*;
mod service_contract_outbound_matrix;
pub(super) use self::service_contract_outbound_matrix::*;
mod service_contract_live_adapter;
pub(super) use self::service_contract_live_adapter::*;
mod service_contract_release_switch;
pub(super) use self::service_contract_release_switch::*;
mod service_contract_go_free;
pub(super) use self::service_contract_go_free::*;
mod file_contract;
pub(super) use self::file_contract::*;
mod options;
pub(super) use self::options::*;
