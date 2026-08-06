use super::update::prepare_geodata_download_inline;

const GEODATA_PREPARE_HELPER_TASK_NAME: &str = "daed-geodata";
const GEODATA_PREPARE_HELPER_SO_MARK_ENV: &str = "DAED_CONTROL_HELPER_SO_MARK";
use super::*;

mod command;
mod process;
mod protocol;

pub(in crate::daed_product) use command::run_geodata_prepare_helper_command;
pub(super) use process::prepare_geodata_with_helper;
pub(super) use protocol::GeodataPreparedDownload;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GeodataPreparationMode {
    Inline,
    IsolatedProcess,
}

impl GeodataPreparationMode {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::IsolatedProcess => "isolated-process",
        }
    }
}
