use super::update::prepare_geodata_download_inline;

const GEODATA_PREPARE_HELPER_TASK_NAME: &str = "daed-geodata";
use super::*;

mod command;

pub(in crate::daed_product) use command::run_geodata_prepare_helper_command;
pub(super) use dae_product_geodata::{GeodataPreparedDownload, prepare_geodata_with_helper};

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
