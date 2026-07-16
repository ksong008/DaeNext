use super::{
    chained_sources::chained_builder_sources, standalone_sources::standalone_builder_sources,
};

pub(super) fn builder_sources() -> Vec<String> {
    let mut sources = standalone_builder_sources();
    sources.extend(chained_builder_sources());
    sources
}
