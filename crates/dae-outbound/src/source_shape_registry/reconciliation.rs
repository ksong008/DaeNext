mod dimensions;
pub use self::dimensions::*;

mod tls_variant;
pub use self::tls_variant::*;

mod ownership;

mod selector;
pub use self::selector::*;

mod table;
use self::table::SOURCE_SHAPE_RECONCILIATIONS;

pub fn source_shape_reconciliation(shape_id: &str) -> Option<&'static SourceShapeReconciliation> {
    SOURCE_SHAPE_RECONCILIATIONS
        .iter()
        .find(|reconciliation| reconciliation.shape_id == shape_id)
}

pub fn source_shape_reconciliations() -> &'static [SourceShapeReconciliation] {
    SOURCE_SHAPE_RECONCILIATIONS
}
