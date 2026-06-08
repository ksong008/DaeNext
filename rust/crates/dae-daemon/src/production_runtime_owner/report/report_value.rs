use super::*;
mod context;
pub(super) use self::context::*;
mod header_contract;
pub(super) use self::header_contract::*;
mod summary_flags;
pub(super) use self::summary_flags::*;
mod scope_assets;
pub(super) use self::scope_assets::*;
mod evidence_sections;
pub(super) use self::evidence_sections::*;
mod footer;
pub(super) use self::footer::*;

pub(crate) fn report_value(
    options: &ProductionRuntimeOwnerOptions,
    artifact_dir: &Path,
    manifest_file: &Path,
    param_object: &Path,
    checks: Vec<Value>,
    evidence: ExecutionEvidence,
) -> Value {
    let context = ReportValueContext::new(
        options,
        artifact_dir,
        manifest_file,
        param_object,
        checks,
        evidence,
    );
    let mut report = Map::new();
    insert_header_and_contract(&mut report, &context);
    insert_summary_flags(&mut report, &context);
    insert_scope_and_assets(&mut report, &context);
    insert_evidence_sections(&mut report, &context);
    insert_source_and_bpf_footer(&mut report, &context);
    Value::Object(report)
}
