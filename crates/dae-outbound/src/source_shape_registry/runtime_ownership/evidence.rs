use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnershipEvidenceState {
    Verified,
    Pending,
    Rejected,
    Blocked,
}

impl OwnershipEvidenceState {
    fn as_report_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Pending => "pending",
            Self::Rejected => "rejected",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeOwnershipEvidence {
    parser: OwnershipEvidenceState,
    configuration_materialization: OwnershipEvidenceState,
    local_executable_path: OwnershipEvidenceState,
    resource_validation: OwnershipEvidenceState,
    immutable_artifact: OwnershipEvidenceState,
    authorized_live_interoperability: OwnershipEvidenceState,
}

impl RuntimeOwnershipEvidence {
    fn for_source_row(row: SourceShapeRegistryRow) -> Self {
        if row.source_support == "not-source-supported" {
            return Self {
                parser: OwnershipEvidenceState::Rejected,
                configuration_materialization: OwnershipEvidenceState::Rejected,
                local_executable_path: OwnershipEvidenceState::Rejected,
                resource_validation: OwnershipEvidenceState::Rejected,
                immutable_artifact: OwnershipEvidenceState::Rejected,
                authorized_live_interoperability: OwnershipEvidenceState::Rejected,
            };
        }
        if row.resident_status == "blocked" {
            return Self {
                parser: OwnershipEvidenceState::Verified,
                configuration_materialization: OwnershipEvidenceState::Blocked,
                local_executable_path: OwnershipEvidenceState::Blocked,
                resource_validation: OwnershipEvidenceState::Blocked,
                immutable_artifact: OwnershipEvidenceState::Blocked,
                authorized_live_interoperability: OwnershipEvidenceState::Blocked,
            };
        }
        Self {
            parser: OwnershipEvidenceState::Verified,
            configuration_materialization: OwnershipEvidenceState::Verified,
            local_executable_path: OwnershipEvidenceState::Verified,
            resource_validation: OwnershipEvidenceState::Pending,
            immutable_artifact: OwnershipEvidenceState::Pending,
            authorized_live_interoperability: OwnershipEvidenceState::Pending,
        }
    }

    fn materialized_runtime() -> Self {
        Self {
            parser: OwnershipEvidenceState::Verified,
            configuration_materialization: OwnershipEvidenceState::Verified,
            local_executable_path: OwnershipEvidenceState::Verified,
            resource_validation: OwnershipEvidenceState::Pending,
            immutable_artifact: OwnershipEvidenceState::Pending,
            authorized_live_interoperability: OwnershipEvidenceState::Pending,
        }
    }

    fn to_value(self) -> Value {
        json!({
            "parser": self.parser.as_report_str(),
            "configurationMaterialization": self.configuration_materialization.as_report_str(),
            "localExecutablePath": self.local_executable_path.as_report_str(),
            "resourceValidation": self.resource_validation.as_report_str(),
            "immutableArtifact": self.immutable_artifact.as_report_str(),
            "authorizedLiveInteroperability": self.authorized_live_interoperability.as_report_str(),
        })
    }
}

impl RuntimeOwnershipProfile {
    pub fn to_materialized_value(self, redacted_identity: &str) -> Value {
        self.to_value(
            redacted_identity,
            RuntimeOwnershipEvidence::materialized_runtime(),
        )
    }

    fn to_value(self, redacted_identity: &str, evidence: RuntimeOwnershipEvidence) -> Value {
        json!({
            "schema": "runtime-shape-ownership-ledger",
            "schemaVersion": 1,
            "redactedIdentity": redacted_identity,
            "model": self.model.as_report_str(),
            "disposition": self.disposition.as_report_str(),
            "callers": {
                "tcp": self.tcp.to_value(),
                "udp": self.udp.to_value(),
                "health": self.health.to_value(),
                "manual": self.manual.to_value(),
                "dns": self.dns.to_value(),
            },
            "evidence": evidence.to_value(),
        })
    }
}

impl SourceShapeRegistryRow {
    pub fn runtime_ownership_ledger(self) -> Value {
        self.runtime_ownership.to_value(
            self.redacted_identity,
            RuntimeOwnershipEvidence::for_source_row(self),
        )
    }
}
