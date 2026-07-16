use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnershipEvidenceState {
    Verified,
    Pending,
    Rejected,
    Blocked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnershipEvidenceScope {
    SourceContract,
    MaterializedRuntime,
}

impl OwnershipEvidenceScope {
    fn as_report_str(self) -> &'static str {
        match self {
            Self::SourceContract => "source-contract",
            Self::MaterializedRuntime => "materialized-runtime",
        }
    }
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
    scope: OwnershipEvidenceScope,
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
                scope: OwnershipEvidenceScope::SourceContract,
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
                scope: OwnershipEvidenceScope::SourceContract,
                parser: OwnershipEvidenceState::Verified,
                configuration_materialization: OwnershipEvidenceState::Blocked,
                local_executable_path: OwnershipEvidenceState::Blocked,
                resource_validation: OwnershipEvidenceState::Blocked,
                immutable_artifact: OwnershipEvidenceState::Blocked,
                authorized_live_interoperability: OwnershipEvidenceState::Blocked,
            };
        }
        Self {
            scope: OwnershipEvidenceScope::SourceContract,
            parser: OwnershipEvidenceState::Verified,
            configuration_materialization: OwnershipEvidenceState::Pending,
            local_executable_path: OwnershipEvidenceState::Pending,
            resource_validation: OwnershipEvidenceState::Pending,
            immutable_artifact: OwnershipEvidenceState::Pending,
            authorized_live_interoperability: OwnershipEvidenceState::Pending,
        }
    }

    fn materialized_runtime() -> Self {
        Self {
            scope: OwnershipEvidenceScope::MaterializedRuntime,
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
            "scope": self.scope.as_report_str(),
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
            "schemaVersion": 2,
            "redactedIdentity": redacted_identity,
            "model": self.model.as_report_str(),
            "disposition": self.disposition.as_report_str(),
            "allowedMaterializedModels": self.allowed_materialized_models
                .iter()
                .map(|model| model.as_report_str())
                .collect::<Vec<_>>(),
            "callers": {
                "dataTcp": self.data_tcp.to_value(),
                "dataUdp": self.data_udp.to_value(),
                "healthTcp": self.health_tcp.to_value(),
                "healthDns": self.health_dns.to_value(),
                "manual": self.manual.to_value(),
                "configuredDns": self.configured_dns.to_value(),
                "forcedManagedDns": self.forced_managed_dns.to_value(),
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
