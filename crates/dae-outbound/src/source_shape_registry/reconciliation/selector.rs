use serde::Serialize;
use serde_json::{Value, json};

use super::*;
use crate::source_shape_registry::RuntimeOwnershipModel;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceShapeReconciliationKind {
    ProductionWitness,
    AggregateCapability,
    DeferredCapability,
    SourceRejected,
}

impl SourceShapeReconciliationKind {
    pub const fn as_report_str(self) -> &'static str {
        match self {
            Self::ProductionWitness => "production-witness",
            Self::AggregateCapability => "aggregate-capability",
            Self::DeferredCapability => "deferred-capability",
            Self::SourceRejected => "source-rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceShapeSelector {
    pub protocol: MaterializedProtocol,
    pub tls_variants: &'static [MaterializedTlsVariant],
    pub wrapper: MaterializedWrapper,
    pub udp: MaterializedUdp,
    pub chain: MaterializedChain,
    pub chain_udp: MaterializedChainUdp,
    pub xhttp_modes: &'static [MaterializedXhttpMode],
    pub xhttp_settings: MaterializedXhttpSettings,
    pub quic_verification: &'static [MaterializedQuicVerification],
    pub port_hopping: MaterializedPortHopping,
    pub source_import: MaterializedSourceImport,
    pub passthrough_udp: MaterializedPassthroughUdp,
}

impl SourceShapeSelector {
    pub fn matches(self, shape: MaterializedSourceShape) -> bool {
        self.protocol == shape.protocol
            && self.tls_variants.contains(&shape.tls_variant())
            && self.wrapper == shape.wrapper
            && self.udp == shape.udp
            && self.chain == shape.chain
            && self.chain_udp == shape.chain_udp
            && self.xhttp_modes.contains(&shape.xhttp_mode)
            && self.xhttp_settings == shape.xhttp_settings
            && self.quic_verification.contains(&shape.quic_verification)
            && self.port_hopping == shape.port_hopping
            && self.source_import == shape.source_import
            && self.passthrough_udp == shape.passthrough_udp
    }

    pub fn materialized_shapes(self) -> Vec<MaterializedSourceShape> {
        let mut shapes = Vec::with_capacity(
            self.tls_variants.len() * self.xhttp_modes.len() * self.quic_verification.len(),
        );
        for tls_variant in self.tls_variants {
            for xhttp_mode in self.xhttp_modes {
                for quic_verification in self.quic_verification {
                    shapes.push(MaterializedSourceShape {
                        protocol: self.protocol,
                        security: tls_variant.security,
                        tls_features: tls_variant.features,
                        wrapper: self.wrapper,
                        udp: self.udp,
                        chain: self.chain,
                        chain_udp: self.chain_udp,
                        xhttp_mode: *xhttp_mode,
                        xhttp_settings: self.xhttp_settings,
                        quic_verification: *quic_verification,
                        port_hopping: self.port_hopping,
                        source_import: self.source_import,
                        passthrough_udp: self.passthrough_udp,
                    });
                }
            }
        }
        shapes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceShapeProjection {
    All,
    TlsFragment,
    Reality,
}

impl SourceShapeProjection {
    pub const fn as_report_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::TlsFragment => "tls-fragment",
            Self::Reality => "reality",
        }
    }

    pub const fn matches(self, shape: MaterializedSourceShape) -> bool {
        match self {
            Self::All => true,
            Self::TlsFragment => shape.tls_features.fragment,
            Self::Reality => matches!(
                shape.security,
                MaterializedSecurity::RealityBoring | MaterializedSecurity::RealityFingerprint
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceShapeAggregateComponent {
    pub shape_id: &'static str,
    pub projection: SourceShapeProjection,
}

impl SourceShapeAggregateComponent {
    pub const fn new(shape_id: &'static str, projection: SourceShapeProjection) -> Self {
        Self {
            shape_id,
            projection,
        }
    }

    fn classifies(self, shape: MaterializedSourceShape) -> bool {
        self.projection.matches(shape)
            && source_shape_reconciliation(self.shape_id).is_some_and(|component| {
                component.kind == SourceShapeReconciliationKind::ProductionWitness
                    && component.matches(shape)
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceShapeReconciliation {
    pub shape_id: &'static str,
    pub kind: SourceShapeReconciliationKind,
    pub selectors: &'static [SourceShapeSelector],
    pub classification_selectors: &'static [SourceShapeSelector],
    pub aggregate_components: &'static [SourceShapeAggregateComponent],
}

impl SourceShapeReconciliation {
    pub fn matches(self, shape: MaterializedSourceShape) -> bool {
        self.selectors
            .iter()
            .any(|selector| selector.matches(shape))
    }

    pub const fn contributes_production_witness(self) -> bool {
        matches!(self.kind, SourceShapeReconciliationKind::ProductionWitness)
            && !self.selectors.is_empty()
    }

    pub fn classifies(self, shape: MaterializedSourceShape) -> bool {
        self.classification_selectors
            .iter()
            .any(|selector| selector.matches(shape))
            || self
                .aggregate_components
                .iter()
                .any(|component| component.classifies(shape))
    }

    pub fn component_shape_ids(self) -> Vec<&'static str> {
        self.aggregate_components
            .iter()
            .map(|component| component.shape_id)
            .collect()
    }

    pub fn aggregate_component_shapes(self) -> Vec<MaterializedSourceShape> {
        let mut shapes = Vec::new();
        for aggregate_component in self.aggregate_components {
            let Some(component) = source_shape_reconciliation(aggregate_component.shape_id) else {
                continue;
            };
            for shape in component
                .selectors
                .iter()
                .flat_map(|selector| selector.materialized_shapes())
                .filter(|shape| aggregate_component.projection.matches(*shape))
            {
                if !shapes.contains(&shape) {
                    shapes.push(shape);
                }
            }
        }
        shapes
    }

    pub fn materialized_shapes(self) -> Vec<MaterializedSourceShape> {
        let materialized = if !self.selectors.is_empty() {
            self.selectors
                .iter()
                .flat_map(|selector| selector.materialized_shapes())
                .collect::<Vec<_>>()
        } else if !self.classification_selectors.is_empty() {
            self.classification_selectors
                .iter()
                .flat_map(|selector| selector.materialized_shapes())
                .collect::<Vec<_>>()
        } else {
            self.aggregate_component_shapes()
        };
        let mut shapes = Vec::new();
        for shape in materialized {
            if !shapes.contains(&shape) {
                shapes.push(shape);
            }
        }
        shapes
    }

    pub fn runtime_ownership_models(self) -> Vec<RuntimeOwnershipModel> {
        let mut models = Vec::new();
        for model in self
            .materialized_shapes()
            .into_iter()
            .map(MaterializedSourceShape::runtime_ownership_model)
        {
            if !models.contains(&model) {
                models.push(model);
            }
        }
        models
    }

    pub fn to_value(self) -> Value {
        let component_shape_ids = self.component_shape_ids();
        let materialized_shape_count = self.materialized_shapes().len();
        let runtime_ownership_models = self
            .runtime_ownership_models()
            .into_iter()
            .map(RuntimeOwnershipModel::as_report_str)
            .collect::<Vec<_>>();
        let aggregate_components = self
            .aggregate_components
            .iter()
            .map(|component| {
                json!({
                    "shapeId": component.shape_id,
                    "projection": component.projection.as_report_str(),
                })
            })
            .collect::<Vec<_>>();
        json!({
            "schemaVersion": 1,
            "kind": self.kind.as_report_str(),
            "selectorCount": self.selectors.len(),
            "classificationSelectorCount": self.classification_selectors.len(),
            "productionSelectors": self.selectors,
            "classificationSelectors": self.classification_selectors,
            "materializedShapeCount": materialized_shape_count,
            "runtimeOwnershipModels": runtime_ownership_models,
            "componentShapeIds": component_shape_ids,
            "aggregateComponents": aggregate_components,
            "contributesProductionWitness": self.contributes_production_witness(),
        })
    }
}
