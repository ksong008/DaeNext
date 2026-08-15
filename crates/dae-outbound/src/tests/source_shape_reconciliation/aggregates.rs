use super::*;

#[test]
fn aggregate_components_define_projected_selector_and_ownership_unions() {
    for reconciliation in source_shape_reconciliations()
        .iter()
        .filter(|reconciliation| {
            reconciliation.kind == SourceShapeReconciliationKind::AggregateCapability
        })
    {
        if reconciliation.shape_id == "xhttp-extended-settings-wrapper" {
            assert!(reconciliation.aggregate_components.is_empty());
            assert!(!reconciliation.classification_selectors.is_empty());
            continue;
        }
        assert!(
            !reconciliation.aggregate_components.is_empty(),
            "{}",
            reconciliation.shape_id
        );
        assert!(reconciliation.classification_selectors.is_empty());
        let aggregate_row = source_shape_registry_rows()
            .iter()
            .find(|row| row.shape_id == reconciliation.shape_id)
            .unwrap();
        let mut expected_union = Vec::new();
        for aggregate_component in reconciliation.aggregate_components {
            let component = source_shape_reconciliation(aggregate_component.shape_id)
                .unwrap_or_else(|| {
                    panic!(
                        "{} references missing component {}",
                        reconciliation.shape_id, aggregate_component.shape_id,
                    )
                });
            let component_row = source_shape_registry_rows()
                .iter()
                .find(|row| row.shape_id == aggregate_component.shape_id)
                .unwrap_or_else(|| {
                    panic!(
                        "{} references missing registry row {}",
                        reconciliation.shape_id, aggregate_component.shape_id,
                    )
                });
            assert_eq!(
                component.kind,
                SourceShapeReconciliationKind::ProductionWitness,
                "{} -> {}",
                reconciliation.shape_id,
                aggregate_component.shape_id,
            );
            assert!(component.contributes_production_witness());
            assert!(
                component_row
                    .runtime_ownership
                    .allowed_materialized_models
                    .iter()
                    .all(|model| aggregate_row.runtime_ownership.accepts_materialized(*model)),
                "{} ownership does not cover {}",
                reconciliation.shape_id,
                aggregate_component.shape_id,
            );
            let projected = component
                .selectors
                .iter()
                .flat_map(|selector| selector.materialized_shapes())
                .filter(|shape| aggregate_component.projection.matches(*shape))
                .collect::<Vec<_>>();
            assert!(
                !projected.is_empty(),
                "{} -> {} has an empty {} projection",
                reconciliation.shape_id,
                aggregate_component.shape_id,
                aggregate_component.projection.as_report_str(),
            );
            for shape in projected {
                assert!(reconciliation.classifies(shape));
                if !expected_union.contains(&shape) {
                    expected_union.push(shape);
                }
            }
        }
        let actual_union = reconciliation.aggregate_component_shapes();
        assert_eq!(
            actual_union.len(),
            expected_union.len(),
            "{}",
            reconciliation.shape_id
        );
        assert!(
            actual_union
                .iter()
                .all(|shape| expected_union.contains(shape)),
            "{}",
            reconciliation.shape_id,
        );
        for (index, aggregate_component) in reconciliation.aggregate_components.iter().enumerate() {
            assert!(
                reconciliation.aggregate_components[..index]
                    .iter()
                    .all(|earlier| earlier != aggregate_component),
                "{} repeats {} / {}",
                reconciliation.shape_id,
                aggregate_component.shape_id,
                aggregate_component.projection.as_report_str(),
            );
        }
    }
}

#[test]
fn projected_aggregate_classifiers_exclude_non_target_security_atoms() {
    fn assert_excluded_atoms(shape_id: &str, excluded: impl Fn(MaterializedSourceShape) -> bool) {
        let reconciliation = source_shape_reconciliation(shape_id).unwrap();
        for aggregate_component in reconciliation.aggregate_components {
            let component = source_shape_reconciliation(aggregate_component.shape_id).unwrap();
            for shape in component
                .selectors
                .iter()
                .flat_map(|selector| selector.materialized_shapes())
                .filter(|shape| excluded(*shape))
            {
                assert!(!reconciliation.classifies(shape), "{shape_id}: {shape:?}");
            }
        }
    }

    assert_excluded_atoms("tls-fragment-security-underlay", |shape| {
        !shape.tls_features.fragment
    });
    assert_excluded_atoms("shared-reality-security-underlay", |shape| {
        !matches!(
            shape.security,
            MaterializedSecurity::RealityBoring | MaterializedSecurity::RealityFingerprint
        )
    });
}

#[test]
fn security_aggregates_cover_every_matching_production_atom() {
    let tls_fragment = source_shape_reconciliation("tls-fragment-security-underlay").unwrap();
    let shared_reality = source_shape_reconciliation("shared-reality-security-underlay").unwrap();
    let mut fragment_atoms = 0usize;
    let mut reality_atoms = 0usize;

    for production in source_shape_reconciliations()
        .iter()
        .filter(|reconciliation| {
            reconciliation.kind == SourceShapeReconciliationKind::ProductionWitness
        })
    {
        for shape in production
            .selectors
            .iter()
            .flat_map(|selector| selector.materialized_shapes())
        {
            if shape.tls_features.fragment {
                fragment_atoms += 1;
                assert!(
                    tls_fragment.classifies(shape),
                    "fragment atom from {} is not classified: {shape:?}",
                    production.shape_id
                );
            }
            if matches!(
                shape.security,
                MaterializedSecurity::RealityBoring | MaterializedSecurity::RealityFingerprint
            ) {
                reality_atoms += 1;
                assert!(
                    shared_reality.classifies(shape),
                    "Reality atom from {} is not classified: {shape:?}",
                    production.shape_id
                );
            }
        }
    }

    assert!(fragment_atoms > 0);
    assert!(reality_atoms > 0);
}

#[test]
fn tls_fragment_aggregate_declares_standalone_and_chained_source_schemes() {
    let row = source_shape_registry_rows()
        .iter()
        .find(|row| row.shape_id == "tls-fragment-security-underlay")
        .unwrap();
    for scheme in ["ss", "shadowsocks", "socks", "socks5", "http"] {
        assert!(row.link_schemes.contains(&scheme), "missing {scheme}");
    }
}
