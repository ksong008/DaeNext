use super::*;

pub(super) struct TcxAttachPreparation {
    pub(super) order: LinkOrder,
    pub(super) anchor: Option<AyaTcxAttachAnchor>,
    pub(super) query_revision: u64,
    pub(super) program_order: Vec<AyaTcxProgramOrderEntry>,
}

pub(super) fn prepare_tcx_attach_order(
    iface: &str,
    attach_type: TcAttachType,
    expected_order: TcxAttachOrder,
) -> Result<TcxAttachPreparation, String> {
    let (query_revision, program_order) = query_tcx_program_order(iface, attach_type)?;
    let anchor = select_tcx_attach_anchor(expected_order, &program_order);
    let order = match &anchor {
        Some(anchor) => {
            // SAFETY: the id comes directly from a successful kernel TCX query. If the
            // referenced program disappears before link creation, the kernel rejects the
            // attach and the caller follows its existing bounded fallback path.
            let program_id = unsafe { ProgramId::new(anchor.program_id) };
            match anchor.relation {
                TcxAnchorRelation::Before => LinkOrder::before_program_id(program_id),
                TcxAnchorRelation::After => LinkOrder::after_program_id(program_id),
            }
        }
        None => match expected_order {
            TcxAttachOrder::First => LinkOrder::first(),
            TcxAttachOrder::Last => LinkOrder::last(),
        },
    };
    Ok(TcxAttachPreparation {
        order,
        anchor,
        query_revision,
        program_order,
    })
}

fn select_tcx_attach_anchor(
    expected_order: TcxAttachOrder,
    program_order: &[AyaTcxProgramOrderEntry],
) -> Option<AyaTcxAttachAnchor> {
    match expected_order {
        TcxAttachOrder::First => program_order.first().map(|program| AyaTcxAttachAnchor {
            relation: TcxAnchorRelation::Before,
            program_id: program.id,
        }),
        TcxAttachOrder::Last => program_order.last().map(|program| AyaTcxAttachAnchor {
            relation: TcxAnchorRelation::After,
            program_id: program.id,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program(id: u32) -> AyaTcxProgramOrderEntry {
        AyaTcxProgramOrderEntry {
            id,
            name: None,
            tag: String::new(),
        }
    }

    #[test]
    fn first_and_last_orders_anchor_to_the_observed_edges() {
        let programs = vec![program(11), program(22), program(33)];
        assert_eq!(
            select_tcx_attach_anchor(TcxAttachOrder::First, &programs),
            Some(AyaTcxAttachAnchor {
                relation: TcxAnchorRelation::Before,
                program_id: 11,
            })
        );
        assert_eq!(
            select_tcx_attach_anchor(TcxAttachOrder::Last, &programs),
            Some(AyaTcxAttachAnchor {
                relation: TcxAnchorRelation::After,
                program_id: 33,
            })
        );
    }

    #[test]
    fn an_empty_chain_uses_the_unanchored_edge_order() {
        assert_eq!(select_tcx_attach_anchor(TcxAttachOrder::First, &[]), None);
        assert_eq!(select_tcx_attach_anchor(TcxAttachOrder::Last, &[]), None);
    }
}
