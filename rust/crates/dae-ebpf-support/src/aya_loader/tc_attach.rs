pub fn load_attach_detach_aya_sched_classifier(
    loaded: &mut AyaUserspaceLoadedObject,
    spec: &TcNativeAttachSpec,
    backend: AttachBackend,
) -> Result<AyaTcAttachDetachReport, String> {
    if !matches!(backend, AttachBackend::TcNetlink | AttachBackend::Tcx) {
        return Err(format!(
            "aya sched classifier attach requires native backend, got {}",
            backend.as_str()
        ));
    }
    let mut report = with_optional_netns(spec.target.netns.as_deref(), || {
        load_attach_detach_aya_sched_classifier_in_current_netns(loaded, spec, backend)
    })?;
    report.netns = spec.target.netns.clone();
    report.netns_entered = spec.target.netns.is_some();
    Ok(report)
}

pub fn load_attach_aya_sched_classifier(
    loaded: &mut AyaUserspaceLoadedObject,
    spec: &TcNativeAttachSpec,
    backend: AttachBackend,
) -> Result<AyaTcAttachDetachReport, String> {
    if !matches!(backend, AttachBackend::TcNetlink | AttachBackend::Tcx) {
        return Err(format!(
            "aya sched classifier attach requires native backend, got {}",
            backend.as_str()
        ));
    }
    let (mut report, _link_id) = with_optional_netns(spec.target.netns.as_deref(), || {
        load_attach_aya_sched_classifier_in_current_netns(loaded, spec, backend)
    })?;
    report.netns = spec.target.netns.clone();
    report.netns_entered = spec.target.netns.is_some();
    Ok(report)
}

pub fn attach_pin_aya_sched_classifier(
    options: PinnedTcAttachOptions<'_>,
) -> Result<PinnedTcAttachReport, String> {
    if !matches!(
        options.requested_backend,
        AttachBackend::Auto | AttachBackend::TcNetlink | AttachBackend::Tcx
    ) {
        return Err(format!(
            "aya sched classifier attach-pin requires auto/tcx/tc_netlink backend, got {}",
            options.requested_backend.as_str()
        ));
    }
    let mut report = with_optional_netns(options.spec.target.netns.as_deref(), || {
        attach_pin_aya_sched_classifier_in_current_netns(&options)
    })?;
    report.netns = options.spec.target.netns.clone();
    report.netns_entered = options.spec.target.netns.is_some();
    Ok(report)
}

fn load_attach_detach_aya_sched_classifier_in_current_netns(
    loaded: &mut AyaUserspaceLoadedObject,
    spec: &TcNativeAttachSpec,
    backend: AttachBackend,
) -> Result<AyaTcAttachDetachReport, String> {
    load_attach_aya_sched_classifier_in_current_netns(loaded, spec, backend).and_then(
        |(mut report, link_id)| {
            let program = loaded.ebpf.program_mut(&spec.program_name).ok_or_else(|| {
                format!(
                    "aya sched classifier program not found for detach: {}",
                    spec.program_name
                )
            })?;
            let classifier: &mut SchedClassifier = program.try_into().map_err(|err| {
                format!("aya program is not a sched classifier for detach: {err:?}")
            })?;
            classifier
                .detach(link_id)
                .map_err(|err| format!("aya sched classifier detach failed: {err:?}"))?;
            report.detached = true;
            Ok(report)
        },
    )
}

fn load_attach_aya_sched_classifier_in_current_netns(
    loaded: &mut AyaUserspaceLoadedObject,
    spec: &TcNativeAttachSpec,
    backend: AttachBackend,
) -> Result<(AyaTcAttachDetachReport, SchedClassifierLinkId), String> {
    if spec.clsact_required {
        add_clsact_or_accept_existing(&spec.target.iface)?;
    }
    let attach_type = match spec.target.direction {
        TcAttachDirection::Ingress => TcAttachType::Ingress,
        TcAttachDirection::Egress => TcAttachType::Egress,
    };
    let program = loaded.ebpf.program_mut(&spec.program_name).ok_or_else(|| {
        format!(
            "aya sched classifier program not found: {}",
            spec.program_name
        )
    })?;
    let classifier: &mut SchedClassifier = program
        .try_into()
        .map_err(|err| format!("aya program is not a sched classifier: {err:?}"))?;
    if classifier.fd().is_err() {
        classifier
            .load()
            .map_err(|err| format!("aya sched classifier load failed: {err:?}"))?;
    }
    let program_id = classifier.info().ok().map(|info| info.id());
    let requested_backend = backend;
    let (
        backend,
        link_id,
        fallback_error,
        tcx_query_revision,
        tcx_program_order,
        tcx_query_error,
        tcx_order_verified,
        tcx_order_error,
    ) = match backend {
        AttachBackend::TcNetlink => (
            AttachBackend::TcNetlink,
            attach_loaded_aya_sched_classifier(
                classifier,
                spec,
                attach_type,
                AttachBackend::TcNetlink,
            )?,
            None,
            None,
            Vec::new(),
            None,
            false,
            None,
        ),
        AttachBackend::Tcx => match attach_loaded_aya_sched_classifier(
            classifier,
            spec,
            attach_type,
            AttachBackend::Tcx,
        ) {
            Ok(link_id) => match query_tcx_program_order(&spec.target.iface, attach_type) {
                Ok((revision, program_order)) => {
                    match verify_tcx_program_order(program_id, spec.tcx_order, &program_order) {
                        Ok(()) => (
                            AttachBackend::Tcx,
                            link_id,
                            None,
                            Some(revision),
                            program_order,
                            None,
                            true,
                            None,
                        ),
                        Err(order_err) => {
                            classifier.detach(link_id).map_err(|detach_err| {
                                format!(
                                    "aya tcx order verification failed after attach: {order_err}; tcx detach before tc-netlink fallback failed: {detach_err:?}"
                                )
                            })?;
                            let link_id = attach_loaded_aya_sched_classifier(
                                classifier,
                                spec,
                                attach_type,
                                AttachBackend::TcNetlink,
                            )
                            .map_err(|tc_err| {
                                format!(
                                    "aya tcx order verification failed after attach: {order_err}; tc-netlink fallback failed: {tc_err}"
                                )
                            })?;
                            (
                                AttachBackend::TcNetlink,
                                link_id,
                                Some(format!("tcx order verification failed: {order_err}")),
                                Some(revision),
                                program_order,
                                None,
                                false,
                                Some(order_err),
                            )
                        }
                    }
                }
                Err(query_err) => {
                    classifier.detach(link_id).map_err(|detach_err| {
                        format!(
                            "aya tcx query failed after attach: {query_err}; tcx detach before tc-netlink fallback failed: {detach_err:?}"
                        )
                    })?;
                    let link_id = attach_loaded_aya_sched_classifier(
                        classifier,
                        spec,
                        attach_type,
                        AttachBackend::TcNetlink,
                    )
                    .map_err(|tc_err| {
                        format!(
                            "aya tcx query failed after attach: {query_err}; tc-netlink fallback failed: {tc_err}"
                        )
                    })?;
                    (
                        AttachBackend::TcNetlink,
                        link_id,
                        Some(format!("tcx query failed after attach: {query_err}")),
                        None,
                        Vec::new(),
                        Some(query_err),
                        false,
                        None,
                    )
                }
            },
            Err(tcx_err) => {
                let link_id = attach_loaded_aya_sched_classifier(
                    classifier,
                    spec,
                    attach_type,
                    AttachBackend::TcNetlink,
                )
                .map_err(|tc_err| {
                    format!(
                        "aya sched classifier tcx attach failed: {tcx_err}; tc-netlink fallback failed: {tc_err}"
                    )
                })?;
                (
                    AttachBackend::TcNetlink,
                    link_id,
                    Some(tcx_err),
                    None,
                    Vec::new(),
                    None,
                    false,
                    None,
                )
            }
        },
        _ => unreachable!(),
    };

    Ok((
        AyaTcAttachDetachReport {
            requested_backend,
            backend,
            fallback_used: fallback_error.is_some(),
            fallback_error,
            program_id,
            program_name: spec.program_name.clone(),
            iface: spec.target.iface.clone(),
            netns: None,
            netns_entered: false,
            direction: spec.target.direction,
            priority: spec.priority,
            handle: spec.handle,
            tcx_order: spec.tcx_order,
            tcx_query_revision,
            tcx_program_order,
            tcx_query_error,
            tcx_order_verified,
            tcx_order_error,
            clsact_added_or_present: spec.clsact_required,
            loaded: true,
            attached: true,
            detached: false,
            link_lifetime_owned_by_backend: spec.link_lifetime_owned_by_backend,
        },
        link_id,
    ))
}

fn attach_pin_aya_sched_classifier_in_current_netns(
    options: &PinnedTcAttachOptions<'_>,
) -> Result<PinnedTcAttachReport, String> {
    let spec = options.spec;
    if spec.clsact_required {
        add_clsact_or_accept_existing(&spec.target.iface)?;
    }
    fs::create_dir_all(options.link_root).map_err(|err| {
        format!(
            "create tc attach link root {} failed: {err}",
            options.link_root.display()
        )
    })?;

    let attach_type = match spec.target.direction {
        TcAttachDirection::Ingress => TcAttachType::Ingress,
        TcAttachDirection::Egress => TcAttachType::Egress,
    };
    let program_path = options.program_root.join(&spec.program_name);
    let mut classifier = SchedClassifier::from_pin(&program_path).map_err(|err| {
        format!(
            "open pinned sched classifier {} failed: {err:?}",
            program_path.display()
        )
    })?;
    let program_id = classifier.info().ok().map(|info| info.id());

    let attach_result = match options.requested_backend {
        AttachBackend::Auto => {
            match attach_pinned_classifier_once(
                &mut classifier,
                spec,
                attach_type,
                AttachBackend::Tcx,
                program_id,
            ) {
                Ok(result) => result,
                Err(tcx_err) => {
                    let mut result = attach_pinned_classifier_once(
                        &mut classifier,
                        spec,
                        attach_type,
                        AttachBackend::TcNetlink,
                        program_id,
                    )
                    .map_err(|tc_err| {
                        format!(
                            "aya tcx attach-pin failed: {tcx_err}; tc-netlink fallback failed: {tc_err}"
                        )
                    })?;
                    result.fallback_used = true;
                    result.fallback_error = Some(tcx_err);
                    result
                }
            }
        }
        AttachBackend::Tcx | AttachBackend::TcNetlink => attach_pinned_classifier_once(
            &mut classifier,
            spec,
            attach_type,
            options.requested_backend,
            program_id,
        )?,
        AttachBackend::TcCommandFallback => unreachable!(),
    };

    let link_path = if attach_result.backend == AttachBackend::Tcx {
        let link = classifier
            .take_link(attach_result.link_id)
            .map_err(|err| format!("take tcx sched classifier link failed: {err:?}"))?;
        let fd_link: FdLink = link
            .try_into()
            .map_err(|err| format!("tcx sched classifier link is not an fd link: {err:?}"))?;
        let link_path = options.link_root.join("link");
        remove_existing_pin(&link_path)?;
        let pinned = fd_link
            .pin(&link_path)
            .map_err(|err| format!("pin tcx sched classifier link failed: {err:?}"))?;
        drop(pinned);
        Some(link_path)
    } else {
        let link = classifier
            .take_link(attach_result.link_id)
            .map_err(|err| format!("take tc-netlink sched classifier link failed: {err:?}"))?;
        // TC netlink attachments are persistent kernel filters. After a
        // successful helper-owned attach, Go keeps the cleanup contract via
        // FilterDel/delBpfFilter, so the temporary Aya link must not detach on
        // helper process exit.
        mem::forget(link);
        None
    };

    Ok(PinnedTcAttachReport {
        requested_backend: options.requested_backend,
        backend: attach_result.backend,
        fallback_used: attach_result.fallback_used,
        fallback_error: attach_result.fallback_error,
        program_id,
        program_name: spec.program_name.clone(),
        program_path,
        iface: spec.target.iface.clone(),
        netns: None,
        netns_entered: false,
        direction: spec.target.direction,
        priority: spec.priority,
        handle: spec.handle,
        tcx_order: spec.tcx_order,
        tcx_query_revision: attach_result.tcx_query_revision,
        tcx_program_order: attach_result.tcx_program_order,
        tcx_order_verified: attach_result.tcx_order_verified,
        link_path,
        tc_filter_persistent: attach_result.backend == AttachBackend::TcNetlink,
        clsact_added_or_present: spec.clsact_required,
    })
}

struct PinnedClassifierAttachResult {
    backend: AttachBackend,
    link_id: SchedClassifierLinkId,
    fallback_used: bool,
    fallback_error: Option<String>,
    tcx_query_revision: Option<u64>,
    tcx_program_order: Vec<AyaTcxProgramOrderEntry>,
    tcx_order_verified: bool,
}

fn attach_pinned_classifier_once(
    classifier: &mut SchedClassifier,
    spec: &TcNativeAttachSpec,
    attach_type: TcAttachType,
    backend: AttachBackend,
    program_id: Option<u32>,
) -> Result<PinnedClassifierAttachResult, String> {
    let link_id = attach_loaded_aya_sched_classifier(classifier, spec, attach_type, backend)?;
    if backend != AttachBackend::Tcx {
        return Ok(PinnedClassifierAttachResult {
            backend,
            link_id,
            fallback_used: false,
            fallback_error: None,
            tcx_query_revision: None,
            tcx_program_order: Vec::new(),
            tcx_order_verified: false,
        });
    }

    let (revision, program_order) = match query_tcx_program_order(&spec.target.iface, attach_type) {
        Ok(value) => value,
        Err(query_err) => {
            classifier.detach(link_id).map_err(|detach_err| {
                format!(
                    "aya tcx query failed after attach-pin: {query_err}; tcx detach failed: {detach_err:?}"
                )
            })?;
            return Err(query_err);
        }
    };
    if let Err(order_err) = verify_tcx_program_order(program_id, spec.tcx_order, &program_order) {
        classifier.detach(link_id).map_err(|detach_err| {
            format!(
                "aya tcx order verification failed after attach-pin: {order_err}; tcx detach failed: {detach_err:?}"
            )
        })?;
        return Err(order_err);
    }

    Ok(PinnedClassifierAttachResult {
        backend,
        link_id,
        fallback_used: false,
        fallback_error: None,
        tcx_query_revision: Some(revision),
        tcx_program_order: program_order,
        tcx_order_verified: true,
    })
}

fn attach_loaded_aya_sched_classifier(
    classifier: &mut SchedClassifier,
    spec: &TcNativeAttachSpec,
    attach_type: TcAttachType,
    backend: AttachBackend,
) -> Result<SchedClassifierLinkId, String> {
    let attach_options = match backend {
        AttachBackend::TcNetlink => TcAttachOptions::Netlink(NlOptions {
            priority: spec.priority,
            handle: spec.handle,
        }),
        // TCX multi-prog ordering is not a numeric TC priority equivalent.
        // Resident same-interface WAN/LAN ordering must be controlled by attach
        // order or explicit anchors, while tc-netlink fallback keeps priority.
        AttachBackend::Tcx => TcAttachOptions::TcxOrder(match spec.tcx_order {
            TcxAttachOrder::First => LinkOrder::first(),
            TcxAttachOrder::Last => LinkOrder::last(),
        }),
        _ => unreachable!(),
    };
    classifier
        .attach_with_options(&spec.target.iface, attach_type, attach_options)
        .map_err(|err| {
            format!(
                "aya sched classifier {} attach failed: {err:?}",
                backend.as_str()
            )
        })
}

fn query_tcx_program_order(
    iface: &str,
    attach_type: TcAttachType,
) -> Result<(u64, Vec<AyaTcxProgramOrderEntry>), String> {
    let (revision, programs) = SchedClassifier::query_tcx(iface, attach_type)
        .map_err(|err| format!("aya tcx query failed: {err:?}"))?;
    let order = programs
        .into_iter()
        .map(|program| AyaTcxProgramOrderEntry {
            id: program.id(),
            name: program.name_as_str().map(str::to_owned),
            tag: format!("{:016x}", program.tag()),
        })
        .collect();
    Ok((revision, order))
}

fn verify_tcx_program_order(
    program_id: Option<u32>,
    expected_order: TcxAttachOrder,
    program_order: &[AyaTcxProgramOrderEntry],
) -> Result<(), String> {
    let program_id = program_id.ok_or_else(|| "attached program id is unavailable".to_owned())?;
    let observed_id = match expected_order {
        TcxAttachOrder::First => program_order.first().map(|entry| entry.id),
        TcxAttachOrder::Last => program_order.last().map(|entry| entry.id),
    }
    .ok_or_else(|| "tcx query returned an empty program order".to_owned())?;
    if observed_id == program_id {
        return Ok(());
    }
    Err(format!(
        "program id {program_id} is not {} in tcx query order",
        expected_order.as_str()
    ))
}
