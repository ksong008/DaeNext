use super::*;
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

pub(super) fn load_attach_detach_aya_sched_classifier_in_current_netns(
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

pub(super) fn load_attach_aya_sched_classifier_in_current_netns(
    loaded: &mut AyaUserspaceLoadedObject,
    spec: &TcNativeAttachSpec,
    backend: AttachBackend,
) -> Result<(AyaTcAttachDetachReport, SchedClassifierLinkId), String> {
    let ifindex = current_netns_interface_index(&spec.target.iface)?;
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
    let program_info = classifier
        .info()
        .map_err(|err| format!("read sched classifier program identity failed: {err:?}"))?;
    let program_id = Some(program_info.id());
    let program_tag = format!("{:016x}", program_info.tag());
    let requested_backend = backend;
    let (
        backend,
        link_id,
        backend_switch_error,
        tcx_anchor,
        tcx_pre_query_revision,
        tcx_pre_program_order,
        tcx_query_revision,
        tcx_program_order,
        tcx_query_error,
        tcx_order_verified,
        tcx_order_error,
    ) = match backend {
        AttachBackend::TcNetlink => {
            let attached = attach_loaded_aya_sched_classifier(
                classifier,
                spec,
                attach_type,
                AttachBackend::TcNetlink,
            )?;
            (
                AttachBackend::TcNetlink,
                attached.link_id,
                None,
                None,
                None,
                Vec::new(),
                None,
                Vec::new(),
                None,
                false,
                None,
            )
        }
        AttachBackend::Tcx => match attach_loaded_aya_sched_classifier(
            classifier,
            spec,
            attach_type,
            AttachBackend::Tcx,
        ) {
            Ok(attached) => match query_tcx_program_order(&spec.target.iface, attach_type) {
                Ok((revision, program_order)) => {
                    match verify_tcx_program_order(program_id, spec.tcx_order, &program_order) {
                        Ok(()) => (
                            AttachBackend::Tcx,
                            attached.link_id,
                            None,
                            attached.tcx_anchor,
                            attached.tcx_pre_query_revision,
                            attached.tcx_pre_program_order,
                            Some(revision),
                            program_order,
                            None,
                            true,
                            None,
                        ),
                        Err(order_err) => {
                            classifier.detach(attached.link_id).map_err(|detach_err| {
                                format!(
                                    "aya tcx order verification failed after attach: {order_err}; tcx detach before tc-netlink backend switch failed: {detach_err:?}"
                                )
                            })?;
                            let fallback = attach_loaded_aya_sched_classifier(
                                classifier,
                                spec,
                                attach_type,
                                AttachBackend::TcNetlink,
                            )
                            .map_err(|tc_err| {
                                format!(
                                    "aya tcx order verification failed after attach: {order_err}; tc-netlink backend switch failed: {tc_err}"
                                )
                            })?;
                            (
                                AttachBackend::TcNetlink,
                                fallback.link_id,
                                Some(format!("tcx order verification failed: {order_err}")),
                                attached.tcx_anchor,
                                attached.tcx_pre_query_revision,
                                attached.tcx_pre_program_order,
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
                    classifier.detach(attached.link_id).map_err(|detach_err| {
                        format!(
                            "aya tcx query failed after attach: {query_err}; tcx detach before tc-netlink backend switch failed: {detach_err:?}"
                        )
                    })?;
                    let fallback = attach_loaded_aya_sched_classifier(
                        classifier,
                        spec,
                        attach_type,
                        AttachBackend::TcNetlink,
                    )
                    .map_err(|tc_err| {
                        format!(
                            "aya tcx query failed after attach: {query_err}; tc-netlink backend switch failed: {tc_err}"
                        )
                    })?;
                    (
                        AttachBackend::TcNetlink,
                        fallback.link_id,
                        Some(format!("tcx query failed after attach: {query_err}")),
                        attached.tcx_anchor,
                        attached.tcx_pre_query_revision,
                        attached.tcx_pre_program_order,
                        None,
                        Vec::new(),
                        Some(query_err),
                        false,
                        None,
                    )
                }
            },
            Err(tcx_err) => {
                let fallback = attach_loaded_aya_sched_classifier(
                    classifier,
                    spec,
                    attach_type,
                    AttachBackend::TcNetlink,
                )
                .map_err(|tc_err| {
                    format!(
                        "aya sched classifier tcx attach failed: {tcx_err}; tc-netlink backend switch failed: {tc_err}"
                    )
                })?;
                (
                    AttachBackend::TcNetlink,
                    fallback.link_id,
                    Some(tcx_err),
                    None,
                    None,
                    Vec::new(),
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
            backend_switch_used: backend_switch_error.is_some(),
            backend_switch_error,
            program_id,
            program_tag,
            program_name: spec.program_name.clone(),
            iface: spec.target.iface.clone(),
            ifindex,
            netns: None,
            netns_entered: false,
            direction: spec.target.direction,
            priority: spec.priority,
            handle: spec.handle,
            tcx_order: spec.tcx_order,
            tcx_anchor,
            tcx_pre_query_revision,
            tcx_pre_program_order,
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

pub(super) fn attach_pin_aya_sched_classifier_in_current_netns(
    options: &PinnedTcAttachOptions<'_>,
) -> Result<PinnedTcAttachReport, String> {
    let spec = options.spec;
    let ifindex = current_netns_interface_index(&spec.target.iface)?;
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
    let program_info = classifier
        .info()
        .map_err(|err| format!("read pinned sched classifier identity failed: {err:?}"))?;
    let program_id = Some(program_info.id());
    let program_tag = format!("{:016x}", program_info.tag());

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
                            "aya tcx attach-pin failed: {tcx_err}; tc-netlink backend switch failed: {tc_err}"
                        )
                    })?;
                    result.backend_switch_used = true;
                    result.backend_switch_error = Some(tcx_err);
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
        AttachBackend::TcCommand => unreachable!(),
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
        // successful helper-owned attach, native cleanup keeps the contract via
        // FilterDel/delBpfFilter, so the temporary Aya link must not detach on
        // helper process exit.
        mem::forget(link);
        None
    };

    Ok(PinnedTcAttachReport {
        requested_backend: options.requested_backend,
        backend: attach_result.backend,
        backend_switch_used: attach_result.backend_switch_used,
        backend_switch_error: attach_result.backend_switch_error,
        program_id,
        program_tag,
        program_name: spec.program_name.clone(),
        program_path,
        iface: spec.target.iface.clone(),
        ifindex,
        netns: None,
        netns_entered: false,
        direction: spec.target.direction,
        priority: spec.priority,
        handle: spec.handle,
        tcx_order: spec.tcx_order,
        tcx_anchor: attach_result.tcx_anchor,
        tcx_pre_query_revision: attach_result.tcx_pre_query_revision,
        tcx_pre_program_order: attach_result.tcx_pre_program_order,
        tcx_query_revision: attach_result.tcx_query_revision,
        tcx_program_order: attach_result.tcx_program_order,
        tcx_order_verified: attach_result.tcx_order_verified,
        link_path,
        tc_filter_persistent: attach_result.backend == AttachBackend::TcNetlink,
        clsact_added_or_present: spec.clsact_required,
    })
}

pub fn query_aya_tcx_binding(
    target: &crate::TcAttachTarget,
) -> Result<AyaTcxBindingSnapshot, String> {
    let mut snapshot = with_optional_netns(target.netns.as_deref(), || {
        let attach_type = match target.direction {
            TcAttachDirection::Ingress => TcAttachType::Ingress,
            TcAttachDirection::Egress => TcAttachType::Egress,
        };
        let ifindex = current_netns_interface_index(&target.iface)?;
        let (revision, program_order) = query_tcx_program_order(&target.iface, attach_type)?;
        Ok(AyaTcxBindingSnapshot {
            iface: target.iface.clone(),
            ifindex,
            netns: None,
            direction: target.direction,
            revision,
            program_order,
        })
    })?;
    snapshot.netns = target.netns.clone();
    Ok(snapshot)
}

pub fn query_aya_interface_index(target: &crate::TcAttachTarget) -> Result<u32, String> {
    with_optional_netns(target.netns.as_deref(), || {
        current_netns_interface_index(&target.iface)
    })
}

fn current_netns_interface_index(iface: &str) -> Result<u32, String> {
    let iface = CString::new(iface)
        .map_err(|_| "interface name contains an interior NUL byte".to_owned())?;
    // SAFETY: `iface` is a live NUL-terminated C string for the duration of
    // the call. `if_nametoindex` only reads that string and returns an index
    // in the thread's current network namespace.
    let ifindex = unsafe { libc::if_nametoindex(iface.as_ptr()) };
    if ifindex == 0 {
        Err(format!(
            "resolve interface index failed: {}",
            io::Error::last_os_error()
        ))
    } else {
        Ok(ifindex)
    }
}

pub(super) struct PinnedClassifierAttachResult {
    pub(super) backend: AttachBackend,
    pub(super) link_id: SchedClassifierLinkId,
    pub(super) backend_switch_used: bool,
    pub(super) backend_switch_error: Option<String>,
    pub(super) tcx_anchor: Option<AyaTcxAttachAnchor>,
    pub(super) tcx_pre_query_revision: Option<u64>,
    pub(super) tcx_pre_program_order: Vec<AyaTcxProgramOrderEntry>,
    pub(super) tcx_query_revision: Option<u64>,
    pub(super) tcx_program_order: Vec<AyaTcxProgramOrderEntry>,
    pub(super) tcx_order_verified: bool,
}

pub(super) fn attach_pinned_classifier_once(
    classifier: &mut SchedClassifier,
    spec: &TcNativeAttachSpec,
    attach_type: TcAttachType,
    backend: AttachBackend,
    program_id: Option<u32>,
) -> Result<PinnedClassifierAttachResult, String> {
    let attached = attach_loaded_aya_sched_classifier(classifier, spec, attach_type, backend)?;
    if backend != AttachBackend::Tcx {
        return Ok(PinnedClassifierAttachResult {
            backend,
            link_id: attached.link_id,
            backend_switch_used: false,
            backend_switch_error: None,
            tcx_anchor: None,
            tcx_pre_query_revision: None,
            tcx_pre_program_order: Vec::new(),
            tcx_query_revision: None,
            tcx_program_order: Vec::new(),
            tcx_order_verified: false,
        });
    }

    let (revision, program_order) = match query_tcx_program_order(&spec.target.iface, attach_type) {
        Ok(value) => value,
        Err(query_err) => {
            classifier.detach(attached.link_id).map_err(|detach_err| {
                format!(
                    "aya tcx query failed after attach-pin: {query_err}; tcx detach failed: {detach_err:?}"
                )
            })?;
            return Err(query_err);
        }
    };
    if let Err(order_err) = verify_tcx_program_order(program_id, spec.tcx_order, &program_order) {
        classifier.detach(attached.link_id).map_err(|detach_err| {
            format!(
                "aya tcx order verification failed after attach-pin: {order_err}; tcx detach failed: {detach_err:?}"
            )
        })?;
        return Err(order_err);
    }

    Ok(PinnedClassifierAttachResult {
        backend,
        link_id: attached.link_id,
        backend_switch_used: false,
        backend_switch_error: None,
        tcx_anchor: attached.tcx_anchor,
        tcx_pre_query_revision: attached.tcx_pre_query_revision,
        tcx_pre_program_order: attached.tcx_pre_program_order,
        tcx_query_revision: Some(revision),
        tcx_program_order: program_order,
        tcx_order_verified: true,
    })
}

pub(super) struct LoadedClassifierAttachResult {
    pub(super) link_id: SchedClassifierLinkId,
    pub(super) tcx_anchor: Option<AyaTcxAttachAnchor>,
    pub(super) tcx_pre_query_revision: Option<u64>,
    pub(super) tcx_pre_program_order: Vec<AyaTcxProgramOrderEntry>,
}

pub(super) fn attach_loaded_aya_sched_classifier(
    classifier: &mut SchedClassifier,
    spec: &TcNativeAttachSpec,
    attach_type: TcAttachType,
    backend: AttachBackend,
) -> Result<LoadedClassifierAttachResult, String> {
    let (attach_options, tcx_anchor, tcx_pre_query_revision, tcx_pre_program_order) = match backend
    {
        AttachBackend::TcNetlink => (
            TcAttachOptions::Netlink(NlOptions {
                priority: spec.priority,
                handle: spec.handle,
            }),
            None,
            None,
            Vec::new(),
        ),
        // TCX multi-prog ordering is not a numeric TC priority equivalent.
        // Anchor to the currently observed edge by program id, then verify the
        // resulting order after attach. tc-netlink fallback keeps priority/handle.
        AttachBackend::Tcx => {
            let preparation =
                prepare_tcx_attach_order(&spec.target.iface, attach_type, spec.tcx_order)?;
            (
                TcAttachOptions::TcxOrder(preparation.order),
                preparation.anchor,
                Some(preparation.query_revision),
                preparation.program_order,
            )
        }
        _ => unreachable!(),
    };
    let link_id = classifier
        .attach_with_options(&spec.target.iface, attach_type, attach_options)
        .map_err(|err| {
            format!(
                "aya sched classifier {} attach failed: {err:?}",
                backend.as_str()
            )
        })?;
    Ok(LoadedClassifierAttachResult {
        link_id,
        tcx_anchor,
        tcx_pre_query_revision,
        tcx_pre_program_order,
    })
}

pub(super) fn query_tcx_program_order(
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

pub(super) fn verify_tcx_program_order(
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
