use super::*;

pub(super) fn read_callback_body(path: Option<PathBuf>) -> Result<Vec<u8>> {
    if let Some(path) = path {
        return Ok(std::fs::read(path)?);
    }
    let mut body = Vec::new();
    std::io::stdin().read_to_end(&mut body)?;
    Ok(body)
}

pub(super) fn approval_list(
    layout: HomeLayout,
    json: bool,
    status: ApprovalStatusArg,
) -> Result<ExitCode> {
    let store = ApprovalStore::open(&layout.approvals_log);
    let mut states = store.list()?;
    if let Some(status) = status.status() {
        states.retain(|state| state.status == status);
    }
    if json {
        let items = states
            .iter()
            .map(ApprovalListItem::from)
            .collect::<Vec<_>>();
        println!("{}", serde_json::to_string_pretty(&items)?);
        return Ok(ExitCode::SUCCESS);
    }
    if states.is_empty() {
        print_empty_inbox(status);
        return Ok(ExitCode::SUCCESS);
    }
    print_inbox(&states, status);
    Ok(ExitCode::SUCCESS)
}

pub(super) fn approval_show(layout: HomeLayout, id: &str, json: bool) -> Result<ExitCode> {
    let store = ApprovalStore::open(&layout.approvals_log);
    let Some(state) = store.get(id)? else {
        println!("approval request {id} not found");
        return Ok(ExitCode::from(1));
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&state)?);
    } else {
        print_state_detail(&state);
    }
    Ok(ExitCode::SUCCESS)
}

pub(super) fn approval_approve(
    layout: HomeLayout,
    id: &str,
    uses: u32,
    ttl: i64,
    reason: &str,
    json: bool,
) -> Result<ExitCode> {
    let report = approve_request(&layout, id, uses, ttl, reason)?;
    print_action(json, report)
}

pub(crate) fn approve_request(
    layout: &HomeLayout,
    id: &str,
    uses: u32,
    ttl: i64,
    reason: &str,
) -> Result<ApprovalActionReport> {
    layout.ensure()?;
    let store = ApprovalStore::open(&layout.approvals_log);
    let state = store
        .get(id)?
        .with_context(|| format!("approval request {id:?} not found"))?;
    if state.status != ApprovalStatus::Pending {
        anyhow::bail!("approval request {id:?} is {}", state.status.as_str());
    }

    let read_model = PolicyReadModel::load(layout).context("loading current policy")?;
    let replay = evaluate(&state.request.capabilities, &read_model.policy);
    let replay_matches = matches!(
        &replay.decision,
        Decision::AskPicto {
            required_scope,
            bind_input,
            ..
        } if required_scope == &state.request.required_scope
            && *bind_input == state.request.bind_input
    );
    if !replay_matches {
        let replay_reason = format!(
            "current policy no longer requires the same scope and binding (current decision: {})",
            decision_summary(&replay.decision)
        );
        let resolution = store.resolve(id, ApprovalStatus::Superseded, &replay_reason, None)?;
        let sk = layout.load_key()?;
        AuditWriter::open(&layout.audit_log, sk)?.append_event(AuditEvent::ApprovalResolved {
            id: resolution.request_id,
            status: resolution.status.as_str().to_string(),
            reason: resolution.reason,
            picto_id: None,
        })?;
        anyhow::bail!("approval request {id:?} was superseded: {replay_reason}");
    }

    let sk = layout.load_key()?;
    let pictos = PictoStore::open(&layout.pictos_db)?;
    let picto_id = format!("picto_{}", uuid::Uuid::now_v7());
    let input_bound = state.request.bind_input;
    let approval_reason = if reason.trim().is_empty() {
        format!("approved request {id}")
    } else {
        reason.to_string()
    };
    let picto = if input_bound {
        pictos.create_for_input(
            &picto_id,
            &state.request.required_scope,
            &state.request.input_hash,
            uses,
            ttl,
            &approval_reason,
            &sk,
            false,
        )?
    } else {
        pictos.create(
            &picto_id,
            &state.request.required_scope,
            uses,
            ttl,
            &approval_reason,
            &sk,
            false,
        )?
    };
    let resolution = store.resolve(
        id,
        ApprovalStatus::Approved,
        &approval_reason,
        Some(picto.id.clone()),
    )?;

    let mut writer = AuditWriter::open(&layout.audit_log, sk)?;
    writer.append_event(AuditEvent::PictoCreated {
        id: picto.id.clone(),
        scope: picto.scope.clone(),
        max_uses: picto.max_uses,
        ttl_expires_at: picto.ttl_expires_at.to_string(),
        require_confirmation: false,
    })?;
    writer.append_event(AuditEvent::ApprovalResolved {
        id: resolution.request_id.clone(),
        status: resolution.status.as_str().to_string(),
        reason: resolution.reason.clone(),
        picto_id: resolution.picto_id.clone(),
    })?;

    let picto_id = picto.id.clone();
    let picto_scope = picto.scope.clone();
    let picto_expires_at = format_timestamp(picto.ttl_expires_at);
    let picto_max_uses = picto.max_uses;
    let uses_remaining = picto.max_uses.saturating_sub(picto.uses);
    Ok(ApprovalActionReport {
        schema_version: 2,
        kind: "approval_action".to_string(),
        status: "approved".to_string(),
        request_id: id.to_string(),
        tool: state.request.tool,
        scope: picto_scope.clone(),
        reason: approval_reason,
        picto_id: Some(picto_id.clone()),
        picto: Some(ApprovalPictoReport {
            kind: if input_bound {
                "exact_input".to_string()
            } else {
                "scope_only".to_string()
            },
            id: picto_id,
            scope: picto_scope.clone(),
            input_bound,
            authorizes: if input_bound {
                "only_the_exact_observed_tool_input".to_string()
            } else {
                "any_matching_call_in_scope".to_string()
            },
            consumption: "one_use_per_matching_call".to_string(),
            matching_call_consumes_use: true,
            non_matching_call_consumes_use: false,
            max_uses: picto_max_uses,
            uses_remaining,
            expires_at: picto_expires_at,
        }),
        next_action: "retry_blocked_call".to_string(),
        message: if input_bound {
            format!(
                "approved {id}; minted input-bound picto for {picto_scope}; each matching call consumes one use"
            )
        } else {
            format!(
                "approved {id}; minted scope-only picto for {picto_scope}; any matching call consumes one use"
            )
        },
    })
}

pub(super) fn decision_summary(decision: &Decision) -> String {
    match decision {
        Decision::Allow => "allow".to_string(),
        Decision::Gommage { reason, hard_stop } => {
            format!("gommage(hard_stop={hard_stop}, reason={reason})")
        }
        Decision::AskPicto {
            required_scope,
            bind_input,
            ..
        } => format!("ask_picto(scope={required_scope}, bind_input={bind_input})"),
    }
}

pub(super) fn approval_deny(
    layout: HomeLayout,
    id: &str,
    reason: &str,
    json: bool,
) -> Result<ExitCode> {
    let report = deny_request(&layout, id, reason)?;
    print_action(json, report)
}

pub(super) fn approval_deny_stale(
    layout: HomeLayout,
    older_than: i64,
    apply: bool,
    limit: Option<usize>,
    reason: &str,
    json: bool,
    show_all: bool,
) -> Result<ExitCode> {
    let store = ApprovalStore::open(&layout.approvals_log);
    let now = OffsetDateTime::now_utc();
    let mut stale = store
        .pending()?
        .into_iter()
        .filter_map(|state| approval_age_seconds(&state, now).map(|age| (state, age)))
        .filter(|(_, age)| *age >= older_than as u64)
        .collect::<Vec<_>>();
    stale.sort_by_key(|(state, _)| state.request.created_at);
    if let Some(limit) = limit {
        stale.truncate(limit);
    }

    let mut report = ApprovalDenyStaleReport {
        schema_version: 1,
        kind: "approval_deny_stale",
        apply,
        older_than_seconds: older_than,
        matched: stale.len(),
        denied: 0,
        requests: Vec::with_capacity(stale.len()),
    };

    let mut audit = if apply && !stale.is_empty() {
        layout.ensure()?;
        Some(AuditWriter::open(&layout.audit_log, layout.load_key()?)?)
    } else {
        None
    };

    let deny_reason = if reason.trim().is_empty() {
        "stale approval request closed by operator sweep"
    } else {
        reason
    };

    for (state, age_seconds) in stale {
        let status = if apply {
            let resolution =
                store.resolve(&state.request.id, ApprovalStatus::Denied, deny_reason, None)?;
            if let Some(writer) = audit.as_mut() {
                writer.append_event(AuditEvent::ApprovalResolved {
                    id: resolution.request_id.clone(),
                    status: resolution.status.as_str().to_string(),
                    reason: resolution.reason.clone(),
                    picto_id: None,
                })?;
            }
            report.denied += 1;
            "denied"
        } else {
            "dry_run"
        };
        report.requests.push(ApprovalDenyStaleItem {
            id: state.request.id,
            status,
            created_at: format_timestamp(state.request.created_at),
            age_seconds,
            tool: state.request.tool,
            scope: state.request.required_scope,
        });
    }

    print_deny_stale_report(json, &report, show_all)?;
    Ok(ExitCode::SUCCESS)
}

pub(super) fn approval_age_seconds(state: &ApprovalState, now: OffsetDateTime) -> Option<u64> {
    let duration = now - state.request.created_at;
    if duration.is_negative() {
        return None;
    }
    Some(duration.whole_seconds() as u64)
}

pub(crate) fn deny_request(
    layout: &HomeLayout,
    id: &str,
    reason: &str,
) -> Result<ApprovalActionReport> {
    layout.ensure()?;
    let store = ApprovalStore::open(&layout.approvals_log);
    let state = store
        .get(id)?
        .with_context(|| format!("approval request {id:?} not found"))?;
    let deny_reason = if reason.trim().is_empty() {
        format!("denied request {id}")
    } else {
        reason.to_string()
    };
    let sk = layout.load_key()?;
    let resolution = store.resolve(id, ApprovalStatus::Denied, &deny_reason, None)?;
    let mut writer = AuditWriter::open(&layout.audit_log, sk)?;
    writer.append_event(AuditEvent::ApprovalResolved {
        id: resolution.request_id.clone(),
        status: resolution.status.as_str().to_string(),
        reason: resolution.reason.clone(),
        picto_id: None,
    })?;
    Ok(ApprovalActionReport {
        schema_version: 2,
        kind: "approval_action".to_string(),
        status: "denied".to_string(),
        request_id: id.to_string(),
        tool: state.request.tool,
        scope: state.request.required_scope,
        reason: deny_reason,
        picto_id: None,
        picto: None,
        next_action: "none".to_string(),
        message: format!("denied {id}"),
    })
}
