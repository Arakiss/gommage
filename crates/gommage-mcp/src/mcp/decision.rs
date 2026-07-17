use super::*;

pub(super) async fn forward_to_daemon(
    layout: &HomeLayout,
    call: &ToolCall,
) -> Result<gommage_core::EvalResult> {
    let stream = UnixStream::connect(&layout.socket).await?;
    let (r, mut w) = stream.into_split();
    let req = serde_json::json!({ "op": "decide", "call": call });
    w.write_all(serde_json::to_string(&req)?.as_bytes()).await?;
    w.write_all(b"\n").await?;
    let mut lines = TokioBufReader::new(r).lines();
    let line = lines
        .next_line()
        .await?
        .context("daemon closed without response")?;
    let resp: serde_json::Value = serde_json::from_str(&line)?;
    if resp.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        let result = resp.get("result").cloned().context("missing result")?;
        let eval: gommage_core::EvalResult = serde_json::from_value(result)?;
        Ok(eval)
    } else {
        anyhow::bail!(
            "daemon returned error: {}",
            resp.get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("<none>")
        );
    }
}

pub(super) fn is_missing_daemon(error: &anyhow::Error) -> bool {
    error.downcast_ref::<std::io::Error>().is_some_and(|e| {
        matches!(
            e.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
        )
    })
}

pub(super) fn decide_in_process_and_audit(
    layout: &HomeLayout,
    call: &ToolCall,
) -> Result<gommage_core::EvalResult> {
    let sk = layout.load_key()?;
    let vk = sk.verifying_key();
    let rt = Runtime::open(HomeLayout::at(&layout.root))?;
    let caps = rt.mapper.map(call);
    let mut eval = evaluate(&caps, &rt.policy);
    let mut events = Vec::new();
    if let Decision::AskPicto {
        required_scope,
        reason,
        bind_input,
    } = eval.decision.clone()
    {
        let now = time::OffsetDateTime::now_utc();
        let input_hash = call.input_hash();
        let lookup = if bind_input {
            rt.pictos
                .find_verified_match_for_input(&required_scope, &input_hash, now, &vk)?
        } else {
            rt.pictos.find_verified_match(&required_scope, now, &vk)?
        };
        match lookup {
            PictoLookup::None => {
                let request = rt.approvals.request_for_ask(
                    call,
                    &eval,
                    &required_scope,
                    bind_input,
                    &reason,
                )?;
                events.push(AuditEvent::ApprovalRequested {
                    id: request.id.clone(),
                    tool: request.tool.clone(),
                    input_hash: request.input_hash.clone(),
                    required_scope: request.required_scope.clone(),
                    reason: request.reason.clone(),
                    policy_version: request.policy_version.clone(),
                });
                for event in notify_approval_webhook_best_effort(&request) {
                    events.push(event);
                }
                eval.decision = Decision::AskPicto {
                    required_scope,
                    reason: approval_reason(&reason, &request.id),
                    bind_input,
                };
            }
            PictoLookup::BadSignature { id, scope } => {
                events.push(AuditEvent::PictoRejected {
                    id,
                    scope,
                    reason: "bad signature".to_string(),
                });
            }
            PictoLookup::Verified { picto } => {
                let consume = if bind_input {
                    rt.pictos
                        .consume_verified_for_input(&picto.id, &input_hash, now, &vk)?
                } else {
                    rt.pictos.consume_verified(&picto.id, now, &vk)?
                };
                match consume {
                    PictoConsume::Consumed { picto } => {
                        let authorization = AuthorizationEvidence::from_picto(&picto);
                        let satisfied = rt.approvals.satisfy_matching_call(
                            &call.tool,
                            &input_hash,
                            &required_scope,
                            &picto.binding,
                            &eval.policy_version,
                            &picto.id,
                        )?;
                        events.push(AuditEvent::PictoConsumed {
                            id: picto.id.clone(),
                            scope: picto.scope.clone(),
                            uses: picto.uses,
                            max_uses: picto.max_uses,
                            status: picto.status.as_str().to_string(),
                        });
                        if let Some(resolution) = satisfied {
                            events.push(AuditEvent::ApprovalResolved {
                                id: resolution.request_id,
                                status: resolution.status.as_str().to_string(),
                                reason: resolution.reason,
                                picto_id: resolution.picto_id,
                            });
                        }
                        eval.authorization = Some(authorization);
                        eval.decision = Decision::Allow;
                    }
                    PictoConsume::NotUsable => {}
                    PictoConsume::BadSignature { id, scope } => {
                        events.push(AuditEvent::PictoRejected {
                            id,
                            scope,
                            reason: "bad signature".to_string(),
                        });
                    }
                }
            }
        }
    }
    let expedition_name = rt.expedition.as_ref().map(|e| e.name.clone());
    let mut writer = AuditWriter::open(&rt.layout.audit_log, sk)?;
    for event in events {
        writer.append_event(event)?;
    }
    writer.append(call, &eval, expedition_name.as_deref())?;
    Ok(eval)
}

pub(super) fn approval_reason(reason: &str, request_id: &str) -> String {
    format!(
        "{reason}; approval request {request_id} pending; run `gommage approval approve {request_id}`"
    )
}

pub(super) fn notify_approval_webhook_best_effort(request: &ApprovalRequest) -> Vec<AuditEvent> {
    let Ok(url) = env::var("GOMMAGE_APPROVAL_WEBHOOK_URL") else {
        return Vec::new();
    };
    if url.trim().is_empty() {
        return Vec::new();
    }
    let payload = approval_webhook_generic_payload(request);
    let Ok(prepared) = prepare_approval_webhook(
        payload,
        env::var("GOMMAGE_APPROVAL_WEBHOOK_SECRET").ok().as_deref(),
        env::var("GOMMAGE_APPROVAL_WEBHOOK_SECRET_ID")
            .ok()
            .as_deref(),
    ) else {
        return Vec::new();
    };
    let layout = HomeLayout::default();
    let settings = ApprovalWebhookDeliverySettings::from_env();
    match deliver_prepared_approval_webhook(
        &layout,
        request,
        ApprovalWebhookSource::McpFallback,
        "generic",
        &url,
        &prepared,
        &settings,
    ) {
        Ok(outcome) if outcome.kind == ApprovalWebhookDeliveryKind::Delivered => {
            vec![AuditEvent::ApprovalWebhookDelivered {
                id: request.id.clone(),
                url,
                status: outcome.http_status,
                attempts: outcome.attempts,
                source: ApprovalWebhookSource::McpFallback.as_str().to_string(),
                signature: outcome.signature.as_ref().map(signature_audit_summary),
            }]
        }
        Ok(outcome) => {
            let error = outcome
                .error
                .clone()
                .unwrap_or_else(|| "webhook delivery failed".to_string());
            vec![
                AuditEvent::ApprovalWebhookFailed {
                    id: request.id.clone(),
                    url: url.clone(),
                    error: error.clone(),
                    attempts: outcome.attempts,
                    source: ApprovalWebhookSource::McpFallback.as_str().to_string(),
                    signature: outcome.signature.as_ref().map(signature_audit_summary),
                },
                AuditEvent::ApprovalWebhookDeadLettered {
                    id: request.id.clone(),
                    url,
                    dead_letter_id: outcome
                        .dead_letter_id
                        .clone()
                        .unwrap_or_else(|| "<unknown>".to_string()),
                    provider: "generic".to_string(),
                    attempts: outcome.attempts,
                    source: ApprovalWebhookSource::McpFallback.as_str().to_string(),
                    error,
                    signature: outcome.signature.as_ref().map(signature_audit_summary),
                },
            ]
        }
        Err(error) => vec![AuditEvent::ApprovalWebhookFailed {
            id: request.id.clone(),
            url,
            error: error.to_string(),
            attempts: settings.attempts,
            source: ApprovalWebhookSource::McpFallback.as_str().to_string(),
            signature: prepared.signature.as_ref().map(signature_audit_summary),
        }],
    }
}

pub(super) fn signature_audit_summary(
    signature: &WebhookSignatureReport,
) -> gommage_audit::WebhookSignatureAudit {
    gommage_audit::WebhookSignatureAudit {
        algorithm: signature.algorithm.clone(),
        key_id: signature.key_id.clone(),
        timestamp: signature.timestamp.clone(),
        body_sha256: signature.body_sha256.clone(),
        signature_prefix: signature.signature.chars().take(18).collect(),
    }
}
