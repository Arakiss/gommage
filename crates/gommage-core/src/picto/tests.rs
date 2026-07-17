use super::*;
use rand_core::OsRng;
use std::{
    fs,
    sync::{Arc, Barrier},
    thread,
};
use tempfile::tempdir;

fn key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn input_hash(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn whole_second_now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp()).unwrap()
}

fn assert_invalid_picto(result: Result<Picto, GommageError>, field: &str) {
    match result {
        Err(GommageError::InvalidPicto(message)) => {
            assert!(
                message.contains(field),
                "expected {field:?} in validation error, got {message:?}"
            );
        }
        other => panic!("expected InvalidPicto for {field}, got {other:?}"),
    }
}

#[test]
fn create_find_consume() {
    let store = PictoStore::open_in_memory().unwrap();
    let sk = key();
    let picto = store
        .create("p1", "git.push:main", 1, 600, "test", &sk, false)
        .unwrap();
    picto.verify(&sk.verifying_key()).unwrap();

    let found = store
        .find_match("git.push:main", OffsetDateTime::now_utc())
        .unwrap();
    assert!(found.is_some());
    assert!(store.consume("p1").unwrap());
    // second consume fails — use exhausted
    assert!(!store.consume("p1").unwrap());
    // after exhaustion, no match
    assert!(
        store
            .find_match("git.push:main", OffsetDateTime::now_utc())
            .unwrap()
            .is_none()
    );
}

#[test]
fn read_store_never_migrates_or_creates_sidecars() {
    let td = tempdir().unwrap();
    let path = td.path().join("pictos.sqlite");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        r#"
            CREATE TABLE pictos (
                id TEXT PRIMARY KEY,
                scope TEXT NOT NULL,
                max_uses INTEGER NOT NULL,
                uses INTEGER NOT NULL,
                ttl_expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                status TEXT NOT NULL,
                reason TEXT NOT NULL,
                signature_b64 TEXT NOT NULL
            );
            "#,
    )
    .unwrap();
    drop(conn);
    let before = fs::read(&path).unwrap();

    let store = PictoReadStore::open(&path).unwrap();
    assert!(store.list().unwrap().is_empty());
    drop(store);

    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(!path.with_extension("sqlite-wal").exists());
    assert!(!path.with_extension("sqlite-shm").exists());
}

#[test]
fn verified_lookup_rejects_tampered_scope() {
    let store = PictoStore::open_in_memory().unwrap();
    let sk = key();
    store
        .create("p1", "git.push:feature", 1, 600, "test", &sk, false)
        .unwrap();
    store
        .conn
        .execute(
            "UPDATE pictos SET scope = 'git.push:main' WHERE id = 'p1'",
            [],
        )
        .unwrap();

    let found = store
        .find_verified_match(
            "git.push:main",
            OffsetDateTime::now_utc(),
            &sk.verifying_key(),
        )
        .unwrap();
    assert!(matches!(found, PictoLookup::BadSignature { .. }));
}

#[test]
fn verified_consume_rejects_tampered_scope() {
    let store = PictoStore::open_in_memory().unwrap();
    let sk = key();
    store
        .create("p1", "git.push:feature", 1, 600, "test", &sk, false)
        .unwrap();
    store
        .conn
        .execute(
            "UPDATE pictos SET scope = 'git.push:main' WHERE id = 'p1'",
            [],
        )
        .unwrap();

    let consumed = store
        .consume_verified("p1", OffsetDateTime::now_utc(), &sk.verifying_key())
        .unwrap();
    assert!(matches!(consumed, PictoConsume::BadSignature { .. }));
    assert_eq!(store.get("p1").unwrap().unwrap().uses, 0);
}

#[test]
fn verified_consume_updates_uses_and_status() {
    let store = PictoStore::open_in_memory().unwrap();
    let sk = key();
    store
        .create("p1", "git.push:main", 1, 600, "test", &sk, false)
        .unwrap();

    let consumed = store
        .consume_verified("p1", OffsetDateTime::now_utc(), &sk.verifying_key())
        .unwrap();
    let PictoConsume::Consumed { picto } = consumed else {
        panic!("expected consumed picto");
    };
    assert_eq!(picto.uses, 1);
    assert_eq!(picto.status, PictoStatus::Spent);
    assert!(
        store
            .find_match("git.push:main", OffsetDateTime::now_utc())
            .unwrap()
            .is_none()
    );
}

#[test]
fn concurrent_verified_consumers_spend_one_use_exactly_once() {
    const CONSUMERS: usize = 32;

    let dir = tempdir().unwrap();
    let path = dir.path().join("pictos.sqlite");
    let sk = key();
    let store = PictoStore::open(&path).unwrap();
    store
        .create("p1", "git.push:main", 1, 600, "test", &sk, false)
        .unwrap();
    drop(store);

    // Open before the barrier so WAL setup is not part of the race under
    // test. Each worker still owns an independent SQLite connection, as
    // separate daemon/MCP processes would.
    let stores = (0..CONSUMERS)
        .map(|_| PictoStore::open(&path).unwrap())
        .collect::<Vec<_>>();
    let barrier = Arc::new(Barrier::new(CONSUMERS));
    let verifying_key = sk.verifying_key();
    let handles = stores
        .into_iter()
        .map(|store| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                store
                    .consume_verified("p1", OffsetDateTime::now_utc(), &verifying_key)
                    .unwrap()
            })
        })
        .collect::<Vec<_>>();

    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, PictoConsume::Consumed { .. }))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, PictoConsume::NotUsable))
            .count(),
        CONSUMERS - 1
    );

    let stored = PictoStore::open(&path).unwrap().get("p1").unwrap().unwrap();
    assert_eq!(stored.uses, 1);
    assert_eq!(stored.status, PictoStatus::Spent);
}

#[test]
fn revoke_blocks_match() {
    let store = PictoStore::open_in_memory().unwrap();
    let sk = key();
    store
        .create("p1", "git.push:main", 2, 600, "x", &sk, false)
        .unwrap();
    assert!(store.revoke("p1").unwrap());
    assert!(
        store
            .find_match("git.push:main", OffsetDateTime::now_utc())
            .unwrap()
            .is_none()
    );
}

#[test]
fn pending_confirmation_not_usable() {
    let store = PictoStore::open_in_memory().unwrap();
    let sk = key();
    store
        .create("p1", "git.push:main", 1, 600, "x", &sk, true)
        .unwrap();
    assert!(
        store
            .find_match("git.push:main", OffsetDateTime::now_utc())
            .unwrap()
            .is_none()
    );
    assert!(store.confirm("p1").unwrap());
    assert!(
        store
            .find_match("git.push:main", OffsetDateTime::now_utc())
            .unwrap()
            .is_some()
    );
}

#[test]
fn expired_ignored() {
    let store = PictoStore::open_in_memory().unwrap();
    let sk = key();
    store
        .create("p1", "git.push:main", 1, 1, "x", &sk, false)
        .unwrap();
    std::thread::sleep(std::time::Duration::from_secs(2));
    let now = OffsetDateTime::now_utc();
    store.sweep_expired(now).unwrap();
    assert!(store.find_match("git.push:main", now).unwrap().is_none());
}

#[test]
fn signature_verifies_roundtrip() {
    let store = PictoStore::open_in_memory().unwrap();
    let sk = key();
    let picto = store.create("p1", "any", 1, 60, "r", &sk, false).unwrap();
    assert!(picto.verify(&sk.verifying_key()).is_ok());
    assert_eq!(picto.created_at.nanosecond(), 0);
    assert_eq!(picto.ttl_expires_at.nanosecond(), 0);

    let wrong = SigningKey::generate(&mut OsRng);
    assert!(picto.verify(&wrong.verifying_key()).is_err());
}

#[test]
fn legacy_v1_signing_vectors_remain_byte_stable() {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let picto = Picto {
        id: "picto_legacy_001".to_string(),
        scope: "gommage.authorize".to_string(),
        max_uses: 3,
        uses: 2,
        ttl_expires_at: OffsetDateTime::from_unix_timestamp(1_700_000_600).unwrap(),
        created_at: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
        status: PictoStatus::Revoked,
        reason: "operator reviewed exact command".to_string(),
        signature_b64: String::new(),
        binding: PictoBinding::ScopeOnly,
    };
    let input_hash = input_hash('a');
    let scope_payload = picto.signing_payload_for_input_hash_unchecked(None);
    let input_payload = picto.signing_payload_for_input_hash_unchecked(Some(&input_hash));

    assert_eq!(
            scope_payload,
            b"picto_legacy_001\ngommage.authorize\n3\n1700000600\n1700000000\noperator reviewed exact command"
        );
    assert_eq!(
            input_payload,
            b"picto_legacy_001\ngommage.authorize\n3\n1700000600\n1700000000\noperator reviewed exact command\ninput_hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );

    let mut scope_only = picto.clone();
    scope_only.signature_b64 =
        "Zgig5tGaUvom9GgN4rXhIf3fHKoWM35J0yL9Q0eWGXfUHOqNfx2oHaY5BxSt/lrR+Ag+h4wNva/xBJGaJC2KBg"
            .to_string();
    let mut input_bound = picto;
    input_bound.binding = PictoBinding::ExactInput {
        input_hash: input_hash.clone(),
    };
    input_bound.signature_b64 =
        "JHfuED1g5eQaJNXsXX0w5zZ2HjpdUImRLYTi+jTjO8Rs719bjgll2MICxn+RJ7LeQMtI9ajJ/TsE8xkFiznTBQ"
            .to_string();

    scope_only.verify(&signing_key.verifying_key()).unwrap();
    input_bound
        .verify_for_input_hash(Some(&input_hash), &signing_key.verifying_key())
        .unwrap();
}

#[test]
fn signature_encoding_must_be_canonical() {
    let store = PictoStore::open_in_memory().unwrap();
    let sk = key();
    let mut picto = store.create("p1", "scope", 1, 60, "r", &sk, false).unwrap();
    picto.signature_b64.push('=');

    assert!(matches!(
        picto.verify(&sk.verifying_key()),
        Err(GommageError::BadSignature)
    ));

    store
        .conn
        .execute(
            "UPDATE pictos SET signature_b64 = ?1 WHERE id = 'p1'",
            params![picto.signature_b64],
        )
        .unwrap();
    assert!(matches!(
        store
            .find_verified_match("scope", OffsetDateTime::now_utc(), &sk.verifying_key())
            .unwrap(),
        PictoLookup::BadSignature { .. }
    ));
}

#[test]
fn verification_rejects_weak_key_signatures_accepted_by_permissive_ed25519() {
    use ed25519_dalek::Verifier as _;

    let mut weak_key_bytes = [0_u8; 32];
    weak_key_bytes[0] = 1;
    let weak_key = VerifyingKey::from_bytes(&weak_key_bytes).unwrap();
    assert!(weak_key.is_weak());

    let mut signature_bytes = [0_u8; 64];
    signature_bytes[0] = 1;
    let signature = Signature::from_bytes(&signature_bytes);
    let created_at = whole_second_now();
    let picto = Picto {
        id: "strict-signature".to_string(),
        scope: "test.strict".to_string(),
        max_uses: 1,
        uses: 0,
        ttl_expires_at: created_at + time::Duration::seconds(60),
        created_at,
        status: PictoStatus::Active,
        reason: "strict verification regression".to_string(),
        signature_b64: base64_encode(&signature_bytes),
        binding: PictoBinding::ScopeOnly,
    };
    let payload = picto.signing_payload_for_input_hash_unchecked(None);

    assert!(weak_key.verify(&payload, &signature).is_ok());
    assert!(matches!(
        picto.verify(&weak_key),
        Err(GommageError::BadSignature)
    ));
}

#[test]
fn creation_rejects_ambiguous_or_empty_signed_text_fields() {
    let store = PictoStore::open_in_memory().unwrap();
    let sk = key();

    assert_invalid_picto(store.create("", "scope", 1, 60, "r", &sk, false), "id");
    assert_invalid_picto(store.create("p1", "", 1, 60, "r", &sk, false), "scope");
    assert_invalid_picto(
        store.create("p1\nother", "scope", 1, 60, "r", &sk, false),
        "id",
    );
    assert_invalid_picto(
        store.create("hidden\u{200b}id", "scope", 1, 60, "r", &sk, false),
        "id",
    );
    assert_invalid_picto(
        store.create("id with space", "scope", 1, 60, "r", &sk, false),
        "id",
    );
    assert_invalid_picto(
        store.create("p2", "scope\radmin", 1, 60, "r", &sk, false),
        "scope",
    );
    assert_invalid_picto(
        store.create("p3", "scope", 1, 60, "tab\treason", &sk, false),
        "reason",
    );
    assert_invalid_picto(
        store.create("p4", "scope", 1, 60, "nul\0reason", &sk, false),
        "reason",
    );
    assert_invalid_picto(
        store.create("p5", "scope", 1, 60, "unicode\u{2028}separator", &sk, false),
        "reason",
    );
    assert_invalid_picto(
        store.create("p6", "safe\u{202e}evil", 1, 60, "r", &sk, false),
        "scope",
    );
    assert_invalid_picto(
        store.create("p7", "safe\u{2066}evil", 1, 60, "r", &sk, false),
        "scope",
    );
    assert_invalid_picto(
        store.create("p8", "safe\u{200b}evil", 1, 60, "r", &sk, false),
        "scope",
    );
    assert_invalid_picto(
        store.create("p8-space", "scope with space", 1, 60, "r", &sk, false),
        "scope",
    );
    assert_invalid_picto(
        store.create_for_input(
            "p9",
            "scope",
            &format!("SHA256:{}", "a".repeat(64)),
            1,
            60,
            "r",
            &sk,
            false,
        ),
        "input_hash",
    );
    assert_invalid_picto(
        store.create("p10", "scope", 0, 60, "r", &sk, false),
        "max_uses",
    );
    assert_invalid_picto(store.create("p11", "scope", 1, 0, "r", &sk, false), "ttl");
    assert_invalid_picto(
        store.create(
            "p12",
            "scope",
            1,
            MAX_PICTO_TTL_SECONDS + 1,
            "r",
            &sk,
            false,
        ),
        "ttl",
    );
    assert!(store.list().unwrap().is_empty());
}

#[test]
fn reason_allows_visible_unicode_and_emoji_variation_selectors() {
    let store = PictoStore::open_in_memory().unwrap();
    let sk = key();
    let picto = store
        .create(
            "p1",
            "approval.reason",
            1,
            60,
            "Revisión del operador ✅️",
            &sk,
            false,
        )
        .unwrap();

    picto.verify(&sk.verifying_key()).unwrap();
}

#[test]
fn signed_text_field_byte_limits_are_exact() {
    let store = PictoStore::open_in_memory().unwrap();
    let sk = key();
    let picto = store
        .create(
            &"i".repeat(MAX_PICTO_ID_BYTES),
            &"s".repeat(MAX_PICTO_SCOPE_BYTES),
            1,
            60,
            &"r".repeat(MAX_PICTO_REASON_BYTES),
            &sk,
            false,
        )
        .unwrap();
    picto.verify(&sk.verifying_key()).unwrap();

    let mut legacy_oversized = picto.clone();
    legacy_oversized.id.push('i');
    legacy_oversized.signature_b64 = base64_encode(
        &sk.sign(&legacy_oversized.signing_payload_for_input_hash_unchecked(None))
            .to_bytes(),
    );
    assert!(matches!(
        legacy_oversized.verify(&sk.verifying_key()),
        Err(GommageError::BadSignature)
    ));

    assert_invalid_picto(
        store.create(
            &"i".repeat(MAX_PICTO_ID_BYTES + 1),
            "scope",
            1,
            60,
            "r",
            &sk,
            false,
        ),
        "id",
    );
    assert_invalid_picto(
        store.create(
            "scope-overflow",
            &"s".repeat(MAX_PICTO_SCOPE_BYTES + 1),
            1,
            60,
            "r",
            &sk,
            false,
        ),
        "scope",
    );
    assert_invalid_picto(
        store.create(
            "reason-overflow",
            "scope",
            1,
            60,
            &"r".repeat(MAX_PICTO_REASON_BYTES + 1),
            &sk,
            false,
        ),
        "reason",
    );

    // The contract is byte-bounded, not character-count bounded.
    let multibyte_id = "é".repeat((MAX_PICTO_ID_BYTES / 2) + 1);
    assert!(multibyte_id.chars().count() < MAX_PICTO_ID_BYTES);
    assert!(multibyte_id.len() > MAX_PICTO_ID_BYTES);
    assert_invalid_picto(
        store.create(&multibyte_id, "scope", 1, 60, "r", &sk, false),
        "id",
    );
}

#[test]
fn verification_rejects_noncanonical_timestamp_representation() {
    let store = PictoStore::open_in_memory().unwrap();
    let sk = key();
    let picto = store.create("p1", "scope", 1, 60, "r", &sk, false).unwrap();
    let mut subsecond = picto.clone();
    subsecond.created_at = subsecond.created_at.replace_nanosecond(1).unwrap();

    // The legacy encoder ignored subseconds. Verification must reject the
    // non-canonical representation even though the signature bytes match.
    assert_eq!(
        picto.signing_payload_for_input_hash_unchecked(None),
        subsecond.signing_payload_for_input_hash_unchecked(None)
    );
    assert!(matches!(
        subsecond.verify(&sk.verifying_key()),
        Err(GommageError::BadSignature)
    ));
}

#[test]
fn input_bound_picto_matches_only_the_approved_input() {
    let store = PictoStore::open_in_memory().unwrap();
    let sk = key();
    let approved_input = input_hash('a');
    let other_input = input_hash('b');
    let created = store
        .create_for_input(
            "p1",
            "deploy.production",
            &approved_input,
            1,
            600,
            "reviewed exact deployment",
            &sk,
            false,
        )
        .unwrap();
    assert_eq!(
        created.binding,
        PictoBinding::ExactInput {
            input_hash: approved_input.clone(),
        }
    );
    assert!(created.verify(&sk.verifying_key()).is_ok());
    assert!(matches!(
        created.verify_for_input_hash(None, &sk.verifying_key()),
        Err(GommageError::BadSignature)
    ));
    let encoded = serde_json::to_value(&created).unwrap();
    assert_eq!(encoded["binding"]["kind"], "exact_input");
    assert_eq!(encoded["binding"]["input_hash"], approved_input);
    assert_eq!(store.get("p1").unwrap().unwrap().binding, created.binding);
    assert_eq!(store.list().unwrap()[0].binding, created.binding);

    assert!(matches!(
        store
            .find_verified_match_for_input(
                "deploy.production",
                &approved_input,
                OffsetDateTime::now_utc(),
                &sk.verifying_key(),
            )
            .unwrap(),
        PictoLookup::Verified { .. }
    ));
    assert!(matches!(
        store
            .find_verified_match_for_input(
                "deploy.production",
                &other_input,
                OffsetDateTime::now_utc(),
                &sk.verifying_key(),
            )
            .unwrap(),
        PictoLookup::None
    ));
    assert!(matches!(
        store
            .consume_verified_for_input(
                "p1",
                &other_input,
                OffsetDateTime::now_utc(),
                &sk.verifying_key(),
            )
            .unwrap(),
        PictoConsume::NotUsable
    ));
    assert_eq!(store.get("p1").unwrap().unwrap().uses, 0);

    assert!(matches!(
        store
            .consume_verified_for_input(
                "p1",
                &approved_input,
                OffsetDateTime::now_utc(),
                &sk.verifying_key(),
            )
            .unwrap(),
        PictoConsume::Consumed { .. }
    ));
}

#[test]
fn legacy_json_without_binding_defaults_to_scope_only() {
    let store = PictoStore::open_in_memory().unwrap();
    let sk = key();
    let picto = store.create("p1", "scope", 1, 60, "r", &sk, false).unwrap();
    let mut value = serde_json::to_value(&picto).unwrap();
    assert_eq!(value["binding"]["kind"], "scope_only");
    value.as_object_mut().unwrap().remove("binding");

    let legacy: Picto = serde_json::from_value(value).unwrap();

    assert_eq!(legacy.binding, PictoBinding::ScopeOnly);
    legacy.verify(&sk.verifying_key()).unwrap();
}

#[test]
fn input_binding_tampering_rejects_the_picto_signature() {
    let store = PictoStore::open_in_memory().unwrap();
    let sk = key();
    let approved_input = input_hash('a');
    let tampered_input = input_hash('b');
    store
        .create_for_input(
            "p1",
            "deploy.production",
            &approved_input,
            1,
            600,
            "reviewed exact deployment",
            &sk,
            false,
        )
        .unwrap();
    store
        .conn
        .execute(
            "UPDATE pictos SET input_hash = ?1 WHERE id = 'p1'",
            params![tampered_input],
        )
        .unwrap();

    assert!(matches!(
        store
            .find_verified_match_for_input(
                "deploy.production",
                &input_hash('b'),
                OffsetDateTime::now_utc(),
                &sk.verifying_key(),
            )
            .unwrap(),
        PictoLookup::BadSignature { .. }
    ));
}

#[test]
fn input_binding_cannot_be_reinterpreted_as_scope_only_reason_text() {
    let store = PictoStore::open_in_memory().unwrap();
    let sk = key();
    let approved_input = input_hash('a');
    let reason = "reviewed exact deployment";
    let original = store
        .create_for_input(
            "p1",
            "deploy.production",
            &approved_input,
            1,
            600,
            reason,
            &sk,
            false,
        )
        .unwrap();
    let signed_input_bound_payload =
        original.signing_payload_for_input_hash_unchecked(Some(&approved_input));

    // Under the legacy newline-delimited encoding, moving the input hash
    // into `reason` produced the exact same signed bytes while changing an
    // input-bound grant into a scope-only grant.
    let smuggled_reason = format!("{reason}\ninput_hash={approved_input}");
    store
        .conn
        .execute(
            "UPDATE pictos SET reason = ?1, input_hash = NULL WHERE id = 'p1'",
            params![smuggled_reason],
        )
        .unwrap();
    let reinterpreted = store
            .conn
            .query_row(
                r#"SELECT id, scope, max_uses, uses, ttl_expires_at, created_at, status, reason, signature_b64, input_hash
                   FROM pictos WHERE id = 'p1'"#,
                [],
                row_to_picto,
            )
            .unwrap();
    assert_eq!(reinterpreted.binding, PictoBinding::ScopeOnly);
    assert_eq!(
        signed_input_bound_payload,
        reinterpreted.signing_payload_for_input_hash_unchecked(None)
    );

    assert!(matches!(
        store
            .find_verified_match(
                "deploy.production",
                OffsetDateTime::now_utc(),
                &sk.verifying_key(),
            )
            .unwrap(),
        PictoLookup::BadSignature { .. }
    ));
    assert!(matches!(
        store
            .consume_verified("p1", OffsetDateTime::now_utc(), &sk.verifying_key())
            .unwrap(),
        PictoConsume::BadSignature { .. }
    ));
    assert_eq!(store.get("p1").unwrap().unwrap().uses, 0);
}

#[test]
fn legacy_id_scope_boundary_collision_is_rejected_from_existing_rows() {
    let store = PictoStore::open_in_memory().unwrap();
    let sk = key();
    let created_at = whole_second_now();
    let ttl_expires_at = created_at + time::Duration::seconds(600);
    let mut originally_signed = Picto {
        id: "p1".to_string(),
        scope: "deploy\n1".to_string(),
        max_uses: 2,
        uses: 0,
        ttl_expires_at,
        created_at,
        status: PictoStatus::Active,
        reason: "legacy".to_string(),
        signature_b64: String::new(),
        binding: PictoBinding::ScopeOnly,
    };
    let signed_bytes = originally_signed.signing_payload_for_input_hash_unchecked(None);
    originally_signed.signature_b64 = base64_encode(&sk.sign(&signed_bytes).to_bytes());

    let mut reinterpreted = originally_signed.clone();
    reinterpreted.id = "p1\ndeploy".to_string();
    reinterpreted.scope = "1".to_string();
    assert_eq!(
        signed_bytes,
        reinterpreted.signing_payload_for_input_hash_unchecked(None)
    );

    store
            .conn
            .execute(
                r#"INSERT INTO pictos
                   (id, scope, max_uses, uses, ttl_expires_at, created_at, status, reason, signature_b64, input_hash)
                   VALUES (?1, ?2, ?3, 0, ?4, ?5, 'active', ?6, ?7, NULL)"#,
                params![
                    reinterpreted.id,
                    reinterpreted.scope,
                    reinterpreted.max_uses,
                    reinterpreted.ttl_expires_at.unix_timestamp(),
                    reinterpreted.created_at.unix_timestamp(),
                    reinterpreted.reason,
                    reinterpreted.signature_b64,
                ],
            )
            .unwrap();

    assert!(matches!(
        store
            .find_verified_match("1", OffsetDateTime::now_utc(), &sk.verifying_key(),)
            .unwrap(),
        PictoLookup::BadSignature { .. }
    ));
}

#[test]
fn out_of_range_timestamp_in_existing_row_fails_closed() {
    let store = PictoStore::open_in_memory().unwrap();
    let sk = key();
    store.create("p1", "scope", 1, 60, "r", &sk, false).unwrap();
    store
        .conn
        .execute(
            "UPDATE pictos SET ttl_expires_at = ?1 WHERE id = 'p1'",
            params![i64::MAX],
        )
        .unwrap();

    assert!(
        store
            .find_verified_match("scope", OffsetDateTime::now_utc(), &sk.verifying_key())
            .is_err()
    );
    assert!(
        store
            .consume_verified("p1", OffsetDateTime::now_utc(), &sk.verifying_key())
            .is_err()
    );
}

#[test]
fn scope_only_picto_cannot_satisfy_an_input_bound_lookup() {
    let store = PictoStore::open_in_memory().unwrap();
    let sk = key();
    store
        .create(
            "p1",
            "deploy.production",
            1,
            600,
            "explicit operator grant",
            &sk,
            false,
        )
        .unwrap();

    assert!(matches!(
        store
            .find_verified_match_for_input(
                "deploy.production",
                &input_hash('a'),
                OffsetDateTime::now_utc(),
                &sk.verifying_key(),
            )
            .unwrap(),
        PictoLookup::None
    ));
    assert!(matches!(
        store
            .find_verified_match(
                "deploy.production",
                OffsetDateTime::now_utc(),
                &sk.verifying_key(),
            )
            .unwrap(),
        PictoLookup::Verified { .. }
    ));
}

#[test]
fn opening_a_legacy_store_adds_the_input_hash_column() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("pictos.sqlite");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        r#"
            CREATE TABLE pictos (
                id TEXT PRIMARY KEY,
                scope TEXT NOT NULL,
                max_uses INTEGER NOT NULL,
                uses INTEGER NOT NULL DEFAULT 0,
                ttl_expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                status TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                signature_b64 TEXT NOT NULL
            );
            "#,
    )
    .unwrap();
    drop(conn);

    let store = PictoStore::open(&path).unwrap();
    let mut statement = store.conn.prepare("PRAGMA table_info(pictos)").unwrap();
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(columns.iter().any(|column| column == "input_hash"));
}
