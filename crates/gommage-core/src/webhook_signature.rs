use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const SIGNATURE_HEADER: &str = "x-gommage-signature";
const TIMESTAMP_HEADER: &str = "x-gommage-signature-timestamp";
const ALGORITHM_HEADER: &str = "x-gommage-signature-algorithm";
const KEY_ID_HEADER: &str = "x-gommage-signature-key-id";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookSignatureReport {
    pub algorithm: String,
    pub timestamp: String,
    pub body_sha256: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    pub headers: Vec<WebhookSignatureHeader>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookSignatureHeader {
    pub name: String,
    pub value: String,
}

impl WebhookSignatureReport {
    pub fn curl_headers(&self) -> Vec<String> {
        self.headers
            .iter()
            .map(|header| format!("{}: {}", header.name, header.value))
            .collect()
    }
}

pub fn sign_webhook_body(
    body: &[u8],
    secret: &str,
    key_id: Option<&str>,
) -> WebhookSignatureReport {
    sign_webhook_body_at(body, secret, key_id, OffsetDateTime::now_utc())
}

fn sign_webhook_body_at(
    body: &[u8],
    secret: &str,
    key_id: Option<&str>,
    timestamp: OffsetDateTime,
) -> WebhookSignatureReport {
    let timestamp = timestamp
        .format(&Rfc3339)
        .unwrap_or_else(|_| timestamp.to_string());
    let body_sha256 = hex::encode(Sha256::digest(body));
    let mut signed = Vec::with_capacity(timestamp.len() + 1 + body.len());
    signed.extend_from_slice(timestamp.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(body);
    let signature = format!(
        "v1={}",
        hex::encode(hmac_sha256(secret.as_bytes(), &signed))
    );
    let mut headers = vec![
        WebhookSignatureHeader {
            name: ALGORITHM_HEADER.to_string(),
            value: "hmac-sha256".to_string(),
        },
        WebhookSignatureHeader {
            name: TIMESTAMP_HEADER.to_string(),
            value: timestamp.clone(),
        },
        WebhookSignatureHeader {
            name: SIGNATURE_HEADER.to_string(),
            value: signature.clone(),
        },
    ];
    if let Some(key_id) = key_id.filter(|value| !value.trim().is_empty()) {
        headers.push(WebhookSignatureHeader {
            name: KEY_ID_HEADER.to_string(),
            value: key_id.to_string(),
        });
    }
    WebhookSignatureReport {
        algorithm: "hmac-sha256".to_string(),
        timestamp,
        body_sha256,
        signature,
        key_id: key_id.map(str::to_string),
        headers,
    }
}

fn hmac_sha256(secret: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key = [0u8; BLOCK];
    if secret.len() > BLOCK {
        key[..32].copy_from_slice(&Sha256::digest(secret));
    } else {
        key[..secret.len()].copy_from_slice(secret);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for (idx, byte) in key.iter().enumerate() {
        ipad[idx] ^= byte;
        opad[idx] ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn hmac_matches_rfc_4231_test_vector() {
        let actual = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            hex::encode(actual),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn signature_changes_when_body_changes() {
        let timestamp = datetime!(2026-04-23 09:00 UTC);
        let original =
            sign_webhook_body_at(br#"{"id":"apr_1"}"#, "secret", Some("prod"), timestamp);
        let tampered =
            sign_webhook_body_at(br#"{"id":"apr_2"}"#, "secret", Some("prod"), timestamp);
        assert_ne!(original.signature, tampered.signature);
        assert_eq!(original.key_id.as_deref(), Some("prod"));
        assert!(
            original
                .headers
                .iter()
                .any(|header| header.name == SIGNATURE_HEADER)
        );
    }
}
