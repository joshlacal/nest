//! Sealed chat wake envelope, version 2.
//!
//! A chat wake travels through Apple or Google, who are outside our trust
//! boundary. Version 1 put the conversation id, generation, seq, epoch, wake
//! kind and an unsalted hash of the account DID in the payload in clear, and
//! the presence or absence of the inline ciphertext revealed a size bit. This
//! module replaces that with one opaque, constant-size blob.
//!
//! The key is derived from the device's `pushKey`: a 256-bit secret the gateway
//! issued to the device at `registerKey`, which the device handed to its
//! delivery service and which arrives with every `deliver` call. The device,
//! the delivery service and the gateway therefore all hold it, and the push
//! provider never does. Deriving from it needs no extra registration step and
//! no lexicon change. It gives no forward secrecy: a party that later obtains
//! the `pushKey` can open recorded wakes. Every such party already sees the
//! same wake metadata by other means, so nothing new is exposed.
//!
//! ```text
//! ikm      = ASCII bytes of pushKey, exactly as issued (base64url, no padding)
//! prk      = HKDF-SHA256-Extract(salt = "catbird-push-wake-v2", ikm)
//! key      = HKDF-Expand(prk, "key", 32)                 AES-256-GCM key
//! kid      = lowercase hex of HKDF-Expand(prk, "kid", 8) routing tag
//! collapse = lowercase hex of HKDF-Expand(prk,
//!              "collapse|" + conversationId + "|" + YYYY-MM-DD (UTC), 16)
//!
//! header   = compact JSON { wakeKind, conversationId, generation, seq, epoch,
//!                           fetchRequired }
//! plain    = u16be(len(header)) || header || u16be(len(ct)) || ct || 0x00...
//!            zero-padded to exactly WAKE_PLAINTEXT_LEN bytes
//! aad      = "catbird-push-wake-v2|" + kid + "|" + appId
//! nonce    = 12 random bytes
//! sealed   = base64url-nopad( nonce || AES-256-GCM(key, nonce, plain, aad) )
//!
//! payload  = { "v": 2, "kid": kid, "sealed": sealed }
//! ```
//!
//! `kid` lets a device that holds several push keys (one per signed-in
//! account) pick the right one without trial decryption. It is stable per
//! registration, which tells the provider nothing it does not already know
//! from the device token. `collapse` keeps the provider's "replace the older
//! undelivered wake for the same conversation" behaviour, but changes every UTC
//! day so the provider cannot follow one conversation across days.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload as AeadPayload},
    Aes256Gcm,
};
use anyhow::{anyhow, bail, ensure, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine as _};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;

/// Envelope version carried as `v` in the provider-visible payload.
pub const WAKE_ENVELOPE_VERSION: u64 = 2;

/// Every sealed wake plaintext is padded to exactly this many bytes, so a wake
/// that inlines a ciphertext is indistinguishable in size from one that does
/// not. 2 + header (under 300) + 2 + 2200 fits with room to spare, and the
/// resulting APNs/FCM payload stays under the 4096-byte provider limit.
pub const WAKE_PLAINTEXT_LEN: usize = 2560;

/// Largest inline ciphertext the envelope accepts. Mirrors the gateway's own
/// `MAX_INLINE_CIPHERTEXT_BYTES`.
pub const WAKE_MAX_INLINE_CIPHERTEXT: usize = 2200;

const HKDF_SALT: &[u8] = b"catbird-push-wake-v2";
const AAD_PREFIX: &str = "catbird-push-wake-v2|";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

type HmacSha256 = Hmac<Sha256>;

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// RFC 5869 HKDF-SHA256 extract.
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, &[ikm])
}

/// RFC 5869 HKDF-SHA256 expand.
fn hkdf_expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) {
    assert!(out.len() <= 255 * 32, "HKDF output too long");
    let mut previous: Vec<u8> = Vec::new();
    let mut written = 0usize;
    let mut counter = 1u8;
    while written < out.len() {
        let block = hmac_sha256(prk, &[&previous, info, &[counter]]);
        let take = (out.len() - written).min(block.len());
        out[written..written + take].copy_from_slice(&block[..take]);
        written += take;
        previous = block.to_vec();
        counter = counter.wrapping_add(1);
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The key material one `pushKey` yields.
pub struct WakeKeys {
    prk: [u8; 32],
    key: [u8; 32],
    kid: String,
}

impl WakeKeys {
    /// Derive from the `pushKey` string exactly as the gateway issued it.
    pub fn derive(push_key: &str) -> Self {
        let prk = hkdf_extract(HKDF_SALT, push_key.as_bytes());
        let mut key = [0u8; 32];
        hkdf_expand(&prk, b"key", &mut key);
        let mut kid = [0u8; 8];
        hkdf_expand(&prk, b"kid", &mut kid);
        Self {
            prk,
            key,
            kid: hex_lower(&kid),
        }
    }

    /// Provider-visible routing tag: 16 lowercase hex characters.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Provider-visible collapse identifier: 32 lowercase hex characters, stable
    /// for one conversation on one device for one UTC day (`utc_day` is
    /// `YYYY-MM-DD`).
    pub fn collapse_id(&self, conversation_id: &str, utc_day: &str) -> String {
        let info = format!("collapse|{conversation_id}|{utc_day}");
        let mut out = [0u8; 16];
        hkdf_expand(&self.prk, info.as_bytes(), &mut out);
        hex_lower(&out)
    }
}

/// What the device needs to act on a wake. Field names match the version 1
/// clear payload so client code downstream of the unseal step does not change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WakeHeader {
    pub wake_kind: String,
    pub conversation_id: String,
    pub generation: i64,
    pub seq: i64,
    pub epoch: i64,
    pub fetch_required: bool,
}

/// An opened wake: the header plus the inline MLS ciphertext, if one was sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedWake {
    pub header: WakeHeader,
    pub ciphertext: Option<Vec<u8>>,
}

fn aad(kid: &str, app_id: &str) -> Vec<u8> {
    format!("{AAD_PREFIX}{kid}|{app_id}").into_bytes()
}

fn encode_plaintext(header: &WakeHeader, ciphertext: Option<&[u8]>) -> Result<Vec<u8>> {
    let header_bytes = serde_json::to_vec(header)?;
    let ciphertext = ciphertext.unwrap_or_default();
    ensure!(
        ciphertext.len() <= WAKE_MAX_INLINE_CIPHERTEXT,
        "inline ciphertext exceeds the wake envelope limit"
    );
    ensure!(
        header.fetch_required == ciphertext.is_empty(),
        "fetchRequired must be true exactly when no ciphertext is inlined"
    );
    let needed = 2 + header_bytes.len() + 2 + ciphertext.len();
    ensure!(
        needed <= WAKE_PLAINTEXT_LEN,
        "wake header and ciphertext do not fit the fixed envelope"
    );
    let mut plain = Vec::with_capacity(WAKE_PLAINTEXT_LEN);
    plain.extend_from_slice(&u16::try_from(header_bytes.len())?.to_be_bytes());
    plain.extend_from_slice(&header_bytes);
    plain.extend_from_slice(&u16::try_from(ciphertext.len())?.to_be_bytes());
    plain.extend_from_slice(ciphertext);
    plain.resize(WAKE_PLAINTEXT_LEN, 0);
    Ok(plain)
}

fn decode_plaintext(plain: &[u8]) -> Result<OpenedWake> {
    ensure!(
        plain.len() == WAKE_PLAINTEXT_LEN,
        "wake plaintext has the wrong length"
    );
    let header_len = usize::from(u16::from_be_bytes([plain[0], plain[1]]));
    let header_end = 2 + header_len;
    ensure!(header_end + 2 <= plain.len(), "wake header overruns");
    let header: WakeHeader = serde_json::from_slice(&plain[2..header_end])?;
    let ct_len = usize::from(u16::from_be_bytes([
        plain[header_end],
        plain[header_end + 1],
    ]));
    let ct_start = header_end + 2;
    let ct_end = ct_start + ct_len;
    ensure!(
        ct_len <= WAKE_MAX_INLINE_CIPHERTEXT && ct_end <= plain.len(),
        "wake ciphertext overruns"
    );
    ensure!(
        plain[ct_end..].iter().all(|byte| *byte == 0),
        "wake padding is not all zero"
    );
    ensure!(
        header.fetch_required == (ct_len == 0),
        "fetchRequired disagrees with the inline ciphertext"
    );
    Ok(OpenedWake {
        header,
        ciphertext: (ct_len > 0).then(|| plain[ct_start..ct_end].to_vec()),
    })
}

fn seal_with_nonce(
    keys: &WakeKeys,
    app_id: &str,
    header: &WakeHeader,
    ciphertext: Option<&[u8]>,
    nonce: [u8; NONCE_LEN],
) -> Result<Value> {
    let plain = encode_plaintext(header, ciphertext)?;
    let cipher = Aes256Gcm::new_from_slice(&keys.key).map_err(|_| anyhow!("bad wake key"))?;
    let sealed = cipher
        .encrypt(
            (&nonce).into(),
            AeadPayload {
                msg: &plain,
                aad: &aad(keys.kid(), app_id),
            },
        )
        .map_err(|_| anyhow!("failed to seal wake envelope"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + sealed.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(json!({
        "v": WAKE_ENVELOPE_VERSION,
        "kid": keys.kid(),
        "sealed": BASE64URL.encode(out),
    }))
}

/// Seal one wake. Returns the provider-visible `catbird` object:
/// `{ "v": 2, "kid": ..., "sealed": ... }`.
pub fn seal(
    keys: &WakeKeys,
    app_id: &str,
    header: &WakeHeader,
    ciphertext: Option<&[u8]>,
) -> Result<Value> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    seal_with_nonce(keys, app_id, header, ciphertext, nonce)
}

/// Open a sealed wake. This is the reference for what a client does; the
/// gateway itself only uses it in tests.
pub fn open(keys: &WakeKeys, app_id: &str, catbird: &Value) -> Result<OpenedWake> {
    let object = catbird
        .as_object()
        .ok_or_else(|| anyhow!("wake payload is not an object"))?;
    ensure!(
        object.len() == 3,
        "wake payload must hold exactly v, kid and sealed"
    );
    ensure!(
        object.get("v").and_then(Value::as_u64) == Some(WAKE_ENVELOPE_VERSION),
        "unsupported wake envelope version"
    );
    let Some(kid) = object.get("kid").and_then(Value::as_str) else {
        bail!("wake payload has no kid");
    };
    ensure!(kid == keys.kid(), "wake is addressed to a different key");
    let Some(sealed) = object.get("sealed").and_then(Value::as_str) else {
        bail!("wake payload has no sealed field");
    };
    let raw = BASE64URL.decode(sealed)?;
    ensure!(
        raw.len() == NONCE_LEN + WAKE_PLAINTEXT_LEN + TAG_LEN,
        "sealed wake has the wrong length"
    );
    let (nonce, body) = raw.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into()?;
    let cipher = Aes256Gcm::new_from_slice(&keys.key).map_err(|_| anyhow!("bad wake key"))?;
    let plain = cipher
        .decrypt(
            (&nonce).into(),
            AeadPayload {
                msg: body,
                aad: &aad(kid, app_id),
            },
        )
        .map_err(|_| anyhow!("wake envelope failed authentication"))?;
    decode_plaintext(&plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUSH_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    const APP_ID: &str = "blue.catbird";

    fn header(fetch_required: bool) -> WakeHeader {
        WakeHeader {
            wake_kind: "applicationMessage".into(),
            conversation_id: "3f0e6f0a-6f0b-4c5e-9d55-0a4e4f6c2b11".into(),
            generation: 0,
            seq: 7,
            epoch: 3,
            fetch_required,
        }
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 5869 appendix A.1, so the hand-written HKDF is known to be HKDF.
    #[test]
    fn hkdf_matches_rfc_5869_test_case_1() {
        let ikm = [0x0b_u8; 22];
        let salt = unhex("000102030405060708090a0b0c");
        let info = unhex("f0f1f2f3f4f5f6f7f8f9");
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            hex_lower(&prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        let mut okm = [0u8; 42];
        hkdf_expand(&prk, &info, &mut okm);
        assert_eq!(
            hex_lower(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn round_trips_with_and_without_inline_ciphertext() {
        let keys = WakeKeys::derive(PUSH_KEY);
        let ct = vec![0xA5_u8; 1800];

        let inline = seal(&keys, APP_ID, &header(false), Some(&ct)).unwrap();
        let opened = open(&keys, APP_ID, &inline).unwrap();
        assert_eq!(opened.header, header(false));
        assert_eq!(opened.ciphertext.as_deref(), Some(ct.as_slice()));

        let fetch = seal(&keys, APP_ID, &header(true), None).unwrap();
        let opened = open(&keys, APP_ID, &fetch).unwrap();
        assert_eq!(opened.header, header(true));
        assert_eq!(opened.ciphertext, None);
    }

    /// The property the envelope exists for: the provider cannot tell an inline
    /// wake from a fetch wake, or a short ciphertext from a long one, by size.
    #[test]
    fn every_wake_is_the_same_size_and_under_the_provider_limit() {
        let keys = WakeKeys::derive(PUSH_KEY);
        let mut lengths = std::collections::BTreeSet::new();
        for ct_len in [0usize, 1, 64, 1024, WAKE_MAX_INLINE_CIPHERTEXT] {
            let ct = vec![7u8; ct_len];
            let sealed = seal(
                &keys,
                APP_ID,
                &header(ct_len == 0),
                (ct_len > 0).then_some(ct.as_slice()),
            )
            .unwrap();
            let apns = json!({
                "aps": { "alert": { "body": "New message" }, "mutable-content": 1 },
                "catbird": sealed,
            });
            lengths.insert(serde_json::to_vec(&apns).unwrap().len());
        }
        assert_eq!(lengths.len(), 1, "wake sizes differ: {lengths:?}");
        assert!(*lengths.first().unwrap() <= 4096, "{lengths:?}");
    }

    #[test]
    fn provider_visible_payload_holds_no_identifiers() {
        let keys = WakeKeys::derive(PUSH_KEY);
        let sealed = seal(&keys, APP_ID, &header(true), None).unwrap();
        let text = serde_json::to_string(&sealed).unwrap();
        let mut fields: Vec<&str> = sealed
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort_unstable();
        assert_eq!(fields, ["kid", "sealed", "v"]);
        for needle in [
            "3f0e6f0a",
            "conversationId",
            "applicationMessage",
            "wakeKind",
            "recipientAccountHash",
            "seq",
            "epoch",
        ] {
            assert!(!text.contains(needle), "payload leaks {needle}");
        }
    }

    #[test]
    fn rejects_wrong_key_wrong_app_tampering_and_extra_fields() {
        let keys = WakeKeys::derive(PUSH_KEY);
        let sealed = seal(&keys, APP_ID, &header(true), None).unwrap();

        let other = WakeKeys::derive("some-other-push-key");
        assert!(open(&other, APP_ID, &sealed).is_err());
        assert!(open(&keys, "blue.catbird.other", &sealed).is_err());

        let mut tampered = sealed.clone();
        let blob = tampered["sealed"].as_str().unwrap().to_owned();
        let flipped = if blob.ends_with('A') { "B" } else { "A" };
        tampered["sealed"] = json!(format!("{}{flipped}", &blob[..blob.len() - 1]));
        assert!(open(&keys, APP_ID, &tampered).is_err());

        let mut extra = sealed.clone();
        extra["conversationId"] = json!("x");
        assert!(open(&keys, APP_ID, &extra).is_err());

        let mut wrong_version = sealed;
        wrong_version["v"] = json!(1);
        assert!(open(&keys, APP_ID, &wrong_version).is_err());
    }

    #[test]
    fn rejects_inconsistent_or_oversized_input() {
        let keys = WakeKeys::derive(PUSH_KEY);
        assert!(seal(&keys, APP_ID, &header(true), Some(&[1, 2, 3])).is_err());
        assert!(seal(&keys, APP_ID, &header(false), None).is_err());
        let too_big = vec![0u8; WAKE_MAX_INLINE_CIPHERTEXT + 1];
        assert!(seal(&keys, APP_ID, &header(false), Some(&too_big)).is_err());
    }

    #[test]
    fn collapse_id_is_per_conversation_and_rotates_daily() {
        let keys = WakeKeys::derive(PUSH_KEY);
        let a = keys.collapse_id("conv-a", "2026-11-09");
        assert_eq!(a.len(), 32);
        assert_eq!(a, keys.collapse_id("conv-a", "2026-11-09"));
        assert_ne!(a, keys.collapse_id("conv-b", "2026-11-09"));
        assert_ne!(a, keys.collapse_id("conv-a", "2026-11-10"));
        assert_ne!(
            a,
            WakeKeys::derive("some-other-push-key").collapse_id("conv-a", "2026-11-09")
        );
    }

    /// Fixed vector for client implementations (Swift CryptoKit, Android
    /// javax.crypto). Regenerate only with a version bump.
    #[test]
    fn known_answer_vector() {
        let keys = WakeKeys::derive(PUSH_KEY);
        let sealed = seal_with_nonce(
            &keys,
            APP_ID,
            &header(false),
            Some(&[0xDE, 0xAD, 0xBE, 0xEF]),
            [0x11; NONCE_LEN],
        )
        .unwrap();
        let blob = sealed["sealed"].as_str().unwrap();
        let digest = {
            use sha2::Digest as _;
            hex_lower(&Sha256::digest(blob.as_bytes()))
        };
        let opened = open(&keys, APP_ID, &sealed).unwrap();
        assert_eq!(
            opened.ciphertext.as_deref(),
            Some(&[0xDE, 0xAD, 0xBE, 0xEF][..])
        );
        assert_eq!(keys.kid(), EXPECTED_KID);
        assert_eq!(hex_lower(&keys.key), EXPECTED_KEY);
        assert_eq!(
            keys.collapse_id("3f0e6f0a-6f0b-4c5e-9d55-0a4e4f6c2b11", "2026-11-09"),
            EXPECTED_COLLAPSE
        );
        assert_eq!(digest, EXPECTED_SEALED_SHA256);
    }

    const EXPECTED_KID: &str = "147038276a8a4cab";
    const EXPECTED_KEY: &str = "2cabdf528c8de4de63eb1450b059454b100d32b8d27bc6ec72c7913435c37bba";
    const EXPECTED_COLLAPSE: &str = "23d1acfa1b101bb52c972bcc4a616261";
    const EXPECTED_SEALED_SHA256: &str =
        "9064f0f4ba65680f4e952537d3fefae8df1eb17814affa3446dbc988d9d96e3b";
}
