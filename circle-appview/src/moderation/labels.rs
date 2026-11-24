//! Pure folding of Ozone account labels into enforcement events.
//!
//! The operator's Ozone instance is the only authority. When it takes an
//! account down it emits a `!takedown` label (or `!suspend` for a timed
//! takedown) whose `uri` is the account DID, and it negates that label when
//! the takedown is reversed. This module turns one `queryLabels` row into an
//! [`AccountLabelEvent`] or rejects it. It does no I/O, so the same file is
//! shared verbatim by mls-ds and circle-appview.

use chrono::{DateTime, Utc};
use serde::Deserialize;

/// Labels enforced when `MODERATION_ENFORCED_LABELS` is unset.
pub const DEFAULT_ENFORCED_LABELS: &[&str] = &["!takedown", "!suspend"];

/// Upper bound on a DID we accept from a label `uri`.
const MAX_DID_LEN: usize = 2048;

/// `com.atproto.label.queryLabels` output.
#[derive(Debug, Clone, Deserialize)]
pub struct QueryLabelsOutput {
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub labels: Vec<WireLabel>,
}

/// `com.atproto.label.defs#label`, with only the fields enforcement needs.
#[derive(Debug, Clone, Deserialize)]
pub struct WireLabel {
    pub src: String,
    pub uri: String,
    #[serde(default)]
    pub cid: Option<String>,
    pub val: String,
    #[serde(default)]
    pub neg: bool,
    pub cts: String,
    #[serde(default)]
    pub exp: Option<String>,
}

/// Where a reconcile walk starts: every DID begins with this.
pub const RECONCILE_ROOT: &str = "did:";

/// Every character [`is_account_did`] accepts after the method, so splitting a
/// bucket on these covers it exactly. `%` is not among them: Ozone strips it
/// from patterns, so no bucket could narrow onto a percent-encoded DID.
const DID_CHARS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-";

/// One `queryLabels` request in a reconcile walk.
///
/// Ozone pages `queryLabels` without an `ORDER BY`, so following its cursor
/// can skip rows. A request whose page comes back short is complete, so the
/// walk asks for subject prefixes and splits any prefix whose page is full.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelBucket {
    /// Every subject starting with this.
    Prefix(String),
    /// Exactly this subject.
    Exact(String),
}

impl LabelBucket {
    /// The `uriPatterns` value for this bucket.
    pub fn pattern(&self) -> String {
        match self {
            Self::Prefix(prefix) => format!("{prefix}*"),
            Self::Exact(subject) => subject.clone(),
        }
    }

    /// Narrower buckets that together cover this one, or `None` when it
    /// cannot be narrowed further.
    pub fn split(&self) -> Option<Vec<LabelBucket>> {
        match self {
            Self::Exact(_) => None,
            Self::Prefix(prefix) if prefix.len() >= MAX_DID_LEN => None,
            Self::Prefix(prefix) => {
                let mut out = Vec::with_capacity(DID_CHARS.len() + 1);
                out.push(Self::Exact(prefix.clone()));
                out.extend(
                    DID_CHARS
                        .chars()
                        .map(|c| Self::Prefix(format!("{prefix}{c}"))),
                );
                Some(out)
            }
        }
    }
}

/// One account-level label state change from the trusted labeler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountLabelEvent {
    pub src: String,
    pub did: String,
    pub val: String,
    pub cts: DateTime<Utc>,
    pub exp: Option<DateTime<Utc>>,
    /// `true` when the labeler withdrew the label (takedown reversed).
    pub neg: bool,
}

/// Why a label row was not turned into an event. Only for logs and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelSkip {
    UntrustedSource,
    NotAnAccount,
    NotEnforced,
    BadTimestamp,
}

/// Parse `MODERATION_ENFORCED_LABELS`-style input: comma-separated values,
/// whitespace trimmed, empties dropped. `None` or an all-empty list gives the
/// defaults, so a typo can never switch enforcement off.
pub fn parse_enforced_labels(raw: Option<&str>) -> Vec<String> {
    let parsed: Vec<String> = raw
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .collect();
    if parsed.is_empty() {
        DEFAULT_ENFORCED_LABELS
            .iter()
            .map(|v| (*v).to_owned())
            .collect()
    } else {
        parsed
    }
}

/// A bare account DID (`did:plc:…` or `did:web:…`), not a record URI and not
/// a DID URL with a fragment or path.
///
/// A percent-encoded `did:web` (a host with a port, like
/// `did:web:localhost%3A2583`) is not an account here. atproto only allows
/// ports on localhost for development, and the reconcile walk cannot reach
/// such a DID, so enforcing it would be silently partial.
pub fn is_account_did(uri: &str) -> bool {
    if uri.len() > MAX_DID_LEN {
        return false;
    }
    let rest = match uri
        .strip_prefix("did:plc:")
        .or_else(|| uri.strip_prefix("did:web:"))
    {
        Some(rest) => rest,
        None => return false,
    };
    !rest.is_empty()
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
        && !rest.ends_with(':')
}

fn parse_ts(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// Turn one wire label into an enforcement event, or say why not.
pub fn account_label_event(
    label: &WireLabel,
    trusted_src: &str,
    enforced: &[String],
) -> Result<AccountLabelEvent, LabelSkip> {
    if label.src != trusted_src {
        return Err(LabelSkip::UntrustedSource);
    }
    if label.cid.is_some() || !is_account_did(&label.uri) {
        return Err(LabelSkip::NotAnAccount);
    }
    if !enforced.iter().any(|v| v == &label.val) {
        return Err(LabelSkip::NotEnforced);
    }
    let cts = parse_ts(&label.cts).ok_or(LabelSkip::BadTimestamp)?;
    let exp = match label.exp.as_deref() {
        None => None,
        Some(raw) => Some(parse_ts(raw).ok_or(LabelSkip::BadTimestamp)?),
    };
    Ok(AccountLabelEvent {
        src: label.src.clone(),
        did: label.uri.clone(),
        val: label.val.clone(),
        cts,
        exp,
        neg: label.neg,
    })
}

/// Whether a stored (latest) label state restricts the account at `now`.
pub fn restricts(neg: bool, exp: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    !neg && exp.map_or(true, |exp| exp > now)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OZONE: &str = "did:plc:ozonecatbird";

    fn label(uri: &str, val: &str) -> WireLabel {
        WireLabel {
            src: OZONE.into(),
            uri: uri.into(),
            cid: None,
            val: val.into(),
            neg: false,
            cts: "2026-11-24T12:00:00.000Z".into(),
            exp: None,
        }
    }

    fn enforced() -> Vec<String> {
        parse_enforced_labels(None)
    }

    #[test]
    fn takedown_on_account_is_enforced() {
        let ev = account_label_event(&label("did:plc:abc123", "!takedown"), OZONE, &enforced())
            .expect("event");
        assert_eq!(ev.did, "did:plc:abc123");
        assert!(!ev.neg);
        assert!(restricts(ev.neg, ev.exp, ev.cts));
    }

    #[test]
    fn negation_lifts_restriction() {
        let mut l = label("did:plc:abc123", "!takedown");
        l.neg = true;
        let ev = account_label_event(&l, OZONE, &enforced()).expect("event");
        assert!(ev.neg);
        assert!(!restricts(ev.neg, ev.exp, ev.cts));
    }

    #[test]
    fn expired_suspension_no_longer_restricts() {
        let mut l = label("did:web:spam.example.com", "!suspend");
        l.exp = Some("2026-11-25T12:00:00Z".into());
        let ev = account_label_event(&l, OZONE, &enforced()).expect("event");
        let before = parse_ts("2026-11-25T11:59:59Z").unwrap();
        let after = parse_ts("2026-11-25T12:00:01Z").unwrap();
        assert!(restricts(ev.neg, ev.exp, before));
        assert!(!restricts(ev.neg, ev.exp, after));
    }

    #[test]
    fn other_sources_are_ignored() {
        let mut l = label("did:plc:abc123", "!takedown");
        l.src = "did:plc:ar7c4by46qjdydhdevvrndac".into();
        assert_eq!(
            account_label_event(&l, OZONE, &enforced()),
            Err(LabelSkip::UntrustedSource)
        );
    }

    #[test]
    fn record_labels_are_not_account_bans() {
        let l = label("at://did:plc:abc123/app.bsky.feed.post/3k", "!takedown");
        assert_eq!(
            account_label_event(&l, OZONE, &enforced()),
            Err(LabelSkip::NotAnAccount)
        );
        let mut with_cid = label("did:plc:abc123", "!takedown");
        with_cid.cid = Some("bafy".into());
        assert_eq!(
            account_label_event(&with_cid, OZONE, &enforced()),
            Err(LabelSkip::NotAnAccount)
        );
        assert!(!is_account_did("did:plc:abc#atproto"));
        assert!(!is_account_did("did:key:z6Mk"));
        assert!(!is_account_did("did:plc:"));
        assert!(!is_account_did("did:web:localhost%3A2583"));
    }

    #[test]
    fn bucket_splits_reach_every_account_did() {
        // Each byte an account DID may hold after `did:` has its own child
        // bucket, so a full bucket's children always cover it.
        for b in 0u8..=127 {
            let c = b as char;
            let did = format!("did:web:a{c}b");
            if is_account_did(&did) {
                assert!(DID_CHARS.contains(c), "{c:?} is accepted but never walked");
            }
        }
        let plc = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
        assert!(is_account_did(plc));
        assert!(plc[RECONCILE_ROOT.len()..]
            .chars()
            .all(|c| DID_CHARS.contains(c)));
    }

    #[test]
    fn non_enforced_values_are_ignored() {
        assert_eq!(
            account_label_event(&label("did:plc:abc123", "spam"), OZONE, &enforced()),
            Err(LabelSkip::NotEnforced)
        );
    }

    #[test]
    fn bad_timestamps_are_rejected() {
        let mut l = label("did:plc:abc123", "!takedown");
        l.cts = "yesterday".into();
        assert_eq!(
            account_label_event(&l, OZONE, &enforced()),
            Err(LabelSkip::BadTimestamp)
        );
    }

    #[test]
    fn enforced_list_parsing_never_goes_empty() {
        assert_eq!(parse_enforced_labels(Some(" , ")), enforced());
        assert_eq!(
            parse_enforced_labels(Some("!takedown, catbird-chat-ban")),
            vec!["!takedown".to_owned(), "catbird-chat-ban".to_owned()]
        );
    }

    #[test]
    fn query_labels_output_parses() {
        let raw = r#"{"cursor":"42","labels":[{"ver":1,"src":"did:plc:ozonecatbird",
            "uri":"did:plc:abc123","val":"!takedown","cts":"2026-11-24T12:00:00.000Z",
            "sig":{"$bytes":"AAAA"}}]}"#;
        let out: QueryLabelsOutput = serde_json::from_str(raw).expect("parse");
        assert_eq!(out.cursor.as_deref(), Some("42"));
        assert_eq!(out.labels.len(), 1);
        assert!(!out.labels[0].neg);
    }

    #[test]
    fn bucket_patterns() {
        assert_eq!(LabelBucket::Prefix("did:".into()).pattern(), "did:*");
        assert_eq!(
            LabelBucket::Exact("did:plc:abc".into()).pattern(),
            "did:plc:abc"
        );
    }

    #[test]
    fn splitting_a_bucket_covers_it_exactly() {
        let parts = LabelBucket::Prefix("did:plc:ab".into())
            .split()
            .expect("prefix splits");
        assert_eq!(parts[0], LabelBucket::Exact("did:plc:ab".into()));
        // Every DID under the prefix lands in exactly one part.
        for did in [
            "did:plc:ab",
            "did:plc:abz7",
            "did:plc:abQ",
            "did:plc:ab.x",
            "did:plc:ab-_",
        ] {
            let hits = parts
                .iter()
                .filter(|part| match part {
                    LabelBucket::Exact(subject) => did == subject.as_str(),
                    LabelBucket::Prefix(prefix) => did.starts_with(prefix.as_str()),
                })
                .count();
            assert_eq!(hits, 1, "{did}");
        }
        assert!(LabelBucket::Exact("did:plc:ab".into()).split().is_none());
        assert!(LabelBucket::Prefix("d".repeat(MAX_DID_LEN))
            .split()
            .is_none());
    }
}
