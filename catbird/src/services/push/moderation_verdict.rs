use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde_json::Value;
use sqlx::{Pool, Postgres, Row};
use time::{Duration, OffsetDateTime};

use crate::config::AppState;

/// Per-actor moderation state as reported by the appview's viewer state.
///
/// `#[serde(default)]` is load-bearing, not decoration: these values are cached
/// as JSONB, so without it adding a field would make every pre-existing cached
/// row fail to deserialize at once, deferring every notification until the 24h
/// staleness guard dropped it. A schema change must not be able to cause an
/// outage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(default)]
pub struct ModerationVerdict {
    pub muted: bool,
    pub muted_by_list: bool,
    pub blocking: bool,
    pub blocked_by: bool,
    pub blocking_by_list: bool,
    pub muted_only_reposts: bool,
    pub muted_only_quoteposts: bool,
}

impl ModerationVerdict {
    /// Parse `app.bsky.actor.defs#viewerState`.
    /// Requires that `viewer` is present and is a JSON Object. Fails closed (returns Err) on non-object / missing viewer.
    /// Absent optional booleans in valid object default to false.
    /// `mutedByList`/`blockingByList` are OBJECTS in the lexicon (listViewBasic):
    /// presence of the object means true, absence means false.
    pub fn try_from_viewer_json(viewer: Option<&serde_json::Value>) -> Result<Self> {
        let Some(viewer_val) = viewer else {
            return Err(anyhow!("viewerState is missing"));
        };
        let Some(viewer) = viewer_val.as_object() else {
            return Err(anyhow!("viewerState is not a JSON object"));
        };

        let mut muted = false;
        if let Some(val) = viewer.get("muted") {
            match val {
                Value::Bool(b) => muted = *b,
                _ => {
                    return Err(anyhow!(
                        "viewerState.muted must be a boolean, got {:?}",
                        val
                    ))
                }
            }
        }

        let mut muted_by_list = false;
        if let Some(val) = viewer.get("mutedByList") {
            match val {
                Value::Object(_) => muted_by_list = true,
                _ => {
                    return Err(anyhow!(
                        "viewerState.mutedByList must be an object, got {:?}",
                        val
                    ))
                }
            }
        }

        let mut blocking = false;
        if let Some(val) = viewer.get("blocking") {
            match val {
                Value::String(s) => {
                    if s.trim().is_empty() {
                        return Err(anyhow!("viewerState.blocking must not be an empty string"));
                    }
                    blocking = true;
                }
                _ => {
                    return Err(anyhow!(
                        "viewerState.blocking must be a non-empty string, got {:?}",
                        val
                    ))
                }
            }
        }

        let mut blocked_by = false;
        if let Some(val) = viewer.get("blockedBy") {
            match val {
                Value::Bool(b) => blocked_by = *b,
                _ => {
                    return Err(anyhow!(
                        "viewerState.blockedBy must be a boolean, got {:?}",
                        val
                    ))
                }
            }
        }

        let mut blocking_by_list = false;
        if let Some(val) = viewer.get("blockingByList") {
            match val {
                Value::Object(_) => blocking_by_list = true,
                _ => {
                    return Err(anyhow!(
                        "viewerState.blockingByList must be an object, got {:?}",
                        val
                    ))
                }
            }
        }

        let mut muted_only_reposts = false;
        if let Some(val) = viewer.get("mutedOnlyReposts") {
            match val {
                Value::Bool(b) => muted_only_reposts = *b,
                _ => {
                    return Err(anyhow!(
                        "viewerState.mutedOnlyReposts must be a boolean, got {:?}",
                        val
                    ))
                }
            }
        }

        let mut muted_only_quoteposts = false;
        if let Some(val) = viewer.get("mutedOnlyQuoteposts") {
            match val {
                Value::Bool(b) => muted_only_quoteposts = *b,
                _ => {
                    return Err(anyhow!(
                        "viewerState.mutedOnlyQuoteposts must be a boolean, got {:?}",
                        val
                    ))
                }
            }
        }
        Ok(Self {
            muted,
            muted_by_list,
            blocking,
            blocked_by,
            blocking_by_list,
            muted_only_reposts,
            muted_only_quoteposts,
        })
    }

    /// Parse `app.bsky.actor.defs#viewerState`. Defaults to `Self::default()` when missing or malformed.
    pub fn from_viewer_json(viewer: Option<&serde_json::Value>) -> Self {
        Self::try_from_viewer_json(viewer).unwrap_or_default()
    }
    /// True when NO push may be delivered for this actor.
    /// muted || muted_by_list || blocking || blocked_by || blocking_by_list.
    /// NOTE: muted_only_reposts / muted_only_quoteposts are NOT blanket suppression;
    /// they are consulted per notification_type by the caller.
    pub fn suppresses_all(&self) -> bool {
        self.muted
            || self.muted_by_list
            || self.blocking
            || self.blocked_by
            || self.blocking_by_list
    }

    /// True when this verdict suppresses the given push `notification_type`.
    ///
    /// Wraps `suppresses_all()`, then applies the scoped mutes. `mutedOnly*`
    /// mutes never appeared in `getMutes` ("Mutes scoped to specific kinds of
    /// content ... are not included"), so the mirror could not honour them at
    /// all and delivered these regardless — this is new suppression, not a
    /// port. `via_repost` counts as a repost notification: it is the same actor
    /// reposting, just surfaced through another repost, so a repost-scoped mute
    /// covers it. There is no `via_quote` type to pair with quoteposts.
    pub fn suppresses(&self, notification_type: &str) -> bool {
        if self.suppresses_all() {
            return true;
        }

        match notification_type {
            "repost" | "via_repost" => self.muted_only_reposts,
            "quote" => self.muted_only_quoteposts,
            _ => false,
        }
    }
}

/// How current the returned verdict is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    Live,
    Cached,
    Stale,
}

#[derive(Debug, Clone)]
pub struct ActorModeration {
    pub verdict: ModerationVerdict,
    /// displayName, else "@handle", else None. From the same response.
    pub display_label: Option<String>,
    pub freshness: Freshness,
}

/// Oldest cached verdict that may decide a push when the appview is
/// unreachable. Past this the event is deferred instead, which is what the
/// replaced mirror effectively guaranteed by failing closed once its own state
/// went stale.
const STALE_VERDICT_CEILING: Duration = Duration::minutes(15);

#[derive(Clone)]
pub struct ActorModerationResolver {
    db_pool: Pool<Postgres>,
    ttl: Duration,
}

impl ActorModerationResolver {
    pub fn new(db_pool: Pool<Postgres>, ttl_seconds: u64) -> Self {
        Self {
            db_pool,
            ttl: Duration::seconds(ttl_seconds as i64),
        }
    }

    /// Resolve moderation state of `actor_did` as seen by `recipient_did`.
    ///
    /// 1. Cached row younger than `ttl` -> return it, `Freshness::Cached`.
    /// 2. Else fetch `app.bsky.actor.getProfile?actor=<actor_did>` authenticated
    ///    as the recipient, persist, return `Freshness::Live`.
    /// 3. Fetch failed but a cached row exists within `STALE_VERDICT_CEILING`
    ///    -> return it, `Freshness::Stale`, and warn.
    /// 4. Otherwise `Err`. The caller defers; it MUST NOT deliver.
    ///
    /// Auth revoked (`is_auth_revocation_error`) MUST propagate as Err, not be swallowed:
    /// the caller already handles revocation.
    pub async fn resolve(
        &self,
        state: &Arc<AppState>,
        recipient_did: &str,
        actor_did: &str,
    ) -> Result<ActorModeration> {
        let cached_row = sqlx::query(
            r#"
            SELECT verdict, display_label, fetched_at
            FROM actor_moderation_verdict
            WHERE recipient_did = $1 AND actor_did = $2
            "#,
        )
        .bind(recipient_did)
        .bind(actor_did)
        .fetch_optional(&self.db_pool)
        .await?;

        // A cached row that will not parse is treated as absent, never as an
        // error. Propagating here would be unrecoverable: the only code that
        // overwrites the row lives past this point, so a bad row would defer
        // every notification for this pair until the 24h guard dropped it.
        let cached = match cached_row {
            Some(row) => match Self::decode_cached(&row) {
                Ok(decoded) => Some(decoded),
                Err(err) => {
                    tracing::warn!(
                        recipient = %recipient_did,
                        actor = %actor_did,
                        error = %err,
                        "Discarding unreadable cached moderation verdict; refetching"
                    );
                    None
                }
            },
            None => None,
        };

        if let Some((verdict, display_label, fetched_at)) = &cached {
            let age = OffsetDateTime::now_utc() - *fetched_at;
            if age >= Duration::ZERO && age < self.ttl {
                return Ok(ActorModeration {
                    verdict: *verdict,
                    display_label: display_label.clone(),
                    freshness: Freshness::Cached,
                });
            }
        }

        match self
            .fetch_and_persist_live(state, recipient_did, actor_did)
            .await
        {
            Ok(live) => Ok(live),
            Err(err) => {
                if super::is_auth_revocation_error(&err) {
                    return Err(err);
                }

                // Serving a stale verdict is the availability trade, but its age
                // must be bounded. The mirror this replaced could only ever
                // decide on state younger than its sync interval and failed
                // closed past that; an unbounded fallback would let a block
                // added long after the cached answer leak during an outage.
                match cached {
                    Some((verdict, display_label, fetched_at))
                        if OffsetDateTime::now_utc() - fetched_at <= STALE_VERDICT_CEILING =>
                    {
                        tracing::warn!(
                            recipient = %recipient_did,
                            actor = %actor_did,
                            error = %err,
                            "Live moderation fetch failed; using stale cached verdict"
                        );
                        Ok(ActorModeration {
                            verdict,
                            display_label,
                            freshness: Freshness::Stale,
                        })
                    }
                    _ => Err(err),
                }
            }
        }
    }

    fn decode_cached(
        row: &sqlx::postgres::PgRow,
    ) -> Result<(ModerationVerdict, Option<String>, OffsetDateTime)> {
        let verdict: ModerationVerdict = serde_json::from_value(row.try_get("verdict")?)?;
        Ok((
            verdict,
            row.try_get("display_label")?,
            row.try_get("fetched_at")?,
        ))
    }

    /// Drop every cached verdict for a recipient, so the next push decision
    /// re-asks the appview.
    ///
    /// Called when the recipient performs a moderation action through Nest. The
    /// cache is keyed per actor, but a list mute/block changes the verdict for
    /// every member of that list at once and the members are deliberately never
    /// enumerated — so the whole recipient is invalidated rather than guessing
    /// which actors were affected. Without this, muting someone right after
    /// their notification arrived would leave their freshly-cached "not muted"
    /// verdict serving for the rest of the TTL, and a second notification would
    /// still be delivered.
    pub async fn invalidate_recipient(&self, recipient_did: &str) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        crate::services::push::lock::acquire_account_lock(&mut tx, recipient_did).await?;
        sqlx::query(
            "UPDATE push_accounts SET moderation_generation = moderation_generation + 1 WHERE account_did = $1"
        )
        .bind(recipient_did)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM actor_moderation_verdict WHERE recipient_did = $1")
            .bind(recipient_did)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Delete cached verdicts older than `max_age`, returning the row count.
    ///
    /// The cache grows with distinct (recipient, actor) pairs, which is bounded
    /// only by who interacts with each user — so it needs an actual reaper, not
    /// just a TTL on reads.
    pub async fn prune_older_than(&self, max_age: Duration) -> Result<u64> {
        let cutoff = OffsetDateTime::now_utc() - max_age;
        let result = sqlx::query("DELETE FROM actor_moderation_verdict WHERE fetched_at < $1")
            .bind(cutoff)
            .execute(&self.db_pool)
            .await?;
        Ok(result.rows_affected())
    }

    async fn fetch_and_persist_live(
        &self,
        state: &Arc<AppState>,
        recipient_did: &str,
        actor_did: &str,
    ) -> Result<ActorModeration> {
        let account = sqlx::query(
            r#"
            SELECT COALESCE(session_fingerprint, encode(sha256(session_id::bytea), 'hex')) AS session_id, pds_url, auth_revoked_at, moderation_generation
            FROM push_accounts
            WHERE account_did = $1
            "#,
        )
        .bind(recipient_did)
        .fetch_optional(&self.db_pool)
        .await?;

        let Some(account) = account else {
            return Err(anyhow!(
                "No push account found for recipient {recipient_did}"
            ));
        };

        if account
            .try_get::<Option<OffsetDateTime>, _>("auth_revoked_at")?
            .is_some()
        {
            return Err(anyhow!(
                "Session expired: auth revoked for push account {recipient_did}"
            ));
        }

        let session_id = account.try_get::<String, _>("session_id")?;
        let pds_url = account.try_get::<String, _>("pds_url")?;
        let captured_gen: i64 = account.try_get("moderation_generation").unwrap_or(1);

        let (session, dpop) =
            match super::resolve_background_session(state, recipient_did, &session_id, &pds_url)
                .await
            {
                Ok(res) => res,
                Err(err) if super::is_auth_revocation_error(&err) => {
                    tracing::warn!(
                        user_did = %recipient_did,
                        error = %err,
                        "Auth revoked for push account; marking revoked in push_accounts"
                    );
                    let registry =
                        super::registry::PushRegistry::new(self.db_pool.clone(), String::new());
                    let _ = registry
                        .mark_auth_revoked_if_session(recipient_did, &session_id)
                        .await;
                    return Err(err);
                }
                Err(err) => return Err(err),
            };

        let client = crate::services::AtProtoClient::new(state.clone());
        let query = format!("actor={}", urlencoding::encode(actor_did));
        let response = client
            .proxy_request(
                &session,
                reqwest::Method::GET,
                "/xrpc/app.bsky.actor.getProfile",
                Some(&query),
                None,
                None,
                None,
                "push-moderation",
                Some(&dpop),
            )
            .await?;

        let body = match response {
            crate::services::ProxyResponse::Buffered { status, body, .. } => {
                if !(200..300).contains(&status) {
                    return Err(anyhow!("app.bsky.actor.getProfile returned HTTP {status}"));
                }
                body
            }
            crate::services::ProxyResponse::Streaming { .. } => {
                return Err(anyhow!(
                    "Unexpected streaming response for app.bsky.actor.getProfile"
                ));
            }
        };

        let profile: serde_json::Value = serde_json::from_slice(&body)?;

        // No `viewer` means the response was not evaluated against this
        // recipient — an unauthenticated-equivalent answer. Every actor would
        // parse as unmoderated, so accepting it would fail OPEN for the whole
        // account and then stick for the cache TTL. Treat it as a fetch failure
        // so the caller falls back to a cached verdict or defers.
        let Some(viewer) = profile.get("viewer") else {
            return Err(anyhow!(
                "app.bsky.actor.getProfile returned no viewer state for {recipient_did}; \
                 cannot evaluate moderation"
            ));
        };
        let verdict = ModerationVerdict::try_from_viewer_json(Some(viewer))
            .map_err(|err| anyhow!("app.bsky.actor.getProfile returned malformed viewer state for {recipient_did}: {err}"))?;
        let display_label = actor_label_from_profile_json(&profile);

        let verdict_json = serde_json::to_value(verdict)?;

        // Write must be serialized with invalidation: hold the account lock and
        // discard the result if a newer moderation_generation was installed while
        // this fetch was in flight (i.e., a mute/block landed mid-fetch).
        let mut tx = self.db_pool.begin().await?;
        crate::services::push::lock::acquire_account_lock(&mut tx, recipient_did).await?;
        let current_gen: Option<i64> = sqlx::query_scalar(
            "SELECT moderation_generation FROM push_accounts WHERE account_did = $1",
        )
        .bind(recipient_did)
        .fetch_optional(&mut *tx)
        .await?;
        if current_gen != Some(captured_gen) {
            tx.commit().await?;
            tracing::warn!(
                recipient = %recipient_did,
                actor = %actor_did,
                captured_gen,
                current_gen = ?current_gen,
                "Discarding moderation fetch that began before an invalidation"
            );
            // Return the (possibly fresh) verdict for this call, but do NOT persist it:
            // the caller may still use it, but the cache stays clean.
            return Ok(ActorModeration {
                verdict,
                display_label,
                freshness: Freshness::Live,
            });
        }
        sqlx::query(
            r#"
            INSERT INTO actor_moderation_verdict (recipient_did, actor_did, verdict, display_label, fetched_at, generation)
            VALUES ($1, $2, $3, $4, NOW(), $5)
            ON CONFLICT (recipient_did, actor_did)
            DO UPDATE
            SET verdict = EXCLUDED.verdict,
                display_label = EXCLUDED.display_label,
                fetched_at = NOW(),
                generation = EXCLUDED.generation
            "#,
        )
        .bind(recipient_did)
        .bind(actor_did)
        .bind(verdict_json)
        .bind(&display_label)
        .bind(captured_gen)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(ActorModeration {
            verdict,
            display_label,
            freshness: Freshness::Live,
        })
    }
}

fn actor_label_from_profile_json(profile: &serde_json::Value) -> Option<String> {
    profile
        .get("displayName")
        .and_then(serde_json::Value::as_str)
        .and_then(clean_profile_label)
        .or_else(|| {
            profile
                .get("handle")
                .and_then(serde_json::Value::as_str)
                .and_then(clean_profile_label)
                .map(|handle| {
                    if handle.starts_with('@') {
                        handle
                    } else {
                        format!("@{handle}")
                    }
                })
        })
}

fn clean_profile_label(value: &str) -> Option<String> {
    let collapsed = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        None
    } else {
        Some(truncate(&collapsed, 80))
    }
}

fn truncate(value: &str, max_len: usize) -> String {
    if value.chars().count() <= max_len {
        return value.to_string();
    }
    value.chars().take(max_len).collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn test_try_from_viewer_json_malformed_non_object_fails() {
        // Non-object viewer values must fail closed rather than returning an all-false default
        assert!(ModerationVerdict::try_from_viewer_json(None).is_err());
        assert!(ModerationVerdict::try_from_viewer_json(Some(&json!("string"))).is_err());
        assert!(ModerationVerdict::try_from_viewer_json(Some(&json!(12345))).is_err());
        assert!(ModerationVerdict::try_from_viewer_json(Some(&json!(true))).is_err());
        assert!(ModerationVerdict::try_from_viewer_json(Some(&json!(false))).is_err());
        assert!(ModerationVerdict::try_from_viewer_json(Some(&json!([{"muted": true}]))).is_err());
        assert!(ModerationVerdict::try_from_viewer_json(Some(&json!(null))).is_err());
    }

    #[test]
    fn test_try_from_viewer_json_valid_empty_object_accepted() {
        // Valid object with absent optional booleans must succeed with defaults
        let empty_obj = json!({});
        let verdict = ModerationVerdict::try_from_viewer_json(Some(&empty_obj))
            .expect("empty object is valid viewerState");
        assert_eq!(verdict, ModerationVerdict::default());
        assert!(!verdict.suppresses_all());
    }
    #[test]
    fn test_malformed_profile_viewer_fails_closed() {
        let malformed_profile = json!({
            "did": "did:plc:actor",
            "handle": "actor.bsky.social",
            "viewer": "not-an-object"
        });
        let viewer = malformed_profile.get("viewer");
        let result = ModerationVerdict::try_from_viewer_json(viewer);
        assert!(result.is_err());
    }

    #[test]
    fn test_muted_by_list() {
        let viewer = json!({
            "mutedByList": {
                "uri": "at://did:plc:123/app.bsky.graph.list/456",
                "name": "Spam List"
            }
        });
        let verdict = ModerationVerdict::from_viewer_json(Some(&viewer));
        assert!(verdict.muted_by_list);
        assert!(verdict.suppresses_all());
        assert!(verdict.suppresses("repost"));
        assert!(verdict.suppresses("like"));
    }

    #[test]
    fn test_blocking_by_list() {
        let viewer = json!({
            "blockingByList": {
                "uri": "at://did:plc:123/app.bsky.graph.list/789",
                "name": "Block List"
            }
        });
        let verdict = ModerationVerdict::from_viewer_json(Some(&viewer));
        assert!(verdict.blocking_by_list);
        assert!(verdict.suppresses_all());
        assert!(verdict.suppresses("repost"));
        assert!(verdict.suppresses("like"));
    }

    #[test]
    fn test_muted_boolean() {
        let viewer_muted_true = json!({ "muted": true });
        let verdict_muted = ModerationVerdict::from_viewer_json(Some(&viewer_muted_true));
        assert!(verdict_muted.muted);
        assert!(verdict_muted.suppresses_all());

        let viewer_muted_false = json!({ "muted": false });
        let verdict_unmuted = ModerationVerdict::from_viewer_json(Some(&viewer_muted_false));
        assert!(!verdict_unmuted.muted);
        assert!(!verdict_unmuted.suppresses_all());
    }

    #[test]
    fn test_blocking_and_blocked_by() {
        let viewer_blocking = json!({ "blocking": "at://did:plc:123/app.bsky.graph.block/456" });
        let verdict_blocking = ModerationVerdict::from_viewer_json(Some(&viewer_blocking));
        assert!(verdict_blocking.blocking);
        assert!(verdict_blocking.suppresses_all());

        let viewer_blocked_by = json!({ "blockedBy": true });
        let verdict_blocked_by = ModerationVerdict::from_viewer_json(Some(&viewer_blocked_by));
        assert!(verdict_blocked_by.blocked_by);
        assert!(verdict_blocked_by.suppresses_all());
    }

    #[test]
    fn test_muted_only_reposts() {
        let viewer = json!({ "mutedOnlyReposts": true });
        let verdict = ModerationVerdict::from_viewer_json(Some(&viewer));
        assert!(verdict.muted_only_reposts);
        assert!(!verdict.suppresses_all());
        assert!(verdict.suppresses("repost"));
        assert!(!verdict.suppresses("like"));
        assert!(!verdict.suppresses("reply"));
        assert!(!verdict.suppresses("quote"));
        // `via_repost` is the same actor reposting, surfaced through another
        // repost, so a repost-scoped mute must cover it too.
        assert!(verdict.suppresses("via_repost"));
        assert!(!verdict.suppresses("via_like"));
    }

    #[test]
    fn test_muted_only_quoteposts() {
        let viewer = json!({ "mutedOnlyQuoteposts": true });
        let verdict = ModerationVerdict::from_viewer_json(Some(&viewer));
        assert!(verdict.muted_only_quoteposts);
        assert!(!verdict.suppresses_all());
        assert!(verdict.suppresses("quote"));
        assert!(!verdict.suppresses("like"));
        assert!(!verdict.suppresses("reply"));
        assert!(!verdict.suppresses("repost"));
    }

    #[test]
    fn blocking_is_read_from_its_at_uri_shape() {
        // `blocking` is an at-uri in the lexicon, not a boolean. Reading it as
        // a bool would silently mean "not blocking" for every blocked actor.
        let viewer = json!({ "blocking": "at://did:plc:me/app.bsky.graph.block/3abc" });
        assert!(ModerationVerdict::from_viewer_json(Some(&viewer)).suppresses_all());

        let empty = json!({ "blocking": "" });
        assert!(!ModerationVerdict::from_viewer_json(Some(&empty)).suppresses_all());
    }

    #[test]
    fn cached_verdict_survives_added_fields() {
        // Cached rows are JSONB. A verdict written before a new field existed
        // must still deserialize, or every cached pair would defer at once.
        let legacy = json!({ "muted": true, "blocking": false });
        let verdict: ModerationVerdict = serde_json::from_value(legacy).expect("must deserialize");
        assert!(verdict.muted);
        assert!(!verdict.blocking_by_list);
    }

    #[test]
    fn test_actor_label_parsing() {
        let profile_display = json!({
            "displayName": " Alice Bob ",
            "handle": "alice.bsky.social"
        });
        assert_eq!(
            actor_label_from_profile_json(&profile_display),
            Some("Alice Bob".to_string())
        );

        let profile_handle_only = json!({
            "displayName": "   ",
            "handle": "alice.bsky.social"
        });
        assert_eq!(
            actor_label_from_profile_json(&profile_handle_only),
            Some("@alice.bsky.social".to_string())
        );

        let profile_handle_with_at = json!({
            "handle": "@alice.bsky.social"
        });
        assert_eq!(
            actor_label_from_profile_json(&profile_handle_with_at),
            Some("@alice.bsky.social".to_string())
        );

        let profile_empty = json!({});
        assert_eq!(actor_label_from_profile_json(&profile_empty), None);
    }
}
