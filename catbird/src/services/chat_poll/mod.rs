//! Chat poll service — polls `chat.bsky.convo.getLog` on behalf of
//! enrolled accounts and enqueues push notifications for new messages.

pub mod mute_sync;
pub mod poller;
pub mod rate_budget;
pub mod scheduler;
pub mod types;

use std::sync::Arc;

use sqlx::{Pool, Postgres};

use crate::config::AppState;

use self::rate_budget::PdsRateBudget;
use self::scheduler::ChatPollScheduler;

/// Top-level chat poll service.
///
/// Owns the scheduler, rate budget, and DB pool. Call [`ChatPollService::spawn`]
/// to kick off the background poll loop and periodic mute sync.
#[derive(Clone)]
pub struct ChatPollService {
    scheduler: ChatPollScheduler,
    rate_budget: Arc<PdsRateBudget>,
    db_pool: Pool<Postgres>,
}

impl ChatPollService {
    pub fn new(db_pool: Pool<Postgres>) -> Self {
        Self {
            scheduler: ChatPollScheduler::new(db_pool.clone()),
            // Global rate: ~20 requests/sec across all PDS hosts
            rate_budget: Arc::new(PdsRateBudget::new(20.0)),
            db_pool,
        }
    }

    /// Access the scheduler (e.g. for enrollment from HTTP handlers).
    pub fn scheduler(&self) -> &ChatPollScheduler {
        &self.scheduler
    }

    /// Spawn background tasks: the main poll loop and periodic mute sync.
    pub fn spawn(self, state: Arc<AppState>) {
        let poll_service = self.clone();
        let poll_state = state.clone();
        tokio::spawn(async move {
            poll_service.run_poll_loop(poll_state).await;
        });

        let mute_state = state;
        let mute_db = self.db_pool.clone();
        let mute_scheduler = self.scheduler.clone();
        tokio::spawn(async move {
            run_mute_sync_loop(mute_state, mute_db, mute_scheduler).await;
        });
    }

    /// Main poll loop: claim due accounts and poll each one.
    async fn run_poll_loop(self, state: Arc<AppState>) {
        let batch_size: i64 = 50;
        let idle_sleep = std::time::Duration::from_secs(2);

        tracing::info!("Chat poll loop started");

        loop {
            match self.scheduler.claim_due_accounts(batch_size).await {
                Ok(rows) if rows.is_empty() => {
                    tokio::time::sleep(idle_sleep).await;
                }
                Ok(rows) => {
                    let count = rows.len();
                    tracing::debug!(count = count, "Claimed chat poll accounts");

                    for row in rows {
                        if let Err(err) = poller::poll_account(
                            &state,
                            &self.db_pool,
                            &self.scheduler,
                            &self.rate_budget,
                            &row,
                        )
                        .await
                        {
                            tracing::warn!(
                                did = %row.account_did,
                                error = %err,
                                "Chat poll failed for account"
                            );
                        }
                    }
                }
                Err(err) => {
                    tracing::error!(error = %err, "Chat poll claim failed");
                    tokio::time::sleep(idle_sleep).await;
                }
            }
        }
    }
}

/// Background mute sync loop — runs every 10 minutes.
async fn run_mute_sync_loop(
    state: Arc<AppState>,
    db_pool: Pool<Postgres>,
    scheduler: ChatPollScheduler,
) {
    let interval = std::time::Duration::from_secs(600);

    tracing::info!("Chat mute sync loop started (interval=600s)");

    loop {
        tokio::time::sleep(interval).await;

        if let Err(err) = mute_sync::sync_all_mutes(&state, &db_pool, &scheduler).await {
            tracing::error!(error = %err, "Chat mute sync cycle failed");
        }
    }
}
