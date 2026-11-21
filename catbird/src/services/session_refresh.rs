//! Session reads that may refresh tokens, run so that a refresh always finishes.
//!
//! A refresh token is single-use. The authorization server consumes it the moment it accepts
//! the refresh and treats a second presentation as theft: it revokes the whole grant. So once
//! a refresh request has reached the server, the gateway must receive the answer and store the
//! new tokens. If it does not, the next refresh replays the consumed token and the account is
//! signed out everywhere this session is used.
//!
//! A refresh used to run inside the HTTP request that happened to need a fresh token. When the
//! client dropped that request (an app going to the background does), the server dropped the
//! request's future, and the refresh in flight with it: the authorization server had consumed
//! the old token, and nobody stored the new one. Seen in production on 2026-11-21
//! (`docs/DECISIONS.md` in the workspace repo).
//!
//! [`get_refreshed_session`] is the only place that asks the session registry to refresh. It
//! runs the read on its own task, so it finishes and stores its result whatever happens to the
//! caller. The same loss can happen when the process stops, so shutdown calls
//! [`finish_detached_work`] to let reads in flight end first.
//!
//! What this cannot cover: an answer the authorization server sent and the network lost, and a
//! session store that refuses the write. Both still leave a consumed token behind.

use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use jacquard_common::types::did::Did;
use jacquard_oauth::session::ClientSessionData;
use tokio::sync::Notify;

use crate::config::JacquardOAuthClient;

/// Why a session could not be read.
#[derive(Debug)]
pub enum SessionReadError {
    /// The registry's own answer: no such session, a refused refresh, or a server that could
    /// not be reached. Displays exactly as the registry error does, because callers classify
    /// permanent and transient failures from that text.
    Registry(Box<jacquard_oauth::session::Error>),
    /// The task running the read ended without an answer.
    TaskFailed(String),
}

impl SessionReadError {
    /// Whether signing in again is the only way forward. A read that did not finish, a store
    /// that could not be reached and a server that could not be asked are not: retrying can
    /// succeed, and answering "sign in again" for them signs a working account out.
    pub fn is_permanent(&self) -> bool {
        match self {
            Self::Registry(error) => error.is_permanent(),
            Self::TaskFailed(_) => false,
        }
    }
}

impl fmt::Display for SessionReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry(error) => fmt::Display::fmt(error, f),
            Self::TaskFailed(why) => write!(f, "session read task did not finish: {why}"),
        }
    }
}

impl std::error::Error for SessionReadError {}

/// Detached work still running, and a wake-up for whoever waits for it to end.
static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
static IDLE: Notify = Notify::const_new();

/// Counts one piece of detached work from the moment it is handed over until it ends,
/// finished or not.
struct InFlight;

impl InFlight {
    fn begin() -> Self {
        IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
        Self
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if IN_FLIGHT.fetch_sub(1, Ordering::SeqCst) == 1 {
            IDLE.notify_waiters();
        }
    }
}

/// Runs `work` on its own task and waits for its result.
///
/// Dropping the returned future stops the waiting, not the work: `work` still runs to its end.
pub async fn run_detached<T, F>(work: F) -> Result<T, String>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let in_flight = InFlight::begin();
    tokio::spawn(async move {
        let _in_flight = in_flight;
        work.await
    })
    .await
    .map_err(|error| error.to_string())
}

/// Waits, for at most `limit`, until no detached work is running. Returns how much still is.
///
/// Called at shutdown, after the server has stopped taking requests: the runtime cancels
/// whatever is left when the process exits, and a refresh cancelled there is lost exactly as
/// one cancelled by a dropped request was.
pub async fn finish_detached_work(limit: Duration) -> usize {
    let wait = async {
        loop {
            let idle = IDLE.notified();
            tokio::pin!(idle);
            // Register before checking, so work that ends in between is not missed.
            idle.as_mut().enable();
            if IN_FLIGHT.load(Ordering::SeqCst) == 0 {
                return;
            }
            idle.await;
        }
    };
    let _ = tokio::time::timeout(limit, wait).await;
    IN_FLIGHT.load(Ordering::SeqCst)
}

/// Reads `session_id` for `did`, refreshing its tokens first when they are about to expire.
///
/// The read runs on its own task. A refresh that has started is finished and stored even if
/// the caller goes away before it does.
pub async fn get_refreshed_session(
    client: &Arc<JacquardOAuthClient>,
    did: &str,
    session_id: &str,
) -> Result<ClientSessionData, SessionReadError> {
    let registry = Arc::clone(&client.registry);
    let did = did.to_owned();
    let session_id = session_id.to_owned();
    run_detached(async move {
        let did = Did::new(did.as_str())
            .map_err(|error| SessionReadError::TaskFailed(format!("invalid DID: {error}")))?;
        registry
            .get(&did, &session_id, true)
            .await
            .map_err(|error| SessionReadError::Registry(Box::new(error)))
    })
    .await
    .unwrap_or_else(|why| Err(SessionReadError::TaskFailed(why)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::Mutex;

    /// The in-flight count is process-wide; tests that read it must not overlap.
    static COUNTED: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// An authorization server that, like Swan and the reference PDS, consumes a refresh token
    /// the moment it accepts it and revokes the grant when a consumed token comes back.
    struct SingleUseTokenServer {
        current: Mutex<u32>,
        revoked: AtomicBool,
        answer_delay: Duration,
    }

    impl SingleUseTokenServer {
        fn new(answer_delay: Duration) -> Arc<Self> {
            Arc::new(Self {
                current: Mutex::new(1),
                revoked: AtomicBool::new(false),
                answer_delay,
            })
        }

        async fn refresh(&self, presented: u32) -> Result<u32, &'static str> {
            let issued = {
                let mut current = self.current.lock().unwrap();
                if self.revoked.load(Ordering::SeqCst) {
                    return Err("invalid_grant");
                }
                if presented != *current {
                    self.revoked.store(true, Ordering::SeqCst);
                    return Err("invalid_grant");
                }
                *current += 1;
                *current
            };
            // The old token is consumed; the answer carrying the new one is still on its way.
            tokio::time::sleep(self.answer_delay).await;
            Ok(issued)
        }
    }

    /// The refresh token the gateway holds for one session.
    type HeldToken = Arc<Mutex<u32>>;

    /// What the session registry does: refresh at the server, then store the answer.
    async fn refresh_then_store(
        server: Arc<SingleUseTokenServer>,
        held: HeldToken,
    ) -> Result<u32, &'static str> {
        let presented = *held.lock().unwrap();
        let issued = server.refresh(presented).await?;
        *held.lock().unwrap() = issued;
        Ok(issued)
    }

    // The clock is paused in these tests and only moves when every task is waiting, so the
    // order of events below does not depend on how fast the machine is.
    const ANSWER_DELAY: Duration = Duration::from_millis(800);
    const CLIENT_GIVES_UP_AFTER: Duration = Duration::from_millis(100);

    #[tokio::test(start_paused = true)]
    async fn a_refresh_survives_the_request_that_started_it() {
        let _counted = COUNTED.lock().await;
        let server = SingleUseTokenServer::new(ANSWER_DELAY);
        let held: HeldToken = Arc::new(Mutex::new(1));

        // The client drops its request while the refresh is waiting for the server's answer.
        let request = run_detached(refresh_then_store(server.clone(), held.clone()));
        assert!(
            tokio::time::timeout(CLIENT_GIVES_UP_AFTER, request)
                .await
                .is_err(),
            "the request must be dropped before the server answers"
        );
        assert_eq!(*held.lock().unwrap(), 1, "the answer has not arrived yet");

        tokio::time::sleep(ANSWER_DELAY).await;
        assert_eq!(
            *held.lock().unwrap(),
            2,
            "the new refresh token must be stored although nobody waited for it"
        );

        // The next request refreshes with the stored token and the grant is intact.
        assert_eq!(
            refresh_then_store(server.clone(), held.clone()).await,
            Ok(3)
        );
        assert!(!server.revoked.load(Ordering::SeqCst));
    }

    /// The failure this module exists to prevent, reproduced without it: the production
    /// sequence of 2026-11-21 (request dropped at 01:05:00, grant revoked at 01:20:09).
    #[tokio::test(start_paused = true)]
    async fn awaited_inside_the_request_a_dropped_request_costs_the_grant() {
        let server = SingleUseTokenServer::new(ANSWER_DELAY);
        let held: HeldToken = Arc::new(Mutex::new(1));

        let request = refresh_then_store(server.clone(), held.clone());
        assert!(tokio::time::timeout(CLIENT_GIVES_UP_AFTER, request)
            .await
            .is_err());

        tokio::time::sleep(ANSWER_DELAY).await;
        assert_eq!(*server.current.lock().unwrap(), 2, "the server moved on");
        assert_eq!(
            *held.lock().unwrap(),
            1,
            "the gateway still holds the consumed token"
        );

        assert_eq!(
            refresh_then_store(server.clone(), held.clone()).await,
            Err("invalid_grant")
        );
        assert!(server.revoked.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_waits_for_a_refresh_in_flight_but_not_forever() {
        let _counted = COUNTED.lock().await;
        assert_eq!(finish_detached_work(Duration::from_millis(1)).await, 0);

        let server = SingleUseTokenServer::new(ANSWER_DELAY);
        let held: HeldToken = Arc::new(Mutex::new(1));
        let request = run_detached(refresh_then_store(server.clone(), held.clone()));
        assert!(tokio::time::timeout(CLIENT_GIVES_UP_AFTER, request)
            .await
            .is_err());

        // Too short a wait reports what is still running and leaves it running.
        assert_eq!(finish_detached_work(Duration::from_millis(50)).await, 1);
        assert_eq!(*held.lock().unwrap(), 1);

        // A wait long enough returns as soon as the refresh has been stored.
        let before = tokio::time::Instant::now();
        assert_eq!(finish_detached_work(Duration::from_secs(30)).await, 0);
        assert!(before.elapsed() < Duration::from_secs(2));
        assert_eq!(*held.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn the_caller_gets_the_result_and_a_panic_is_an_error_not_a_crash() {
        let _counted = COUNTED.lock().await;
        assert_eq!(run_detached(async { 7 }).await, Ok(7));

        let failed = run_detached(async {
            if true {
                panic!("refresh blew up");
            }
            7
        })
        .await;
        assert!(failed.is_err());
        assert_eq!(
            finish_detached_work(Duration::from_secs(1)).await,
            0,
            "work that panicked is no longer counted as running"
        );
    }

    #[test]
    fn a_registry_error_displays_unchanged_and_only_real_refusals_are_permanent() {
        // Callers decide between "sign in again" and "try later" from this text.
        let inner = jacquard_oauth::session::Error::SessionNotFound;
        let expected = inner.to_string();
        let missing = SessionReadError::Registry(Box::new(inner));
        assert_eq!(missing.to_string(), expected);
        assert!(missing.is_permanent());

        let unfinished = SessionReadError::TaskFailed("cancelled".into());
        assert!(unfinished.to_string().contains("did not finish"));
        assert!(!unfinished.is_permanent());
        for phrase in ["invalid_grant", "invalid_token", "no refresh token"] {
            assert!(!unfinished.to_string().contains(phrase));
        }
    }

    /// Every refreshing read must go through this module. A new direct call would bring back
    /// the lost-refresh sign-out for whatever request path it sits on.
    ///
    /// This is a tripwire, not a proof: it reads the source text, so a refresh flag passed in a
    /// variable or a registry reached through another name gets past it.
    #[test]
    fn nothing_else_asks_the_registry_to_refresh() {
        fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    rust_files(&path, out);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    out.push(path);
                }
            }
        }

        /// The argument text of the call that starts at `open` (the index of its `(`).
        fn arguments(text: &str, open: usize) -> &str {
            let mut depth = 0usize;
            for (offset, c) in text[open..].char_indices() {
                match c {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            return &text[open + 1..open + offset];
                        }
                    }
                    _ => {}
                }
            }
            &text[open + 1..]
        }

        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rust_files(&src, &mut files);
        assert!(
            files.len() > 20,
            "source tree not found at {}",
            src.display()
        );

        let mut direct_refreshes = Vec::new();
        let mut restores = Vec::new();
        for file in files {
            let name = file
                .strip_prefix(&src)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if name == "services/session_refresh.rs" {
                continue;
            }
            let compact: String = std::fs::read_to_string(&file)
                .unwrap()
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .flat_map(str::chars)
                .filter(|c| !c.is_whitespace())
                .collect();
            for (at, _) in compact.match_indices("registry.get(") {
                let open = at + "registry.get".len();
                if arguments(&compact, open).ends_with(",true") {
                    direct_refreshes.push(name.clone());
                }
            }
            // `OAuthClient::restore` reads through the registry with refresh on.
            if compact.contains("jacquard_client.restore(")
                || compact.contains(".restore(&parsed_did,")
            {
                restores.push(name.clone());
            }
        }
        assert!(
            direct_refreshes.is_empty(),
            "refreshing registry reads outside session_refresh.rs: {direct_refreshes:?}"
        );

        // The two known `restore` calls act on a session minted moments earlier in the same
        // request, whose token is nowhere near expiry. A third needs the same scrutiny.
        restores.sort();
        assert_eq!(
            restores,
            ["handlers/atproto.rs", "handlers/oauth_upgrade.rs"],
            "a new OAuthClient::restore call can refresh inside a request; route it through \
             session_refresh or add it here with the reason it is safe"
        );
    }
}
