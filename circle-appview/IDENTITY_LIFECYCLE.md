# Circle account and identity lifecycle

The Circle AppView consumes account and identity hints from one explicitly configured relay. This closes the path from an account lifecycle change to Circle visibility and deletion cleanup. The relay's `#account` status describes that relay, so it never directly authorizes a purge: the AppView resolves the account's current DID document and confirms its status through that personal data server (PDS). Local tests cover this boundary; supported-host, deployed-relay, device, and capacity qualification remain separate release gates.

Governing scope: [Spaces release readiness, Circles section](/Users/joshlacalamito/Developer/Catbird+Petrel/docs/research/2026-10-23-spaces-release-readiness.md#7-catbird-circles-sync-plus-user-visible-privacy).

## Configuration and readiness

Set `CIRCLE_IDENTITY_RELAY_URL` to the trusted relay's `wss://` origin. There is no default relay and no plaintext, private-address, URL-credential, path, query, or fragment override. The consumer resolves and checks DNS addresses, pins the socket to a checked address, and verifies TLS using the platform native trust roots. Current-PDS confirmations use the existing DNS-pinned HTTPS transport with redirects and proxies disabled.

The private HTTP routes and `getCapabilities.enabled` require the configured source to be ready. Readiness requires:

- A completed initial reconciliation of every known authority, author, member, and retained account ledger entry.
- A fresh source event after the current connection was established. Historical replay cannot establish readiness.
- Recent valid traffic on that caught-up connection, including incoming WebSocket pings or pongs matching the consumer's random challenge. An idle caught-up source does not become unhealthy merely because it has no account changes.
- No connection error, malformed frame, or retained history-gap marker.

A newly connected but quiet source remains conservatively unready until its first fresh event. No production relay has been qualified by these local tests. Newly enrolled accounts require their own current-PDS status confirmation so enrollment after the initial reconciliation cannot skip the ledger.

## State and privacy

`circle_account_status` stores the confirmed account status, PDS endpoint, confirmation time, and source sequence. It is a serving gate separate from authority-issued membership grants. Suspension or deactivation preserves membership and private projection rows while author, requester, and authority gates deny their use. Confirmed reactivation restores normal visibility subject to the existing membership checks.

Only an explicit `active: false, status: "deleted"` response for the exact DID from its current PDS creates a terminal deletion. `RepoNotFound`, failed DID resolution, an HTTP/network failure, and the relay's deletion hint do not establish that fact. An account deletion first persists the inactive gate, then calls the existing authority-Space deletion path and bounded author-payload cleanup. The stream cursor advances only after these effects finish. Repeating the event or restarting after the gate commit resumes cleanup from the retained deletion ledger without requiring an already deleted DID to resolve again. A later active hint cannot resurrect a terminal deleted lifecycle.

Identity hints invalidate the DID-document cache, which is also the source of KEM keys used for response-MAC verification. Confirmation uses the dedicated fresh-resolution path rather than the unauthenticated JWT refresh cooldown. Other service workers retain the existing maximum DID-cache lifetime; this consumer uses a PostgreSQL advisory lock so only one worker processes the source at a time.

## Bounds and restart behavior

The consumer accepts binary subscription frames up to 3 MiB and never stores commit contents. PDS status responses are limited to 16 KiB. Processing is sequential, the cursor flushes at least every second or 256 ordinary events, and lifecycle events checkpoint after their effects. Each connection is bounded to 100,000 events or five minutes; reconnect uses the saved sequence, with an exponential one-to-thirty-second failure backoff. Initial account reconciliation pages 100 DIDs and persists progress after each confirmation. Author-payload cleanup uses batches of 500 records.

These are resource bounds, not throughput or production-capacity claims. A failing account confirmation retains the cursor and makes readiness false rather than skipping an unresolved lifecycle change.

## Inspection and history-gap recovery

Inspect the configured source row in `circle_identity_cursor`: `cursor`, `last_event_at`, `last_received_at`, `last_connected_at`, `reconciled_at`, `reconcile_after`, `caught_up`, `replay_invalid`, and `blocked_reason`. Do not treat a recent socket timestamp alone as caught-up evidence.

`OutdatedCursor` and `FutureCursor` permanently set `replay_invalid`. The consumer keeps the old cursor and refuses to reconnect from an arbitrary stream head. Recovery is an operator action: preserve the existing ledger/cursor and database backup, determine a valid source cursor, and explicitly schedule a full current-PDS account reconciliation by clearing `reconciled_at` and `reconcile_after` along with the reviewed cursor correction and history-gap marker. Keep serving disabled until reconciliation and fresh-source catch-up both complete. Never erase `circle_account_status` or its terminal deletion entries as part of cursor recovery. If a formerly known account cannot be authoritatively resolved or confirmed, that requires investigation; an absent account response is not permission to infer deletion.

No production configuration, migration, deployment, restart, or cursor reset was performed by this implementation task.
