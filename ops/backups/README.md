# Catbird database backups

Encrypted, off-server, nightly backups of every PostgreSQL database on a
Catbird host, with a weekly automatic restore test. One script
(`catbird-backup.sh`) and two systemd timers. Nothing here runs until it is
installed on a server as described below.

## What is backed up

The services, read from their repositories on 2026-11-24. Which service runs on
which Netcup VPS is not recorded in any repository, so run the kit on every
host that has a PostgreSQL cluster: it finds the databases by itself.

| Service | Store | User data? | Covered by |
|---|---|---|---|
| Nest gateway (`nest/catbird`, api.catbird.blue) | PostgreSQL, push database (`CATBIRD__PUSH__DATABASE_URL`): devices, push gateway keys, preferences, activity subscriptions, thread mutes, push queue | Yes | Nightly dump |
| Nest gateway | Redis: OAuth sessions and sign-in flow state only, encrypted, 30-day TTL | Tokens only | **Not backed up**, on purpose (below) |
| Circle AppView (`nest/circle-appview`, circles.catbird.blue) | PostgreSQL `circle_appview`: circles, member cache, posts, notifications, reports, sealed OAuth sessions. Media is proxied, not stored | Yes | Nightly dump |
| Chat delivery service (`mls-ds`, chat.catbird.blue) | PostgreSQL `catbird`: conversations, members, devices, key packages, ciphertext queues, sealed recovery shares | Yes | Nightly dump |
| Chat delivery service | Recovery-share erasure journal (`LABYRINTH_RECOVERY_SHARE_TOMBSTONE_FILE` and its segments) | Yes (erasure records) | Nightly copy, separate repository (below) |
| Chat delivery service | Recovery-share KEK (`LABYRINTH_RECOVERY_SHARE_KEK_FILE`, 32 bytes), signing keys | Keys | **Not** in the bucket: keep in the password manager / Doppler (below) |
| Push notifier (`catbird-firehose`, or its predecessor `bluesky-push-notifier`) | PostgreSQL: push registrations, relationships, cursor | Yes | Nightly dump |
| GlitchTip (diagnostics.catbird.blue) | Its own PostgreSQL | Crash reports | Nightly dump, if it shares a cluster; otherwise point `BACKUP_PG_EXEC` at its container |
| Swan PDS, if it serves real accounts | SQLite databases and blobs under its data directory | Yes | Swan's own offline snapshot tool, see "Swan" below |

The current mls-ds code uses neither Redis nor S3, although its old
`.env.example` still lists both. `mls-ds/server/scripts/backup-db.sh` keeps a
local, unencrypted copy on the same disk; this kit replaces it.

### Why Redis is not backed up

Nest's Redis holds only session records (AES-256-GCM, 30-day TTL) and sign-in
flow state. Losing it signs everyone out once; nothing else is lost. Backing it
up would copy users' AT Protocol refresh tokens to a second place for no gain.

## Where backups go

**Recommended: Cloudflare R2**, one private bucket `catbird-backups` with the
location hint "Eastern North America".

- It is off Netcup entirely, so it survives losing a VPS or the Netcup account.
- Catbird already uses Cloudflare (DNS, Pages), so no new vendor.
- Price, read on developers.cloudflare.com/r2/pricing on 2026-11-24: storage
  $0.015 per GB-month, the first 10 GB-month free; Class A requests $4.50 per
  million, first 1 million free; Class B $0.36 per million, first 10 million
  free; no egress charge, so a restore costs nothing; no minimum storage
  duration. restic compresses and de-duplicates, so a few GB of databases with
  three weeks of history should stay in the free tier. At 50 GB stored it would
  be about $0.60 a month.
- A location hint is a placement preference, not a legal guarantee. The privacy
  policy should say backups are kept "in the United States" only after the
  bucket shows that location.

Alternative: Backblaze B2 at $6.95 per TB-month, first 10 GB free (read on
backblaze.com/pricing the same day). Use it if you would rather keep backups
away from Cloudflare too. Only `RESTIC_REPOSITORY` and the two keys change.

Encryption happens on the server before upload (restic, AES-256), so the
bucket provider only ever sees ciphertext. The restic password never leaves the
server and the password manager.

## Retention, and what it means for account deletion

Each night keeps a snapshot of every database. The policy is **7 daily + 4
weekly** (`BACKUP_KEEP_DAILY`, `BACKUP_KEEP_WEEKLY`), and `restic forget
--prune` deletes everything older from the bucket the same night. restic counts
the current week among the four weekly snapshots, so the oldest snapshot is the
last one of the Sunday three weeks back: at most **22 days** old (measured with
restic 0.16.4 by replaying 50 nights of snapshots for every day of the week;
the worst case falls on a Sunday at 21 days plus the hours until the next run).

- A row deleted today is absent from tonight's snapshot.
- It survives in older snapshots for at most 22 days, then the nightly prune
  removes it from the bucket.
- R2 has no soft delete, so once pruned the objects are gone (a bucket
  lock rule, if you add one later, would delay that).
- If backups stop running, nothing ages out either. The healthcheck alert
  below is what catches that.

**Recommended privacy-policy wording:** "Deleted data may remain in encrypted
backups for up to 30 days, after which it is permanently deleted." 30 leaves a
week of margin over the 22 days for a missed night or a late fix. If you change
the retention variables, change that number with them.

Restoring a backup can bring back data that was deleted after the snapshot was
taken. Two rules keep a restore honest:

1. The chat server's recovery shares are already protected: on start it replays
   the erasure journal into the restored database. Never restore the journal
   from an older copy than the newest one (see "Restoring the chat server").
2. For everything else, keep a dated list of the account-deletion requests you
   carry out (DIDs and date, nothing else). After any restore, run the deletion
   again for every DID deleted after the snapshot's date, before reopening the
   service.

## Setting it up on a host

Do this on each VPS that runs PostgreSQL. Commands are for Ubuntu/Debian.

### Once, for the fleet

1. In Cloudflare: R2, create bucket `catbird-backups`, location hint Eastern
   North America. Keep the bucket private (no public access, no r2.dev URL).
2. R2, Manage API tokens: create a token with **Object Read & Write** scoped to
   `catbird-backups` only. Note the Access Key ID, Secret Access Key and the
   account ID from the S3 endpoint.
3. Put those, and every restic password you create below, in the password
   manager. If the server dies, these are the only way back in.

### On each host

```bash
sudo apt-get install -y restic          # 0.16 or newer; the script is tested with 0.16.4
sudo install -d -m 0700 /etc/catbird-backup /opt/catbird-backup
sudo install -m 0755 ops/backups/catbird-backup.sh /usr/local/sbin/catbird-backup
sudo install -m 0644 ops/backups/README.md /opt/catbird-backup/README.md
sudo install -m 0600 ops/backups/backup.env.example /etc/catbird-backup/backup.env
sudo sh -c 'openssl rand -base64 48 > /etc/catbird-backup/restic-password'
sudo chmod 0600 /etc/catbird-backup/restic-password
sudoedit /etc/catbird-backup/backup.env   # fill in <ACCOUNT_ID>, <HOST_NAME>, keys
```

Copy the new restic password into the password manager now, labelled with the
host name.

Create the repository and take the first backup by hand:

```bash
sudo sh -c 'set -a; . /etc/catbird-backup/backup.env; restic init'
sudo systemd-run --wait --pty -p EnvironmentFile=/etc/catbird-backup/backup.env \
  /usr/local/sbin/catbird-backup backup
sudo systemd-run --wait --pty -p EnvironmentFile=/etc/catbird-backup/backup.env \
  /usr/local/sbin/catbird-backup verify
```

`verify` must end with "every database restored". Then turn on the timers:

```bash
sudo install -m 0644 ops/backups/systemd/* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now catbird-backup.timer catbird-backup-verify.timer
systemctl list-timers 'catbird-backup*'
```

The backup runs daily at 08:17 UTC (3:17 AM Eastern); the restore test runs
Sundays at 10:43 UTC. Logs: `journalctl -u catbird-backup -u catbird-backup-verify`.

To be told when a night fails, set `BACKUP_HEALTHCHECK_URL` to a
dead-man's-switch check (for example healthchecks.io). Without it, a failure
only shows in the journal.

If PostgreSQL runs in Docker on that host, set
`BACKUP_PG_EXEC="docker exec -i -u postgres <container>"`.

### Extra step on the chat (mls-ds) host

Only once `CHAT_CUTOVER_ENABLED` is on and the recovery-share journal exists:

```bash
sudo sh -c 'openssl rand -base64 48 > /etc/catbird-backup/journal-restic-password'
sudo chmod 0600 /etc/catbird-backup/journal-restic-password
sudoedit /etc/catbird-backup/backup.env
#   BACKUP_JOURNAL_DIR=<directory of LABYRINTH_RECOVERY_SHARE_TOMBSTONE_FILE>
#   BACKUP_JOURNAL_STOP_UNIT=catbird-mls-server
#   JOURNAL_RESTIC_REPOSITORY / JOURNAL_RESTIC_PASSWORD_FILE as in the example
sudo sh -c 'set -a; . /etc/catbird-backup/backup.env;
  RESTIC_REPOSITORY=$JOURNAL_RESTIC_REPOSITORY RESTIC_PASSWORD_FILE=$JOURNAL_RESTIC_PASSWORD_FILE restic init'
```

The nightly run then stops `catbird-mls-server` for the few seconds it takes to
copy the journal directory, restarts it, and uploads the copy to its own
repository with its own password. mls-ds `server/docs/recovery-shares.md`
requires the copy to be taken with the writer stopped, and the journal to be
kept apart from the database backups.

Store the KEK file's 32 bytes in the password manager (`base64 <
"$LABYRINTH_RECOVERY_SHARE_KEK_FILE"`), not in the bucket. It never changes
under the same `LABYRINTH_RECOVERY_SHARE_KEK_ID`, so one copy is enough.

## Restoring

Every restore starts with the repository's environment loaded:

```bash
sudo -i
set -a; . /etc/catbird-backup/backup.env; set +a
restic snapshots --tag catbird-db          # pick a snapshot, or use "latest"
```

On a **new** server, first install PostgreSQL and restic, recreate
`/etc/catbird-backup/backup.env` and `restic-password` from the password
manager, and use the old `BACKUP_HOST_TAG` in the `--host` flags below.

### One database

Stop the service that uses it first (for example `systemctl stop
catbird-nest-prod`).

```bash
DB=catbird_push                                         # database to restore
restic dump --host "$BACKUP_HOST_TAG" --tag "db:$DB" latest "/$DB.dump" > /root/$DB.dump
# Roles first, on a new server only:
restic dump --host "$BACKUP_HOST_TAG" --tag globals latest /globals.sql > /root/globals.sql
runuser -u postgres -- psql -f /root/globals.sql        # then set role passwords from Doppler
# Restore into a fresh database:
runuser -u postgres -- dropdb --if-exists "$DB"         # destroys the current copy
runuser -u postgres -- createdb "$DB"
runuser -u postgres -- pg_restore --exit-on-error -d "$DB" < /root/$DB.dump
shred -u /root/$DB.dump /root/globals.sql
```

To look before replacing anything, restore into another name (`createdb
${DB}_restored`, `pg_restore -d ${DB}_restored`) and compare. Use a specific
snapshot ID instead of `latest` to go back further.

Then replay any account deletions made after the snapshot's date (see
"Retention"), start the service, and check its health endpoint.

### Restoring the chat server

Follow mls-ds `server/docs/recovery-shares.md`, "Database restore":

1. Stop `catbird-mls-server`.
2. Restore the `catbird` database as above.
3. Keep the current KEK file and erasure journal as they are. On a new server,
   put the KEK back from the password manager and restore the **newest**
   journal snapshot, never an older one:
   ```bash
   RESTIC_REPOSITORY=$JOURNAL_RESTIC_REPOSITORY RESTIC_PASSWORD_FILE=$JOURNAL_RESTIC_PASSWORD_FILE \
     restic restore latest --host "$BACKUP_HOST_TAG" --target /root/journal-restore
   ```
   The files are under `/root/journal-restore/var/lib/catbird-backup/staging/recovery-journal/`;
   move them into the journal directory with the service's owner and mode 0600.
4. Start the service. On start it replays the journal's erasures into the
   restored database before serving traffic.

## Swan

Swan keeps SQLite databases and blobs, not PostgreSQL, so this script does not
cover it. If Swan serves real accounts, use its own offline full-service
snapshot (`Scripts/service-snapshot.py`, Swan `docs/operational-runbook.md`,
Procedure 5), which needs Swan stopped, then upload the snapshot directory with
`restic backup` to its own prefix in the same bucket. That snapshot is
authenticated but not encrypted; restic adds the encryption.

## Hardening for later

- Anyone with root on a host can read its R2 keys and delete that host's
  backups. An R2 bucket lock rule (for example 7 days) stops deletion of
  anything younger, at the cost of `prune` failing on very recent data; or add
  a second copy with `restic copy` to a bucket the servers cannot write.
- `catbird-backup check` reads back 5% of stored data weekly. Run
  `restic check --read-data` by hand every few months.

## Testing the script locally

```bash
export RESTIC_REPOSITORY=/tmp/repo RESTIC_PASSWORD_FILE=/tmp/pw
openssl rand -base64 32 > /tmp/pw && restic init
BACKUP_STAGING_DIR=/tmp/staging ops/backups/catbird-backup.sh backup
BACKUP_STAGING_DIR=/tmp/staging ops/backups/catbird-backup.sh verify
```

This needs a local PostgreSQL reachable as the `postgres` OS user.
