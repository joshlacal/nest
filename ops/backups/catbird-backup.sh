#!/usr/bin/env bash
# Encrypted, off-server backups for the PostgreSQL databases on one Catbird host.
#
# For every database in the local PostgreSQL cluster (or the list in
# BACKUP_DATABASES) this writes a pg_dump custom-format archive to a private
# staging directory, checks it, and stores it in a restic repository. restic
# encrypts everything client side, compresses it and de-duplicates it against
# earlier days, so only changed data is uploaded. The cluster's roles and
# grants are stored too (pg_dumpall --globals-only, no role passwords).
#
# Optionally (BACKUP_JOURNAL_DIR set) it also takes a consistent copy of the
# mls-ds recovery-share erasure journal into a SECOND restic repository with
# its own password, as docs/recovery-shares.md in mls-ds requires.
#
# Then it applies the retention policy and prunes. See README.md.
#
# Usage: catbird-backup.sh [backup|prune|check|verify]
#   backup  dump, upload and apply retention (default; what the timer runs)
#   prune   apply retention only
#   check   restic integrity check of a sample of the repository data
#   verify  restore the newest dump of every database into a scratch database,
#           compare table counts, then drop the scratch database
#
# Configuration comes from the environment (the systemd unit loads
# /etc/catbird-backup/backup.env). Every variable is documented in
# backup.env.example.

set -Eeuo pipefail
umask 077

readonly SCRIPT_NAME="catbird-backup"
MODE="${1:-backup}"

log() { printf '%s %s: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$SCRIPT_NAME" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# ---- configuration -------------------------------------------------------

: "${RESTIC_REPOSITORY:?set RESTIC_REPOSITORY (see backup.env.example)}"
if [[ -z "${RESTIC_PASSWORD:-}" && -z "${RESTIC_PASSWORD_FILE:-}" ]]; then
  die "set RESTIC_PASSWORD_FILE (or RESTIC_PASSWORD)"
fi

BACKUP_HOST_TAG="${BACKUP_HOST_TAG:-$(hostname -s)}"
BACKUP_STAGING_DIR="${BACKUP_STAGING_DIR:-/var/lib/catbird-backup/staging}"
# Space-separated list. Empty means every non-template database except "postgres".
BACKUP_DATABASES="${BACKUP_DATABASES:-}"
# Space-separated databases to leave out of automatic discovery.
BACKUP_EXCLUDE_DATABASES="${BACKUP_EXCLUDE_DATABASES:-}"
# How to reach PostgreSQL. The default runs the client tools as the local
# "postgres" OS user over the Unix socket (peer authentication), which is how a
# Debian/Ubuntu postgresql package is set up. For PostgreSQL in Docker set e.g.
#   BACKUP_PG_EXEC="docker exec -i -u postgres catbird-postgres"
BACKUP_PG_EXEC="${BACKUP_PG_EXEC:-runuser -u postgres --}"

KEEP_DAILY="${BACKUP_KEEP_DAILY:-7}"
KEEP_WEEKLY="${BACKUP_KEEP_WEEKLY:-4}"
KEEP_MONTHLY="${BACKUP_KEEP_MONTHLY:-0}"

# Optional mls-ds recovery-share erasure journal (see README.md).
BACKUP_JOURNAL_DIR="${BACKUP_JOURNAL_DIR:-}"
BACKUP_JOURNAL_STOP_UNIT="${BACKUP_JOURNAL_STOP_UNIT:-}"
JOURNAL_RESTIC_REPOSITORY="${JOURNAL_RESTIC_REPOSITORY:-}"
JOURNAL_RESTIC_PASSWORD_FILE="${JOURNAL_RESTIC_PASSWORD_FILE:-}"

# Optional dead-man's-switch URL (for example a healthchecks.io check). The
# script pings URL/start, URL on success and URL/fail on failure.
BACKUP_HEALTHCHECK_URL="${BACKUP_HEALTHCHECK_URL:-}"

read -r -a PG_EXEC <<<"$BACKUP_PG_EXEC"

ping_health() {
  [[ -n "$BACKUP_HEALTHCHECK_URL" ]] || return 0
  curl -fsS -m 10 --retry 3 -o /dev/null "${BACKUP_HEALTHCHECK_URL}${1:-}" || log "healthcheck ping failed (ignored)"
}

on_error() {
  local status=$?
  log "failed (exit $status) at line ${BASH_LINENO[0]}"
  ping_health /fail
  exit "$status"
}
trap on_error ERR

cleanup() { rm -rf -- "${STAGING_RUN:-}"; }
trap cleanup EXIT

require() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }

pg() { "${PG_EXEC[@]}" "$@"; }

psql_value() {
  # $1 database, $2 SQL. Prints the single unaligned result.
  pg psql -X -v ON_ERROR_STOP=1 -At -d "$1" -c "$2"
}

list_databases() {
  if [[ -n "$BACKUP_DATABASES" ]]; then
    tr ' ' '\n' <<<"$BACKUP_DATABASES" | sed '/^$/d'
    return
  fi
  local db skip excluded
  while IFS= read -r db; do
    skip=0
    for excluded in $BACKUP_EXCLUDE_DATABASES; do
      [[ "$db" == "$excluded" ]] && skip=1
    done
    # Scratch databases made by `verify` are never backed up.
    [[ "$db" == restore_check_* ]] && skip=1
    (( skip )) || printf '%s\n' "$db"
  done < <(psql_value postgres \
    "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate AND datname <> 'postgres' ORDER BY datname")
}

restic_db() { restic "$@"; }

restic_journal() {
  # Separate repository and password: the journal must be readable by fewer
  # people than the database dumps (mls-ds docs/recovery-shares.md).
  env -u RESTIC_PASSWORD \
    RESTIC_REPOSITORY="$JOURNAL_RESTIC_REPOSITORY" \
    RESTIC_PASSWORD_FILE="$JOURNAL_RESTIC_PASSWORD_FILE" \
    restic "$@"
}

# ---- backup ---------------------------------------------------------------

dump_database() {
  local db="$1" out="$STAGING_RUN/$1.dump"
  log "dumping $db"
  # -Fc: custom format, restorable with pg_restore (selective, parallel).
  # -Z0: no compression here; restic compresses and can then de-duplicate
  #      unchanged table data between days.
  pg pg_dump -Fc -Z0 --no-password -d "$db" >"$out"
  # A dump that pg_restore cannot list is not a backup. Only a complete,
  # readable file is handed to restic, so a failed dump never becomes a
  # snapshot.
  local tables
  tables="$(pg pg_restore --list <"$out" | grep -c ' TABLE DATA ' || true)"
  pg pg_restore --list <"$out" >/dev/null || die "pg_restore cannot read the dump of $db"
  log "$db: $(du -h "$out" | cut -f1) uncompressed, $tables tables with data"
  # --stdin-filename gives every snapshot of this database the same path
  # (/<db>.dump), which is what restore and verify ask for.
  restic_db backup --quiet \
    --host "$BACKUP_HOST_TAG" \
    --tag catbird-db --tag "db:$db" \
    --stdin --stdin-filename "$db.dump" <"$out"
  rm -f -- "$out"
}

dump_globals() {
  local out="$STAGING_RUN/globals.sql"
  log "dumping roles and grants"
  # --no-role-passwords: password hashes stay out of backups; set them again
  # from the secret store (Doppler) after a restore.
  pg pg_dumpall --globals-only --no-role-passwords >"$out"
  [[ -s "$out" ]] || die "globals dump is empty"
  restic_db backup --quiet --host "$BACKUP_HOST_TAG" --tag catbird-db --tag globals \
    --stdin --stdin-filename globals.sql <"$out"
  rm -f -- "$out"
}

backup_journal() {
  [[ -n "$BACKUP_JOURNAL_DIR" ]] || return 0
  [[ -n "$JOURNAL_RESTIC_REPOSITORY" && -n "$JOURNAL_RESTIC_PASSWORD_FILE" ]] \
    || die "BACKUP_JOURNAL_DIR is set but JOURNAL_RESTIC_REPOSITORY / JOURNAL_RESTIC_PASSWORD_FILE are not"
  [[ -n "$BACKUP_JOURNAL_STOP_UNIT" ]] \
    || die "BACKUP_JOURNAL_STOP_UNIT must name the mls-ds unit: the journal is copied with its writer stopped"
  [[ -d "$BACKUP_JOURNAL_DIR" ]] || die "journal directory $BACKUP_JOURNAL_DIR does not exist"

  # A fixed path, so every snapshot restores to the same place.
  local copy="$BACKUP_STAGING_DIR/recovery-journal"
  rm -rf -- "$copy"
  log "stopping $BACKUP_JOURNAL_STOP_UNIT for a consistent journal copy"
  systemctl stop "$BACKUP_JOURNAL_STOP_UNIT"
  # Restart the service whatever happens to the copy.
  local copied=0
  if cp -a -- "$BACKUP_JOURNAL_DIR" "$copy"; then copied=1; fi
  systemctl start "$BACKUP_JOURNAL_STOP_UNIT"
  log "restarted $BACKUP_JOURNAL_STOP_UNIT"
  (( copied )) || die "copying the journal directory failed"

  restic_journal backup --quiet --host "$BACKUP_HOST_TAG" --tag recovery-journal "$copy"
  rm -rf -- "$copy"
}

apply_retention() {
  log "applying retention: $KEEP_DAILY daily, $KEEP_WEEKLY weekly, $KEEP_MONTHLY monthly"
  local keep=(--keep-daily "$KEEP_DAILY" --keep-weekly "$KEEP_WEEKLY")
  (( KEEP_MONTHLY > 0 )) && keep+=(--keep-monthly "$KEEP_MONTHLY")
  # --group-by host,tags keeps a separate history for each database.
  restic_db forget --quiet --host "$BACKUP_HOST_TAG" --tag catbird-db \
    --group-by host,tags "${keep[@]}" --prune
  if [[ -n "$BACKUP_JOURNAL_DIR" ]]; then
    restic_journal forget --quiet --host "$BACKUP_HOST_TAG" --tag recovery-journal \
      --group-by host,tags "${keep[@]}" --prune
  fi
}

run_backup() {
  ping_health /start
  mkdir -p -- "$BACKUP_STAGING_DIR"
  chmod 0700 -- "$BACKUP_STAGING_DIR"
  STAGING_RUN="$(mktemp -d "$BACKUP_STAGING_DIR/run.XXXXXX")"
  # pg_dump runs as the postgres user and writes through our shell, so the
  # directory only needs to be ours.

  local dbs=() db
  mapfile -t dbs < <(list_databases)
  (( ${#dbs[@]} > 0 )) || die "no databases found to back up"
  log "databases: ${dbs[*]}"

  dump_globals
  for db in "${dbs[@]}"; do
    dump_database "$db"
  done
  backup_journal
  apply_retention
  log "backup finished"
  ping_health
}

# ---- verify ---------------------------------------------------------------

run_verify() {
  mkdir -p -- "$BACKUP_STAGING_DIR"
  STAGING_RUN="$(mktemp -d "$BACKUP_STAGING_DIR/verify.XXXXXX")"
  local dbs=() db scratch expected actual failures=0
  mapfile -t dbs < <(list_databases)
  for db in "${dbs[@]}"; do
    scratch="restore_check_${db}"
    log "verifying newest backup of $db in scratch database $scratch"
    restic_db dump --host "$BACKUP_HOST_TAG" --tag "db:$db" latest "/$db.dump" >"$STAGING_RUN/$db.dump" \
      || { log "no restorable snapshot for $db"; failures=$((failures + 1)); continue; }
    expected="$(pg pg_restore --list <"$STAGING_RUN/$db.dump" | grep -c ' TABLE DATA ' || true)"
    pg dropdb --if-exists "$scratch"
    pg createdb "$scratch"
    # --no-owner/--no-privileges: the scratch copy need not recreate grants.
    if ! pg pg_restore --no-owner --no-privileges --exit-on-error -d "$scratch" <"$STAGING_RUN/$db.dump"; then
      log "restore of $db FAILED"
      failures=$((failures + 1))
    else
      actual="$(psql_value "$scratch" \
        "SELECT count(*) FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')")"
      log "$db restored: $actual tables ($expected with data in the dump)"
    fi
    pg dropdb --if-exists "$scratch"
    rm -f -- "$STAGING_RUN/$db.dump"
  done
  (( failures == 0 )) || die "$failures database(s) failed verification"
  log "verify finished: every database restored"
}

# ---- main -----------------------------------------------------------------

require restic
case "$MODE" in
  backup) run_backup ;;
  prune)  apply_retention ;;
  check)  restic_db check --read-data-subset=5% ;;
  verify) run_verify ;;
  *) die "unknown mode: $MODE (use backup, prune, check or verify)" ;;
esac
