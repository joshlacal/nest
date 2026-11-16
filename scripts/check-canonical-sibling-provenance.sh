#!/usr/bin/env bash
# Verifies that both nest crates build against the exact catbird-atproto
# commit recorded in scripts/canonical-sibling-provenance.conf, and that each
# tracked Cargo.lock matches its recorded hash. Run before every release build.
set -euo pipefail

# No overrides are accepted: provenance comes only from this checkout and the
# sibling Cargo resolves from the crates' own manifests.
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
manifest="$repo_root/scripts/canonical-sibling-provenance.conf"

if [[ $# -ne 0 ]]; then
  printf 'usage: %s\n' "$0" >&2
  exit 2
fi
[[ -f "$manifest" ]] || { printf 'provenance manifest not found: %s\n' "$manifest" >&2; exit 1; }

manifest_value() {
  local key=$1 value
  value=$(awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); exit }' "$manifest")
  [[ -n "$value" ]] || { printf 'missing provenance value: %s\n' "$key" >&2; exit 1; }
  printf '%s' "$value"
}

sibling_rel=$(manifest_value CATBIRD_ATPROTO_SIBLING_DIR)
expected_commit=$(manifest_value CATBIRD_ATPROTO_COMMIT)
if [[ ! "$expected_commit" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'CATBIRD_ATPROTO_COMMIT is not a 40-character commit id: %s\n' "$expected_commit" >&2
  exit 1
fi
sibling="$repo_root/$sibling_rel"
[[ -d "$sibling" ]] || { printf 'catbird-atproto sibling not found: %s\n' "$sibling" >&2; exit 1; }
sibling=$(cd "$sibling" && pwd)

check_lock() {
  local crate=$1 key=$2 expected actual
  expected=$(manifest_value "$key")
  [[ -f "$repo_root/$crate/Cargo.lock" ]] || { printf 'tracked lock not found: %s/Cargo.lock\n' "$crate" >&2; exit 1; }
  actual=$(shasum -a 256 "$repo_root/$crate/Cargo.lock" | awk '{print $1}')
  if [[ "$actual" != "$expected" ]]; then
    printf '%s/Cargo.lock provenance mismatch: expected %s, got %s\n' "$crate" "$expected" "$actual" >&2
    exit 1
  fi
  printf '  %s/Cargo.lock sha256=%s\n' "$crate" "$actual"
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

check_resolution() {
  local crate=$1 pkg resolved
  if ! CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo metadata --manifest-path "$repo_root/$crate/Cargo.toml" \
    --format-version 1 --locked --offline >"$tmp/$crate.json" 2>"$tmp/$crate.err"; then
    printf 'locked Cargo metadata failed for %s; refusing unverified sibling provenance\n' "$crate" >&2
    cat "$tmp/$crate.err" >&2
    exit 1
  fi
  for pkg in catbird-atproto atproto-spaces; do
    resolved=$(jq -er --arg n "$pkg" \
      '[.packages[] | select(.name == $n) | .manifest_path] | if length == 1 then .[0] else error("expected exactly one package named " + $n) end' \
      "$tmp/$crate.json")
    if [[ "$resolved" != "$sibling"/* ]]; then
      printf '%s resolved %s outside the checked sibling\nexpected under: %s\nactual:         %s\n' \
        "$crate" "$pkg" "$sibling" "$resolved" >&2
      exit 1
    fi
  done
}

tree_of() {
  local id
  id=$(cd "$sibling" && jj --ignore-working-copy log -r "$1" --no-graph -T 'commit_id')
  (cd "$sibling" && jj --ignore-working-copy debug object commit "$id") |
    awk '/TreeId\(/ { getline; gsub(/[",[:space:]]/, ""); print; exit }'
}

printf 'nest canonical sibling provenance\n'
check_lock catbird CATBIRD_LOCK_SHA256
check_lock circle-appview CIRCLE_APPVIEW_LOCK_SHA256
check_resolution catbird
check_resolution circle-appview

# The sibling's working copy must be an empty change on top of the recorded
# commit. The empty working-copy commit id itself is not pinned, because jj
# rewrites it on every snapshot; its parent commit and tree are stable.
status_output=$(cd "$sibling" && jj --ignore-working-copy st)
if ! grep -Fq 'The working copy has no changes.' <<<"$status_output"; then
  printf 'catbird-atproto sibling is dirty or conflicted: %s\n%s\n' "$sibling" "$status_output" >&2
  exit 1
fi
actual_parent=$(cd "$sibling" && jj --ignore-working-copy log -r '@-' --no-graph -T 'commit_id')
if [[ "$actual_parent" != "$expected_commit" ]]; then
  printf 'catbird-atproto provenance mismatch\nexpected commit: %s\nactual @-:       %s\n' \
    "$expected_commit" "$actual_parent" >&2
  exit 1
fi
parent_tree=$(tree_of "$expected_commit")
child_tree=$(tree_of '@')
if [[ -z "$parent_tree" || "$parent_tree" != "$child_tree" ]]; then
  printf 'catbird-atproto working-copy tree %s differs from recorded commit tree %s\n' \
    "$child_tree" "$parent_tree" >&2
  exit 1
fi
printf '  catbird-atproto commit=%s tree=%s root=%s\n' "$expected_commit" "$parent_tree" "$sibling"
printf 'verified\n'
