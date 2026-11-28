#!/usr/bin/env bash
# Check the exact SDK sources and locked Cargo graphs used by release builds.
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
workspace=$(dirname "$repo_root")
manifest="$repo_root/scripts/canonical-sibling-provenance.conf"
case "${1:-all}" in
  all) services=(catbird circle-appview) ;;
  catbird|circle-appview) services=("$1") ;;
  *) printf 'usage: %s [catbird|circle-appview]\n' "$0" >&2; exit 2 ;;
esac
if (( $# > 1 )); then printf 'usage: %s [catbird|circle-appview]\n' "$0" >&2; exit 2; fi

value() {
  local raw
  raw=$(awk -F= -v key="$1" '$1 == key {print $2}' "$manifest")
  if [[ -z "$raw" ]]; then printf 'missing provenance value: %s\n' "$1" >&2; return 1; fi
  printf '%s' "$raw"
}

check_sibling() {
  local sibling=$1 key=$2 expected actual changes
  expected=$(value "$key")
  if [[ ! "$expected" =~ ^[0-9a-f]{40}$ ]]; then
    printf '%s is not a 40-character commit id\n' "$key" >&2; return 1
  fi
  # A colocated jj working copy with an empty change has Git HEAD at its
  # parent. Plain Git checkouts used by a Linux release builder work too.
  actual=$(git -C "$workspace/$sibling" rev-parse HEAD)
  if [[ "$actual" != "$expected" ]]; then printf '%s provenance mismatch: expected %s, found %s\n' "$sibling" "$expected" "$actual" >&2; return 1; fi
  changes=$(git -C "$workspace/$sibling" status --porcelain --untracked-files=all)
  if [[ -n "$changes" ]]; then printf '%s sibling has uncommitted files\n' "$sibling" >&2; return 1; fi
  printf '  %s %s\n' "$sibling" "$actual"
}

check_sibling Petrel PETREL_COMMIT
check_sibling PetrelCatbird PETREL_CATBIRD_COMMIT

for service in "${services[@]}"; do
  case "$service" in catbird) key=CATBIRD_LOCK_SHA256 ;; circle-appview) key=CIRCLE_APPVIEW_LOCK_SHA256 ;; esac
  expected=$(value "$key")
  lock="$repo_root/$service/Cargo.lock"
  actual=$(shasum -a 256 "$lock" | awk '{print $1}')
  if [[ "$expected" != "$actual" ]]; then printf '%s/Cargo.lock provenance mismatch\n' "$service" >&2; exit 1; fi
  # Match the manifest paths of the resolved graph, including transitive SDK
  # crates. The lockfile alone cannot distinguish two local path dependencies.
  cargo metadata --locked --offline --manifest-path "$repo_root/$service/Cargo.toml" --format-version 1 |
    jq -er --arg petrel "$workspace/Petrel/rust" --arg overlay "$workspace/PetrelCatbird/rust" '
      .packages as $packages |
      if any($packages[]; (.name | startswith("jacquard")) or .name == "catbird-atproto" or .name == "atproto-spaces") then
        error("legacy SDK in resolved dependency graph")
      elif (["petrel-core", "petrel-catbird"] - [$packages[].name] | length) != 0 then
        error("missing Petrel dependency")
      else
        $packages[] | select(.name == "petrel" or (.name | startswith("petrel-"))) |
        (if .name == "petrel-catbird" then $overlay else $petrel end) as $base |
        if .manifest_path == ($base + "/" + .name + "/Cargo.toml") then empty
        else error("resolved " + .name + " outside its pinned sibling") end
      end, true' >/dev/null
  printf '  %s/Cargo.lock %s\n' "$service" "$actual"
done
printf 'verified\n'
