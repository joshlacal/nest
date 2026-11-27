#!/usr/bin/env bash
# Exercise the release check against isolated service manifests beside the pinned SDKs.
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
mkdir "$fixture/nest"
cp -R "$repo/scripts" "$fixture/nest/"
for service in catbird circle-appview; do
  mkdir -p "$fixture/nest/$service/src"
  cp "$repo/$service/"Cargo.{toml,lock} "$fixture/nest/$service/"
  touch "$fixture/nest/$service/src/main.rs"
done
ln -s "$repo/../Petrel" "$fixture/Petrel"
ln -s "$repo/../PetrelCatbird" "$fixture/PetrelCatbird"
manifest="$fixture/nest/scripts/canonical-sibling-provenance.conf"
verify="$fixture/nest/scripts/check-canonical-sibling-provenance.sh"

"$verify"
expect_failure() {
  local reason=$1
  shift
  if "$verify" "$@" >"$fixture/stdout" 2>"$fixture/stderr"; then
    printf 'expected provenance failure: %s\n' "$reason" >&2; exit 1
  fi
  grep -Fq "$reason" "$fixture/stderr" || { cat "$fixture/stderr" >&2; exit 1; }
}
expect_failure 'usage:' --manifest /tmp/untrusted
for pair in 'PETREL_COMMIT Petrel' 'PETREL_CATBIRD_COMMIT PetrelCatbird'; do
  read -r key name <<< "$pair"
  sed "s/^${key}=.*/${key}=0000000000000000000000000000000000000000/" "$repo/scripts/canonical-sibling-provenance.conf" >"$manifest"
  expect_failure "$name provenance mismatch"
done
cp "$repo/scripts/canonical-sibling-provenance.conf" "$manifest"
for service in catbird circle-appview; do
  printf '\n' >>"$fixture/nest/$service/Cargo.lock"
  expect_failure "$service/Cargo.lock provenance mismatch" "$service"
  cp "$repo/$service/Cargo.lock" "$fixture/nest/$service/Cargo.lock"
done
ln -s "$repo/../Petrel" "$fixture/Petrel-alt"
sed 's#../../Petrel/rust#../../Petrel-alt/rust#g' "$repo/catbird/Cargo.toml" >"$fixture/nest/catbird/Cargo.toml"
expect_failure 'outside its pinned sibling' catbird
printf 'canonical sibling provenance guard test passed\n'
