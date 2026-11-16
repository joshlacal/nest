#!/usr/bin/env bash
# Exercises scripts/check-canonical-sibling-provenance.sh against a copy of
# this checkout next to the real catbird-atproto sibling, then checks that each
# recorded value is enforced.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
sibling=$(cd "$repo_root/../catbird-atproto" && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT

copy_checkout() {
  mkdir -p "$1"
  rsync -a --exclude target --exclude _trash --exclude .jj --exclude .git "$repo_root/" "$1/"
}

# The manifest must be a tracked file, not one an ignore rule drops.
if git -C "$repo_root" check-ignore -q scripts/canonical-sibling-provenance.conf; then
  printf 'scripts/canonical-sibling-provenance.conf is ignored and would not be committed\n' >&2
  exit 1
fi

copy_checkout "$fixture/ws/nest"
ln -s "$sibling" "$fixture/ws/catbird-atproto"

(cd "$fixture/ws/nest" && scripts/check-canonical-sibling-provenance.sh)

if (cd "$fixture/ws/nest" && scripts/check-canonical-sibling-provenance.sh --manifest /tmp/external.env); then
  printf 'expected an argument to be refused\n' >&2
  exit 1
fi

expect_failure() {
  local name=$1 want=$2 err="$fixture/$1.err"
  if (cd "$fixture/ws/$name" && scripts/check-canonical-sibling-provenance.sh) 2>"$err"; then
    printf 'expected negative case %s to fail\n' "$name" >&2
    exit 1
  fi
  if ! grep -Fq "$want" "$err"; then
    printf 'negative case %s failed for the wrong reason (wanted: %s)\n' "$name" "$want" >&2
    cat "$err" >&2
    exit 1
  fi
}

manifest_case() {
  local name=$1 sed_expr=$2 want=$3 env_file
  copy_checkout "$fixture/ws/$name"
  env_file="$fixture/ws/$name/scripts/canonical-sibling-provenance.conf"
  sed "$sed_expr" "$fixture/ws/nest/scripts/canonical-sibling-provenance.conf" >"$env_file"
  if cmp -s "$env_file" "$fixture/ws/nest/scripts/canonical-sibling-provenance.conf"; then
    printf 'negative case %s did not change the manifest\n' "$name" >&2
    exit 1
  fi
  expect_failure "$name" "$want"
}

zero=0000000000000000000000000000000000000000
manifest_case wrong-commit "s/^CATBIRD_ATPROTO_COMMIT=.*/CATBIRD_ATPROTO_COMMIT=$zero/" \
  'catbird-atproto provenance mismatch'
manifest_case missing-commit '/^CATBIRD_ATPROTO_COMMIT=/d' \
  'missing provenance value: CATBIRD_ATPROTO_COMMIT'
manifest_case short-commit 's/^CATBIRD_ATPROTO_COMMIT=\(.\{12\}\).*/CATBIRD_ATPROTO_COMMIT=\1/' \
  'is not a 40-character commit id'
manifest_case wrong-catbird-lock "s/^CATBIRD_LOCK_SHA256=.*/CATBIRD_LOCK_SHA256=${zero}${zero:0:24}/" \
  'catbird/Cargo.lock provenance mismatch'
manifest_case wrong-circle-lock "s/^CIRCLE_APPVIEW_LOCK_SHA256=.*/CIRCLE_APPVIEW_LOCK_SHA256=${zero}${zero:0:24}/" \
  'circle-appview/Cargo.lock provenance mismatch'

# A crate that resolves catbird-atproto from anywhere but the checked sibling fails.
copy_checkout "$fixture/ws/redirected"
ln -s "$sibling" "$fixture/ws/catbird-atproto-alt"
sed 's#"\.\./\.\./catbird-atproto#"../../catbird-atproto-alt#g' \
  "$fixture/ws/redirected/circle-appview/Cargo.toml" >"$fixture/ws/redirected/circle-appview/Cargo.toml.tmp"
mv "$fixture/ws/redirected/circle-appview/Cargo.toml.tmp" "$fixture/ws/redirected/circle-appview/Cargo.toml"
if cmp -s "$fixture/ws/redirected/circle-appview/Cargo.toml" "$repo_root/circle-appview/Cargo.toml"; then
  printf 'redirect case did not change the manifest\n' >&2
  exit 1
fi
expect_failure redirected 'resolved catbird-atproto outside'

printf 'canonical sibling provenance guard test passed\n'
