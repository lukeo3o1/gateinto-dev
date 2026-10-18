#!/usr/bin/env bash
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
assets="$here/release-assets.sh"
notes="$here/release-notes.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0
sha=0123456789abcdef0123456789abcdef01234567
short=0123456789ab

pass() { echo "ok   $1"; }
fail() {
  echo "FAIL $1: $2"
  failures=$((failures + 1))
}

payloads() {
  local channel=$1
  printf '%s\n' \
    "gateinto-$short-x86_64-pc-windows-msvc.exe" \
    "gateinto-$short-x86_64-pc-windows-msvc.msi" \
    "gateinto-$short-i686-pc-windows-msvc.exe" \
    "gateinto-$short-i686-pc-windows-msvc.msi"
  if [[ $channel != latest ]]; then
    printf '%s\n' \
      "gateinto-$short-x86_64-win7-windows-msvc-experimental.exe" \
      "gateinto-$short-i686-win7-windows-msvc-experimental.exe"
  fi
}

dist() {
  local channel=$1 dir
  dir=$(mktemp -d "$work/dist.XXXXXX")
  while IFS= read -r name; do
    printf 'content of %s\n' "$name" > "$dir/$name"
    printf '%s  %s\n' "$(sha256sum "$dir/$name" | cut -d ' ' -f 1)" "$name" > "$dir/$name.sha256"
  done < <(payloads "$channel")
  printf '%s' "$dir"
}

expect_assets() {
  local name=$1 channel=$2 dir expected actual
  dir=$(dist "$channel")
  if ! "$assets" "$channel" "$sha" "$dir" > "$work/stdout" 2> "$work/stderr"; then
    fail "$name" "exited with an error: $(cat "$work/stderr")"
    return
  fi
  expected=$(while IFS= read -r file; do
    printf '%s\n%s.sha256\n%s\n%s.sha256\n' "$file" "$file" "${file/-$short/}" "${file/-$short/}"
  done < <(payloads "$channel") | sort)
  actual=$(find "$dir" -mindepth 1 -printf '%f\n' | sort)
  if [[ "$actual" != "$expected" ]]; then
    fail "$name" "files are"$'\n'"$actual"$'\n'"expected"$'\n'"$expected"
    return
  fi
  if ! (cd "$dir" && sha256sum --quiet -c ./*.sha256) > "$work/check" 2>&1; then
    fail "$name" "a checksum file does not verify: $(cat "$work/check")"
    return
  fi
  local fixed=gateinto-x86_64-pc-windows-msvc.exe
  if ! cmp -s "$dir/$fixed" "$dir/gateinto-$short-x86_64-pc-windows-msvc.exe" \
    || [[ "$(cut -d ' ' -f 3 "$dir/$fixed.sha256")" != "$fixed" ]]; then
    fail "$name" "$fixed is not a copy of the commit exe with its own checksum line"
    return
  fi
  pass "$name"
}

expect_assets_fail() {
  local name=$1 channel=$2 commit=$3 dir=$4 message=$5
  if "$assets" "$channel" "$commit" "$dir" > /dev/null 2> "$work/stderr"; then
    fail "$name" 'succeeded'
  elif ! grep -qF -- "$message" "$work/stderr"; then
    fail "$name" "stderr lacks '$message': $(cat "$work/stderr")"
  else
    pass "$name"
  fi
}

expect_assets 'alpha assets' alpha
expect_assets 'beta assets' beta
expect_assets 'latest assets' latest

expect_assets_fail 'unknown channel' stable "$sha" "$(dist latest)" 'unknown release channel'
expect_assets_fail 'short commit' alpha "$short" "$(dist alpha)" 'full 40-character commit'
expect_assets_fail 'uppercase commit' alpha "${sha^^}" "$(dist alpha)" 'full 40-character commit'
expect_assets_fail 'latest with Windows 7 builds' latest "$sha" "$(dist alpha)" 'unexpected file'
expect_assets_fail 'beta without Windows 7 builds' beta "$sha" "$(dist latest)" 'missing'

dir=$(dist alpha)
printf 'pdb\n' > "$dir/gateinto-$short-x86_64-pc-windows-msvc.wixpdb"
expect_assets_fail 'WiX debug file' alpha "$sha" "$dir" "unexpected file gateinto-$short-x86_64-pc-windows-msvc.wixpdb"

dir=$(dist alpha)
rm "$dir/gateinto-$short-x86_64-pc-windows-msvc.msi.sha256"
expect_assets_fail 'missing checksum file' alpha "$sha" "$dir" 'missing'

dir=$(dist latest)
printf 'tampered\n' >> "$dir/gateinto-$short-i686-pc-windows-msvc.exe"
expect_assets_fail 'checksum mismatch' latest "$sha" "$dir" 'does not match'

dir=$(dist latest)
printf '%s  %s\n' "$(sha256sum "$dir/gateinto-$short-i686-pc-windows-msvc.exe" | cut -d ' ' -f 1)" other.exe \
  > "$dir/gateinto-$short-i686-pc-windows-msvc.exe.sha256"
expect_assets_fail 'checksum line names another file' latest "$sha" "$dir" 'does not match'

dir=$(dist latest)
rm "$dir/gateinto-$short-i686-pc-windows-msvc.msi" "$dir/gateinto-$short-i686-pc-windows-msvc.msi.sha256"
expect_assets_fail 'missing x86 MSI' latest "$sha" "$dir" 'gateinto-0123456789ab-i686-pc-windows-msvc.msi is missing'

dir=$(dist latest)
other=fedcba9876543210fedcba9876543210fedcba98
expect_assets_fail 'files of another commit' latest "$other" "$dir" 'missing'

expect_notes() {
  local name=$1 channel=$2 present=$3 absent=$4 actual missing=()
  if ! actual=$("$notes" "$channel" "$sha" '2026-10-18 09:30 UTC' 2> "$work/stderr"); then
    fail "$name" "exited with an error: $(cat "$work/stderr")"
    return
  fi
  while IFS= read -r needle; do
    [[ -z "$needle" ]] || grep -qF -- "$needle" <<< "$actual" || missing+=("$needle")
  done <<< "$present"
  while IFS= read -r needle; do
    [[ -z "$needle" ]] || ! grep -qF -- "$needle" <<< "$actual" || missing+=("unexpected: $needle")
  done <<< "$absent"
  if (( ${#missing[@]} )); then
    fail "$name" "${missing[*]}"$'\n'"$actual"
  else
    pass "$name"
  fi
}

common=$'`'"$sha"$'`\n2026-10-18 09:30 UTC\nnot code-signed\nhttps://github.com/lukeo3o1/gateinto-dev/issues/23\nTPM\nreal browsers\nphysical Windows machines\nWindows 7'
win7=$'experimental\nSoftware Key Storage Provider'
expect_notes 'latest notes' latest "$common"$'\n`latest`' "$win7"
expect_notes 'beta notes' beta "$common"$'\n`beta`\n'"$win7" ''
expect_notes 'alpha notes' alpha "$common"$'\n`alpha`\n'"$win7" ''

expect_notes_fail() {
  local name=$1
  shift
  if "$notes" "$@" > /dev/null 2> "$work/stderr"; then
    fail "$name" 'succeeded'
  else
    pass "$name"
  fi
}

expect_notes_fail 'notes for an unknown channel' stable "$sha" '2026-10-18 09:30 UTC'
expect_notes_fail 'notes for a short commit' alpha "$short" '2026-10-18 09:30 UTC'
expect_notes_fail 'notes without a build date' alpha "$sha" ''
expect_notes_fail 'notes without arguments'

if (( failures )); then
  echo "$failures failed"
  exit 1
fi
echo 'all passed'
