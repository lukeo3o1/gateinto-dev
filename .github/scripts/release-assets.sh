#!/usr/bin/env bash
set -euo pipefail

if (( $# != 3 )); then
  echo "usage: $0 <alpha|beta|latest> <commit> <dir>" >&2
  exit 2
fi
channel=$1
commit=$2
dir=$3

case $channel in
  alpha | beta | latest) ;;
  *)
    echo "unknown release channel '$channel': expected alpha, beta or latest" >&2
    exit 1
    ;;
esac
if [[ ! $commit =~ ^[0-9a-f]{40}$ ]]; then
  echo "'$commit' is not a full 40-character commit SHA in lowercase hex" >&2
  exit 1
fi
short=${commit:0:12}

payloads=(
  "gateinto-$short-x86_64-pc-windows-msvc.exe"
  "gateinto-$short-x86_64-pc-windows-msvc.msi"
  "gateinto-$short-i686-pc-windows-msvc.exe"
  "gateinto-$short-i686-pc-windows-msvc.msi"
)
if [[ $channel != latest ]]; then
  payloads+=(
    "gateinto-$short-x86_64-win7-windows-msvc-experimental.exe"
    "gateinto-$short-i686-win7-windows-msvc-experimental.exe"
  )
fi

declare -A expected=()
for name in "${payloads[@]}"; do
  expected[$name]=1
  expected[$name.sha256]=1
done

status=0
for path in "$dir"/* "$dir"/.[!.]*; do
  [[ -e $path ]] || continue
  name=${path##*/}
  if [[ -z ${expected[$name]:-} ]]; then
    echo "unexpected file $name in $dir for the $channel release" >&2
    status=1
  fi
done
for name in "${!expected[@]}"; do
  if [[ ! -f $dir/$name ]]; then
    echo "$name is missing from $dir" >&2
    status=1
  fi
done
(( status == 0 )) || exit 1

for name in "${payloads[@]}"; do
  hash=$(sha256sum "$dir/$name" | cut -d ' ' -f 1)
  if [[ "$(cat "$dir/$name.sha256")" != "$hash  $name" ]]; then
    echo "$name.sha256 does not match $name (expected '$hash  $name')" >&2
    exit 1
  fi
  fixed=${name/-$short/}
  cp "$dir/$name" "$dir/$fixed"
  printf '%s  %s\n' "$hash" "$fixed" > "$dir/$fixed.sha256"
done

find "$dir" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort
