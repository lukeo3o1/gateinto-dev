#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )); then
  echo "usage: $0 <file>" >&2
  exit 2
fi
path=$1

hash=$(sha256sum -- "$path" | cut -d ' ' -f 1)
printf '%s  %s\n' "$hash" "${path##*/}" > "$path.sha256"
cat -- "$path.sha256"
