#!/usr/bin/env bash
set -euo pipefail

if (( $# != 3 )) || [[ -z $3 ]]; then
  echo "usage: $0 <alpha|beta|latest> <commit> <build date>" >&2
  exit 2
fi
channel=$1
commit=$2
built=$3

case $channel in
  alpha) summary='rolling prerelease, replaced on every push to master that passes CI and the release build' ;;
  beta) summary='prerelease, replaced when the owner publishes a commit to beta' ;;
  latest) summary='stable release, replaced when the owner publishes a commit to latest' ;;
  *)
    echo "unknown release channel '$channel': expected alpha, beta or latest" >&2
    exit 1
    ;;
esac
if [[ ! $commit =~ ^[0-9a-f]{40}$ ]]; then
  echo "'$commit' is not a full 40-character commit SHA in lowercase hex" >&2
  exit 1
fi

cat <<NOTES
Channel: \`$channel\` ($summary)
Commit: \`$commit\`
Built: $built

> [!WARNING]
> - The executables and the MSI are not code-signed. Check each download against its \`.sha256\` file; SmartScreen may warn.
> - TPM-backed keys, real browsers, physical Windows machines and Windows 7 are not yet verified on real hardware; see https://github.com/lukeo3o1/gateinto-dev/issues/23.
NOTES

if [[ $channel != latest ]]; then
  cat <<'NOTES'
> - The Windows 7 builds (`*-win7-windows-msvc-experimental.exe`) are experimental and use only the Microsoft Software Key Storage Provider, never a TPM.
NOTES
fi
