#!/usr/bin/env bash
set -euo pipefail

if (( $# != 4 )) || [[ -z $3 ]]; then
  echo "usage: $0 <alpha|beta|latest> <commit> <build date> <WinDivert manifest>" >&2
  exit 2
fi
channel=$1
commit=$2
built=$3
manifest=$4

case $channel in
  alpha) summary='rolling prerelease, replaced on every push to master that passes CI and the release build' ;;
  beta) summary='prerelease, replaced when the owner publishes a commit to beta' ;;
  latest) summary='prerelease, replaced when the owner publishes a commit to latest' ;;
  *)
    echo "unknown release channel '$channel': expected alpha, beta or latest" >&2
    exit 1
    ;;
esac
if [[ ! $commit =~ ^[0-9a-f]{40}$ ]]; then
  echo "'$commit' is not a full 40-character commit SHA in lowercase hex" >&2
  exit 1
fi
archive_pattern='^(https://github\.com/[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+)/releases/download/([A-Za-z0-9._-]+)/[^/]+$'
if ! read -r record archive_url _ < "$manifest" || [[ $record != archive || ! $archive_url =~ $archive_pattern ]]; then
  echo "$manifest does not start with a GitHub release archive" >&2
  exit 1
fi
windivert_repo=${BASH_REMATCH[1]}
windivert_tag=${BASH_REMATCH[2]}
windivert_version=${windivert_tag#v}

cat <<NOTES
Pre-release, not externally security reviewed.

Channel: \`$channel\` ($summary)
Commit: \`$commit\`
Built: $built

> [!WARNING]
> - The executables and the MSI are not code-signed. Check each download against its \`.sha256\` file; SmartScreen may warn.
> - TPM-backed keys, real browsers, physical Windows machines and Windows 7 are not yet verified on real hardware; see https://github.com/lukeo3o1/gateinto-dev/issues/23.
> - The Linux tarball (\`gateinto-x86_64-unknown-linux-gnu.tar.gz\`) and its \`install.sh\` and \`uninstall.sh\` are not yet verified on a real Linux desktop. There is no device key on Linux yet, so Gateinto connects from Linux without a device certificate.
NOTES

if [[ $channel != latest ]]; then
  cat <<'NOTES'
> - The 32-bit Windows 7 build (`gateinto-i686-win7-windows-msvc-experimental.exe`) is experimental and can use only the Microsoft Software Key Storage Provider, because Windows 7 has no TPM key storage provider.
NOTES
fi

cat <<NOTES

The Windows MSI downloads include WinDivert $windivert_version. The corresponding source is available from upstream. [WinDivert $windivert_version source]($windivert_repo/archive/refs/tags/$windivert_tag.tar.gz)
NOTES
