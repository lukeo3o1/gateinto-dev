#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )); then
  echo "usage: $0 <gateinto Linux .tar.gz>" >&2
  exit 2
fi
tarball=$1

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
home=$work/home
mkdir "$home" "$work/package"
tar -xzf "$tarball" -C "$work/package"
shopt -s nullglob dotglob
package=("$work/package"/*)
if (( ${#package[@]} != 1 )) || [[ ! -d ${package[0]} || -L ${package[0]} ]]; then
  echo 'the tarball must hold exactly one top-level directory' >&2
  exit 1
fi
installed=$home/.local/bin/gateinto
desktop=$home/.local/share/applications/gateinto.desktop

run() {
  env -i HOME="$home" PATH=/usr/bin:/bin "$@"
}

run "${package[0]}/install.sh"
run "$installed" status | tee "$work/status"
if ! grep -qxF "uri-handler: gateinto: \"$installed\" open -- %u" "$work/status"; then
  echo 'the installed gateinto:// handler does not run ~/.local/bin/gateinto' >&2
  exit 1
fi
run "${package[0]}/uninstall.sh"
if [[ -e $installed || -e $desktop ]]; then
  echo 'uninstall.sh left ~/.local/bin/gateinto or the desktop file' >&2
  exit 1
fi
echo 'installed and uninstalled'
