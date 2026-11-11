#!/bin/sh
set -eu

if [ "$#" -ne 0 ]; then
  echo 'usage: install.sh' >&2
  exit 2
fi
if [ "$(id -u)" -eq 0 ]; then
  echo 'install.sh: refusing to run as root: Gateinto installs for one user into ~/.local/bin, and as root or through sudo it would leave root-owned files there; run it as the user who uses Gateinto' >&2
  exit 1
fi
case ${HOME:-} in
  /*) [ -d "$HOME" ] ;;
  *) false ;;
esac || {
  echo 'install.sh: HOME is not an absolute path to an existing directory' >&2
  exit 1
}

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
source=$here/gateinto
bin=$HOME/.local/bin
target=$bin/gateinto

if [ ! -f "$source" ]; then
  echo 'install.sh: the gateinto executable is missing next to install.sh' >&2
  exit 1
fi
if [ -d "$target" ]; then
  echo 'install.sh: ~/.local/bin/gateinto is a directory; remove or rename it, then run install.sh again' >&2
  exit 1
fi
if [ ! -d "$bin" ]; then
  mkdir -p -- "$HOME/.local"
  mkdir -m 0755 -- "$bin"
fi

temp=$(mktemp -- "$bin/.gateinto.XXXXXX")
trap 'rm -f -- "$temp"' EXIT
trap 'exit 1' HUP INT TERM
cp -- "$source" "$temp"
chmod 0755 -- "$temp"
mv -f -- "$temp" "$target"
trap - EXIT HUP INT TERM

if ! "$target" uri register; then
  echo 'install.sh: installed ~/.local/bin/gateinto, but "gateinto uri register" failed; run install.sh again after fixing the error above' >&2
  exit 1
fi

case ":${PATH:-}:" in
  *":$bin:"* | *":$bin/:"*) ;;
  *) echo 'install.sh: warning: ~/.local/bin is not on PATH; add it to PATH or run ~/.local/bin/gateinto' >&2 ;;
esac
echo 'install.sh: installed ~/.local/bin/gateinto and registered the gateinto:// handler'
