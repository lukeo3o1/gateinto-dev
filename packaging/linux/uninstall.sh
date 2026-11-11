#!/bin/sh
set -eu

if [ "$#" -ne 0 ]; then
  echo 'usage: uninstall.sh' >&2
  exit 2
fi
if [ "$(id -u)" -eq 0 ]; then
  echo 'uninstall.sh: refusing to run as root: Gateinto is installed for one user in ~/.local/bin; run it as that user, not as root or through sudo' >&2
  exit 1
fi
case ${HOME:-} in
  /*) [ -d "$HOME" ] ;;
  *) false ;;
esac || {
  echo 'uninstall.sh: HOME is not an absolute path to an existing directory' >&2
  exit 1
}

target=$HOME/.local/bin/gateinto

if [ ! -e "$target" ] && [ ! -L "$target" ]; then
  echo 'uninstall.sh: ~/.local/bin/gateinto is not installed; nothing to stop, unregister or remove'
  exit 0
fi
if [ ! -e "$target" ]; then
  echo 'uninstall.sh: ~/.local/bin/gateinto is a symbolic link to a missing file; remove it by hand' >&2
  exit 1
fi
if ! "$target" stop --remove-stale-profiles; then
  echo 'uninstall.sh: "gateinto stop --remove-stale-profiles" failed, so nothing was removed; run uninstall.sh again after fixing the error above' >&2
  exit 1
fi
if ! "$target" uri unregister; then
  echo 'uninstall.sh: "gateinto uri unregister" failed, so ~/.local/bin/gateinto was kept; run uninstall.sh again after fixing the error above' >&2
  exit 1
fi
rm -f -- "$target"

echo 'uninstall.sh: removed ~/.local/bin/gateinto'
echo 'uninstall.sh: kept the configuration and the gateways added from links in the gateinto directory under XDG_CONFIG_HOME (by default ~/.config/gateinto); Gateinto has no device key on Linux yet'
