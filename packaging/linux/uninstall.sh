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
unit=$HOME/.config/systemd/user/gateinto-agent.service

if [ ! -e "$target" ] && [ ! -L "$target" ]; then
  echo 'uninstall.sh: ~/.local/bin/gateinto is not installed; nothing to stop, unregister or remove'
  exit 0
fi
if [ ! -e "$target" ]; then
  echo 'uninstall.sh: ~/.local/bin/gateinto is a symbolic link to a missing file; remove it by hand' >&2
  exit 1
fi
if [ -L "$unit" ] && [ ! -e "$unit" ]; then
  echo 'uninstall.sh: ~/.config/systemd/user/gateinto-agent.service is a symbolic link to a missing file; run "systemctl --user stop gateinto-agent" if it is running, remove by hand that link and, if present, ~/.config/systemd/user/graphical-session.target.wants/gateinto-agent.service, then run uninstall.sh again' >&2
  exit 1
fi
has_unit=false
if [ -e "$unit" ]; then
  has_unit=true
fi
systemctl=$(command -v systemctl || true)
case $systemctl in
  /*) ;;
  *) systemctl= ;;
esac
if "$has_unit" && [ -n "$systemctl" ] && ! "$systemctl" --user disable --now gateinto-agent.service; then
  echo 'uninstall.sh: "systemctl --user disable --now gateinto-agent.service" failed, so nothing was removed; run uninstall.sh again after fixing the error above' >&2
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
if "$has_unit"; then
  rm -f -- "$unit"
  echo 'uninstall.sh: removed ~/.config/systemd/user/gateinto-agent.service'
  if [ -n "$systemctl" ] && ! "$systemctl" --user daemon-reload; then
    echo 'uninstall.sh: warning: "systemctl --user daemon-reload" failed after the unit was removed; run it after fixing the error above' >&2
  fi
fi
rm -f -- "$target"

echo 'uninstall.sh: removed ~/.local/bin/gateinto'
echo 'uninstall.sh: kept the configuration and the gateways added from links in the gateinto directory under XDG_CONFIG_HOME (by default ~/.config/gateinto); Gateinto has no device key on Linux yet'
