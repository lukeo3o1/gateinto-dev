#!/usr/bin/env bash
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
assets="$here/release-assets.sh"
notes="$here/release-notes.sh"
tarball="$here/linux-tarball.sh"
sha256="$here/write-sha256.sh"
packaging=$here/../../packaging/linux
licenses=$here/../..
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
    "gateinto-$short-i686-pc-windows-msvc.msi" \
    "gateinto-$short-x86_64-unknown-linux-gnu.tar.gz"
  if [[ $channel != latest ]]; then
    printf '%s\n' "gateinto-$short-i686-win7-windows-msvc-experimental.exe"
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
expect_assets_fail 'latest with Windows 7 build' latest "$sha" "$(dist alpha)" 'unexpected file'
expect_assets_fail 'beta without Windows 7 build' beta "$sha" "$(dist latest)" 'missing'

dir=$(dist alpha)
printf 'pdb\n' > "$dir/gateinto-$short-x86_64-pc-windows-msvc.wixpdb"
expect_assets_fail 'WiX debug file' alpha "$sha" "$dir" "unexpected file gateinto-$short-x86_64-pc-windows-msvc.wixpdb"

dir=$(dist alpha)
printf 'exe\n' > "$dir/gateinto-$short-x86_64-win7-windows-msvc-experimental.exe"
expect_assets_fail 'x64 Windows 7 build' alpha "$sha" "$dir" \
  "unexpected file gateinto-$short-x86_64-win7-windows-msvc-experimental.exe"

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

dir=$(dist alpha)
rm "$dir/gateinto-$short-x86_64-unknown-linux-gnu.tar.gz" "$dir/gateinto-$short-x86_64-unknown-linux-gnu.tar.gz.sha256"
expect_assets_fail 'missing Linux tarball' alpha "$sha" "$dir" \
  'gateinto-0123456789ab-x86_64-unknown-linux-gnu.tar.gz is missing'

dir=$(dist latest)
other=fedcba9876543210fedcba9876543210fedcba98
expect_assets_fail 'files of another commit' latest "$other" "$dir" 'missing'

name=gateinto-$short-x86_64-unknown-linux-gnu.tar.gz
dir=$(mktemp -d "$work/sha256.XXXXXX")
printf 'payload\n' > "$dir/$name"
printf '%s  %s\n' "$(sha256sum "$dir/$name" | cut -d ' ' -f 1)" "$name" > "$work/expected.sha256"
if ! output=$("$sha256" "$dir/$name" 2> "$work/stderr"); then
  fail 'SHA-256 file' "exited with an error: $(cat "$work/stderr")"
elif ! cmp -s "$dir/$name.sha256" "$work/expected.sha256"; then
  fail 'SHA-256 file' "wrote '$(cat "$dir/$name.sha256")', expected '$(cat "$work/expected.sha256")'"
elif [[ $output != "$(cat "$work/expected.sha256")" ]]; then
  fail 'SHA-256 file' "printed '$output'"
else
  pass 'SHA-256 file'
fi

if "$sha256" "$dir/missing.tar.gz" > /dev/null 2>&1; then
  fail 'SHA-256 file of a missing file' 'succeeded'
elif [[ -e $dir/missing.tar.gz.sha256 ]]; then
  fail 'SHA-256 file of a missing file' 'wrote a checksum file'
else
  pass 'SHA-256 file of a missing file'
fi

euid=$(id -u)
user_uid=$euid
if (( euid == 0 )); then
  user_uid=65534
  chmod 0711 "$work"
fi
owned() {
  if (( euid == 0 )); then
    chown -R 65534:65534 "$@"
  fi
}
as_user() {
  if (( euid == 0 )); then
    setpriv --reuid=65534 --regid=65534 --clear-groups "$@"
  else
    "$@"
  fi
}
as_root() {
  if (( euid == 0 )); then
    "$@"
  else
    sudo -n "$@"
  fi
}
can_root() {
  (( euid == 0 )) || sudo -n true 2> /dev/null
}

area=$(mktemp -d "$work/linux.XXXXXX")
chmod 0711 "$area"
stub=$area/gateinto
cat > "$stub" <<STUB
#!/bin/sh
printf '%s\n' "\$0 \$*" >> '$area/calls'
if [ -e '$area/fail-'"\$1" ]; then exit 3; fi
STUB
chmod 0755 "$stub"
package=gateinto-$short-x86_64-unknown-linux-gnu
mkdir "$area/a" "$area/b" "$area/x"

if ! (umask 077 && SOURCE_DATE_EPOCH=1700000000 "$tarball" "$stub" "$area/a/$package.tar.gz") > /dev/null 2> "$work/stderr"; then
  fail 'Linux tarball' "exited with an error: $(cat "$work/stderr")"
elif ! (umask 022 && SOURCE_DATE_EPOCH=1700000000 "$tarball" "$stub" "$area/b/$package.tar.gz") > /dev/null 2> "$work/stderr"; then
  fail 'Linux tarball' "the second build exited with an error: $(cat "$work/stderr")"
else
  expected=$(printf '%s 0/0 2023-11-14 22:13:20 %s\n' \
    drwxr-xr-x "$package/" \
    -rw-r--r-- "$package/LICENSE-APACHE" \
    -rw-r--r-- "$package/LICENSE-MIT" \
    -rw-r--r-- "$package/README" \
    -rwxr-xr-x "$package/gateinto" \
    -rwxr-xr-x "$package/install.sh" \
    -rwxr-xr-x "$package/uninstall.sh")
  actual=$(TZ=UTC tar --numeric-owner --full-time -tvzf "$area/a/$package.tar.gz" | awk '{ print $1, $2, $4, $5, $6 }')
  if [[ $actual != "$expected" ]]; then
    fail 'Linux tarball' "lists"$'\n'"$actual"$'\n'"expected"$'\n'"$expected"
  elif ! cmp -s "$area/a/$package.tar.gz" "$area/b/$package.tar.gz"; then
    fail 'Linux tarball' 'two builds of the same input differ'
  elif [[ "$(od -An -tx1 -j4 -N4 "$area/a/$package.tar.gz" | tr -d ' ')" != 00000000 ]]; then
    fail 'Linux tarball' 'the gzip header carries a timestamp'
  elif ! tar -xzf "$area/a/$package.tar.gz" -C "$area/x"; then
    fail 'Linux tarball' 'does not extract'
  elif ! cmp -s "$area/x/$package/gateinto" "$stub" \
    || ! cmp -s "$area/x/$package/install.sh" "$packaging/install.sh" \
    || ! cmp -s "$area/x/$package/uninstall.sh" "$packaging/uninstall.sh" \
    || ! cmp -s "$area/x/$package/README" "$packaging/README" \
    || ! cmp -s "$area/x/$package/LICENSE-APACHE" "$licenses/LICENSE-APACHE" \
    || ! cmp -s "$area/x/$package/LICENSE-MIT" "$licenses/LICENSE-MIT"; then
    fail 'Linux tarball' 'a file differs from its source'
  else
    pass 'Linux tarball'
  fi
fi

expect_tarball_fail() {
  local name=$1 message=$2
  shift 2
  if "$tarball" "$@" > /dev/null 2> "$work/stderr"; then
    fail "$name" 'succeeded'
  elif ! grep -qF -- "$message" "$work/stderr"; then
    fail "$name" "stderr lacks '$message': $(cat "$work/stderr")"
  else
    pass "$name"
  fi
}

expect_tarball_fail 'Linux tarball without arguments' 'usage'
expect_tarball_fail 'Linux tarball of a missing binary' 'is not a file' "$area/missing" "$area/b/other.tar.gz"
expect_tarball_fail 'Linux tarball without .tar.gz' 'must end in .tar.gz' "$stub" "$area/b/$package.tgz"

pkg=$area/x/$package
system_path=/usr/bin:/bin
install_root_message='install.sh: refusing to run as root: Gateinto installs for one user into ~/.local/bin, and as root or through sudo it would leave root-owned files there; run it as the user who uses Gateinto'
uninstall_root_message='uninstall.sh: refusing to run as root: Gateinto is installed for one user in ~/.local/bin; run it as that user, not as root or through sudo'

new_home() {
  local home
  home=$(mktemp -d "$area/home.XXXXXX")
  mkdir -p "$home/.config/gateinto/gateways" "$home/.local/state/gateinto/profiles/kept"
  printf '# config\n' > "$home/.config/gateinto/gateinto.toml"
  printf 'name = "corp"\n' > "$home/.config/gateinto/gateways/corp.toml"
  printf 'profile\n' > "$home/.local/state/gateinto/profiles/kept/file"
  owned "$home"
  rm -f "$area"/fail-*
  : > "$area/calls"
  owned "$area/calls"
  printf '%s' "$home"
}

fail_on() {
  : > "$area/fail-$1"
}

snapshot() {
  (
    cd "$1"
    find . -path ./.local/bin -prune -o -printf '%p %y %m %U\n' | sort
    find . -path ./.local/bin -prune -o -type f -exec sha256sum {} + | sort -k 2
  )
}

run_script() {
  local who=$1 home=$2 path=$3 cwd=$4
  shift 4
  (cd "$cwd" && "as_$who" env -i HOME="$home" PATH="$path" "$@") > "$work/stdout" 2> "$work/stderr"
}

decoy=$(mktemp -d "$area/cwd.XXXXXX")
printf '#!/bin/sh\nexit 0\n' > "$decoy/gateinto"
cp "$decoy/gateinto" "$decoy/install.sh"
cp "$decoy/gateinto" "$decoy/uninstall.sh"
chmod 0755 "$decoy"/*
owned "$decoy"

home=$(new_home)
bin=$home/.local/bin
before=$(snapshot "$home")
if ! run_script user "$home" "$system_path" "$decoy" "$pkg/install.sh"; then
  fail 'install' "exited with an error: $(cat "$work/stderr")"
elif ! cmp -s "$bin/gateinto" "$stub"; then
  fail 'install' 'the installed gateinto is not the packaged one'
elif [[ "$(stat -c '%a %u' "$bin" "$bin/gateinto")" != "755 $user_uid"$'\n'"755 $user_uid" ]]; then
  fail 'install' "modes and owners are $(stat -c '%n %a %u' "$bin" "$bin/gateinto")"
elif [[ "$(ls -A "$bin")" != gateinto ]]; then
  fail 'install' "the bin directory holds $(ls -A "$bin")"
elif [[ "$(cat "$area/calls")" != "$bin/gateinto uri register" ]]; then
  fail 'install' "ran $(cat "$area/calls")"
elif [[ "$(snapshot "$home")" != "$before" ]]; then
  fail 'install' 'changed files outside ~/.local/bin'
elif ! grep -qxF 'install.sh: warning: ~/.local/bin is not on PATH; add it to PATH or run ~/.local/bin/gateinto' "$work/stderr"; then
  fail 'install' "stderr lacks the PATH warning: $(cat "$work/stderr")"
else
  pass 'install'
fi

: > "$area/calls"
if ! run_script user "$home" "$system_path" "$decoy" "$pkg/uninstall.sh"; then
  fail 'uninstall' "exited with an error: $(cat "$work/stderr")"
elif [[ ! -d $bin || -n "$(ls -A "$bin")" ]]; then
  fail 'uninstall' "the bin directory is missing or holds $(ls -A "$bin")"
elif [[ "$(cat "$area/calls")" != "$bin/gateinto stop --remove-stale-profiles"$'\n'"$bin/gateinto uri unregister" ]]; then
  fail 'uninstall' "ran $(cat "$area/calls")"
elif [[ "$(snapshot "$home")" != "$before" ]]; then
  fail 'uninstall' 'changed files outside ~/.local/bin'
elif ! grep -qF 'kept the configuration' "$work/stdout"; then
  fail 'uninstall' "stdout does not say what was kept: $(cat "$work/stdout")"
else
  pass 'uninstall'
fi

home=$(new_home)
bin=$home/.local/bin
mkdir -m 0700 "$bin"
printf 'other\n' > "$bin/other"
owned "$bin"
if ! run_script user "$home" "$bin:$system_path" "$pkg" ./install.sh; then
  fail 'install from the package directory' "exited with an error: $(cat "$work/stderr")"
elif [[ -s $work/stderr ]]; then
  fail 'install from the package directory' "printed on stderr: $(cat "$work/stderr")"
elif [[ "$(stat -c %a "$bin")" != 700 || "$(cat "$bin/other")" != other ]]; then
  fail 'install from the package directory' 'changed the existing ~/.local/bin'
elif ! cmp -s "$bin/gateinto" "$stub"; then
  fail 'install from the package directory' 'the installed gateinto is not the packaged one'
else
  pass 'install from the package directory'
fi

home=$(new_home)
bin=$home/.local/bin
mkdir -m 0755 "$bin"
cp "$(command -v sleep)" "$bin/gateinto"
owned "$bin"
"$bin/gateinto" 60 &
running=$!
for _ in $(seq 100); do
  [[ "$(readlink "/proc/$running/exe" 2> /dev/null)" != "$bin/gateinto" ]] || break
  sleep 0.05
done
if ! run_script user "$home" "$system_path" "$pkg" ./install.sh; then
  fail 'install over a running gateinto' "exited with an error: $(cat "$work/stderr")"
elif ! cmp -s "$bin/gateinto" "$stub"; then
  fail 'install over a running gateinto' 'the installed gateinto is not the packaged one'
elif [[ "$(ls -A "$bin")" != gateinto ]]; then
  fail 'install over a running gateinto' "the bin directory holds $(ls -A "$bin")"
else
  pass 'install over a running gateinto'
fi
kill "$running"
wait "$running" 2> /dev/null || true

home=$(new_home)
bin=$home/.local/bin
fail_on uri
if run_script user "$home" "$system_path" "$pkg" ./install.sh; then
  fail 'install when registering fails' 'succeeded'
elif ! grep -qxF 'install.sh: installed ~/.local/bin/gateinto, but "gateinto uri register" failed; run install.sh again after fixing the error above' "$work/stderr"; then
  fail 'install when registering fails' "stderr lacks the message: $(cat "$work/stderr")"
elif [[ "$(stat -c %a "$bin/gateinto")" != 755 ]]; then
  fail 'install when registering fails' 'did not leave the installed gateinto'
else
  pass 'install when registering fails'
fi

home=$(new_home)
bin=$home/.local/bin
mkdir -p "$bin/gateinto"
printf 'kept\n' > "$bin/gateinto/file"
owned "$bin"
if run_script user "$home" "$system_path" "$pkg" ./install.sh; then
  fail 'install over a directory' 'succeeded'
elif [[ "$(cat "$work/stderr")" != 'install.sh: ~/.local/bin/gateinto is a directory; remove or rename it, then run install.sh again' ]]; then
  fail 'install over a directory' "stderr is $(cat "$work/stderr")"
elif [[ "$(ls -A "$bin")" != gateinto || "$(ls -A "$bin/gateinto")" != file || -s $area/calls ]]; then
  fail 'install over a directory' 'changed something'
else
  pass 'install over a directory'
fi

home=$(new_home)
bin=$home/.local/bin
mkdir -p "$bin" "$home/elsewhere"
ln -s ../../elsewhere "$bin/gateinto"
owned "$bin" "$home/elsewhere"
if run_script user "$home" "$system_path" "$pkg" ./install.sh; then
  fail 'install over a link to a directory' 'succeeded'
elif [[ "$(cat "$work/stderr")" != 'install.sh: ~/.local/bin/gateinto is a directory; remove or rename it, then run install.sh again' ]]; then
  fail 'install over a link to a directory' "stderr is $(cat "$work/stderr")"
elif [[ ! -L $bin/gateinto || "$(ls -A "$bin")" != gateinto || -n "$(ls -A "$home/elsewhere")" || -s $area/calls ]]; then
  fail 'install over a link to a directory' 'changed something'
else
  pass 'install over a link to a directory'
fi

home=$(new_home)
if ! run_script user "$home" "$system_path" "$pkg" ./uninstall.sh; then
  fail 'uninstall without an installed gateinto' "exited with an error: $(cat "$work/stderr")"
elif [[ -s $area/calls ]]; then
  fail 'uninstall without an installed gateinto' "ran $(cat "$area/calls")"
elif ! grep -qxF 'uninstall.sh: ~/.local/bin/gateinto is not installed; nothing to stop, unregister or remove' "$work/stdout"; then
  fail 'uninstall without an installed gateinto' "stdout lacks the message: $(cat "$work/stdout")"
else
  pass 'uninstall without an installed gateinto'
fi

installed_home() {
  local home
  home=$(new_home)
  mkdir -m 0755 "$home/.local/bin"
  cp "$stub" "$home/.local/bin/gateinto"
  owned "$home/.local/bin"
  printf '%s' "$home"
}

home=$(installed_home)
bin=$home/.local/bin
fail_on stop
if run_script user "$home" "$system_path" "$pkg" ./uninstall.sh; then
  fail 'uninstall when stopping the agent fails' 'succeeded'
elif ! cmp -s "$bin/gateinto" "$stub"; then
  fail 'uninstall when stopping the agent fails' 'removed ~/.local/bin/gateinto'
elif [[ "$(cat "$area/calls")" != "$bin/gateinto stop --remove-stale-profiles" ]]; then
  fail 'uninstall when stopping the agent fails' "ran $(cat "$area/calls")"
elif ! grep -qxF 'uninstall.sh: "gateinto stop --remove-stale-profiles" failed, so nothing was removed; run uninstall.sh again after fixing the error above' "$work/stderr"; then
  fail 'uninstall when stopping the agent fails' "stderr lacks the message: $(cat "$work/stderr")"
else
  pass 'uninstall when stopping the agent fails'
fi

home=$(installed_home)
bin=$home/.local/bin
fail_on uri
if run_script user "$home" "$system_path" "$pkg" ./uninstall.sh; then
  fail 'uninstall when unregistering fails' 'succeeded'
elif ! cmp -s "$bin/gateinto" "$stub"; then
  fail 'uninstall when unregistering fails' 'removed ~/.local/bin/gateinto'
elif ! grep -qxF 'uninstall.sh: "gateinto uri unregister" failed, so ~/.local/bin/gateinto was kept; run uninstall.sh again after fixing the error above' "$work/stderr"; then
  fail 'uninstall when unregistering fails' "stderr lacks the message: $(cat "$work/stderr")"
else
  pass 'uninstall when unregistering fails'
fi

home=$(new_home)
bin=$home/.local/bin
mkdir -p "$bin"
ln -s missing "$bin/gateinto"
owned "$bin"
if run_script user "$home" "$system_path" "$pkg" ./uninstall.sh; then
  fail 'uninstall of a dangling link' 'succeeded'
elif grep -qF 'is not installed' "$work/stdout"; then
  fail 'uninstall of a dangling link' 'reported that gateinto is not installed'
elif [[ "$(cat "$work/stderr")" != 'uninstall.sh: ~/.local/bin/gateinto is a symbolic link to a missing file; remove it by hand' ]]; then
  fail 'uninstall of a dangling link' "stderr is $(cat "$work/stderr")"
elif [[ -s $work/stdout || -s $area/calls ]]; then
  fail 'uninstall of a dangling link' 'printed on stdout or ran gateinto'
elif [[ "$(readlink "$bin/gateinto")" != missing ]]; then
  fail 'uninstall of a dangling link' 'removed or changed the link'
else
  pass 'uninstall of a dangling link'
fi

mkdir "$decoy/rel"
owned "$decoy/rel"
expect_refused() {
  local name=$1 script=$2 message=$3 argument=$4 home before listing command
  shift 4
  command=(env "$@" "$pkg/$script" ${argument:+"$argument"})
  if [[ $script == install.sh ]]; then
    home=$(new_home)
  else
    home=$(installed_home)
  fi
  before=$(snapshot "$home")
  listing=$(ls -A "$home/.local/bin" 2> /dev/null || true)
  if run_script user "$home" "$system_path" "$decoy" "${command[@]}"; then
    fail "$name" 'succeeded'
  elif [[ "$(cat "$work/stderr")" != "$message" ]]; then
    fail "$name" "stderr is $(cat "$work/stderr")"
  elif [[ -s $area/calls || "$(snapshot "$home")" != "$before" || -n "$(ls -A "$decoy/rel")" ]]; then
    fail "$name" 'changed something'
  elif [[ "$(ls -A "$home/.local/bin" 2> /dev/null || true)" != "$listing" ]]; then
    fail "$name" 'changed ~/.local/bin'
  elif [[ $script == uninstall.sh ]] && ! cmp -s "$home/.local/bin/gateinto" "$stub"; then
    fail "$name" 'changed ~/.local/bin/gateinto'
  else
    pass "$name"
  fi
}

for script in install.sh uninstall.sh; do
  expect_refused "${script%.sh} with an argument" "$script" "usage: $script" --unit
  expect_refused "${script%.sh} without HOME" "$script" "$script: HOME is not an absolute path to an existing directory" '' -u HOME
  expect_refused "${script%.sh} with a relative HOME" "$script" "$script: HOME is not an absolute path to an existing directory" '' HOME=rel
done

install_check=$here/linux-install-check.sh
layouts=$(mktemp -d "$area/layouts.XXXXXX")
mkdir -p "$layouts/two/first" "$layouts/two/second" "$layouts/file"
cp -r "$pkg/." "$layouts/two/first"
printf 'gateinto\n' > "$layouts/file/gateinto"
tar -czf "$layouts/two.tar.gz" -C "$layouts/two" first second
tar -czf "$layouts/file.tar.gz" -C "$layouts/file" gateinto
for layout in two file; do
  : > "$area/calls"
  if "$install_check" "$layouts/$layout.tar.gz" > "$work/stdout" 2> "$work/stderr"; then
    fail "install check of a tarball with layout $layout" 'succeeded'
  elif [[ "$(cat "$work/stderr")" != 'the tarball must hold exactly one top-level directory' ]]; then
    fail "install check of a tarball with layout $layout" "stderr is $(cat "$work/stderr")"
  elif [[ -s $area/calls ]]; then
    fail "install check of a tarball with layout $layout" "ran $(cat "$area/calls")"
  else
    pass "install check of a tarball with layout $layout"
  fi
done

if ! can_root; then
  echo 'skip install and uninstall as root: needs root or passwordless sudo'
else
  home=$(new_home)
  before=$(snapshot "$home")
  if run_script root "$home" "$system_path" "$pkg" ./install.sh; then
    fail 'install as root' 'succeeded'
  elif [[ "$(cat "$work/stderr")" != "$install_root_message" ]]; then
    fail 'install as root' "stderr is $(cat "$work/stderr")"
  elif [[ -e $home/.local/bin || -s $area/calls || "$(snapshot "$home")" != "$before" ]]; then
    fail 'install as root' 'changed something'
  else
    pass 'install as root'
  fi

  home=$(installed_home)
  before=$(snapshot "$home")
  if run_script root "$home" "$system_path" "$pkg" ./uninstall.sh; then
    fail 'uninstall as root' 'succeeded'
  elif [[ "$(cat "$work/stderr")" != "$uninstall_root_message" ]]; then
    fail 'uninstall as root' "stderr is $(cat "$work/stderr")"
  elif ! cmp -s "$home/.local/bin/gateinto" "$stub" || [[ -s $area/calls || "$(snapshot "$home")" != "$before" ]]; then
    fail 'uninstall as root' 'changed something'
  else
    pass 'uninstall as root'
  fi
fi

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

common=$'`'"$sha"$'`\n2026-10-18 09:30 UTC\nnot code-signed\nhttps://github.com/lukeo3o1/gateinto-dev/issues/23\nTPM\nreal browsers\nphysical Windows machines\nWindows 7\nPre-release, not externally security reviewed.\ngateinto-x86_64-unknown-linux-gnu.tar.gz\nnot yet verified on a real Linux desktop\nno device key on Linux'
win7=$'i686-win7-windows-msvc-experimental.exe\nexperimental\nSoftware Key Storage Provider'
expect_notes 'latest notes' latest "$common"$'\n`latest`' "$win7"$'\nstable'
expect_notes 'beta notes' beta "$common"$'\n`beta`\n'"$win7" 'stable'
expect_notes 'alpha notes' alpha "$common"$'\n`alpha`\n'"$win7" 'stable'

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

workflow="$here/../workflows/release.yml"
create=$(sed -n '/gh release create/,/[^\\]$/p' "$workflow")
if [[ -z $create ]]; then
  fail 'release workflow publishes a prerelease' 'no gh release create command'
elif ! grep -qF -- '--prerelease' <<< "$create" || grep -qE -- '--latest($|[^=])' "$workflow"; then
  fail 'release workflow publishes a prerelease' "every channel must use --prerelease and never --latest:"$'\n'"$create"
else
  pass 'release workflow publishes a prerelease'
fi

if ! grep -qF -- "needs.linux.result == 'success'" "$workflow" \
  || ! grep -qF -- 'cargo build --locked --release --target x86_64-unknown-linux-gnu --bin gateinto' "$workflow" \
  || ! grep -qF -- '.github/scripts/linux-tarball.sh' "$workflow"; then
  fail 'release workflow publishes the Linux tarball' 'no locked Linux build, tarball step or publish dependency on it'
else
  pass 'release workflow publishes the Linux tarball'
fi

if ! sed -n '/^  linux:/,/^  [a-z]/p' "$workflow" | grep -qxF -- '    runs-on: ubuntu-24.04'; then
  fail 'release workflow builds Linux on a fixed image' 'the linux job does not run on ubuntu-24.04'
elif ! sed -n '/^  linux:/,/^  [a-z]/p' "$workflow" | grep -qxF -- '          shared-key: release-ubuntu-24.04'; then
  fail 'release workflow builds Linux on a fixed image' 'the linux job does not use a cache key of ubuntu-24.04'
else
  pass 'release workflow builds Linux on a fixed image'
fi

if ! grep -qxF -- '      - run: shellcheck .github/scripts/*.sh packaging/linux/*.sh' "$here/../workflows/ci.yml"; then
  fail 'CI checks the packaging scripts' 'shellcheck does not cover packaging/linux/*.sh'
else
  pass 'CI checks the packaging scripts'
fi

if ! grep -qF -- '.github/scripts/linux-tarball.sh target/debug/gateinto' "$here/../workflows/ci.yml" \
  || ! grep -qF -- '.github/scripts/linux-install-check.sh' "$here/../workflows/ci.yml"; then
  fail 'CI installs and uninstalls the Linux tarball' 'no Linux tarball built from target/debug/gateinto and checked with linux-install-check.sh'
else
  pass 'CI installs and uninstalls the Linux tarball'
fi

if (( failures )); then
  echo "$failures failed"
  exit 1
fi
echo 'all passed'
