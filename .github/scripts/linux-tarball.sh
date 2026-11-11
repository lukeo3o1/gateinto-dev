#!/usr/bin/env bash
set -euo pipefail

if (( $# != 2 )); then
  echo "usage: $0 <gateinto executable> <output .tar.gz>" >&2
  exit 2
fi
binary=$1
output=$2

if [[ ! -f $binary ]]; then
  echo "$binary is not a file" >&2
  exit 1
fi
name=${output##*/}
if [[ $name != ?*.tar.gz ]]; then
  echo "$output must end in .tar.gz" >&2
  exit 1
fi
package=${name%.tar.gz}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
dir=$stage/$package
mkdir "$dir"
cp -- "$binary" "$dir/gateinto"
cp -- "$root/packaging/linux/install.sh" "$root/packaging/linux/uninstall.sh" \
  "$root/packaging/linux/README" "$root/LICENSE-APACHE" "$root/LICENSE-MIT" "$dir/"
chmod 0755 "$dir" "$dir/gateinto" "$dir/install.sh" "$dir/uninstall.sh"
chmod 0644 "$dir/README" "$dir/LICENSE-APACHE" "$dir/LICENSE-MIT"

tar --create --format=gnu --sort=name --owner=0 --group=0 --numeric-owner \
  --mtime="@${SOURCE_DATE_EPOCH:-0}" --directory="$stage" -- "$package" \
  | gzip -9 -n > "$output"
echo "$output"
