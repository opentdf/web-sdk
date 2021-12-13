#!/usr/bin/env bash
# Validate that version number is same across all expected files

set -euo pipefail

lib_version="$(cd lib && node -p "require('./package.json').version")"

expected_version="${1:-$lib_version}"

if ! grep -Fxq "version=${expected_version}" "Makefile"; then
  echo "Makefile missing version line [version=${expected_version}]"
  exit 1
fi

for x in lib cli sample-web-app; do
  sub_version="$(cd $x && node -p "require('./package.json').version")"
  if [[ $expected_version != "$sub_version" ]]; then
    echo "${x} has incorrect version  [${sub_version}], expected [${expected_version}]"
    exit 1
  fi
done
