#!/usr/bin/env bash
# Validate that version number is same across all expected files

set -exuo pipefail

v="${1%%+*}"
t="${2}"

cd lib
for f in {,tdf3/}src/version.ts; do
  if ! sed "s/export const version = \'[^']\{1,\}\';\$/export const version = \'${v}\';/" $f >${f}.tmp; then
    echo "Failed to insert version [${v}] into file [$f]"
    exit 1
  fi
  mv "${f}.tmp" "${f}"
done
npm --no-git-tag-version --allow-same-version version "$v" --tag "$t"
npm publish --access public

sleep 5

cd ../cli

npm --no-git-tag-version --allow-same-version version "$v" --tag "$t"
npm uninstall "@opentdf/client"
npm install "@opentdf/client@$v"
