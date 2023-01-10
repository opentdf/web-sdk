#!/usr/bin/env bash
# Validate that version number is same across all expected files

set -exuo pipefail

v="${1%%+*}"
t="${2}"

cd lib
sed -i '' "s/export const version = '[^']\{1,\}';\$/export const version = \'${v}\';/" lib{,/tdf3}/src/version.ts
npm --no-git-tag-version --allow-same-version version "$v" --tag "$t"
npm publish --access public

sleep 5

cd ../cli

npm --no-git-tag-version --allow-same-version version "$v" --tag "$t"
npm uninstall "@opentdf/client"
npm install "@opentdf/client@$v"
npm publish --access public

if [[ "$GITHUB_STEP_SUMMARY" ]]; then
  echo "### Published ${v}" >>"$GITHUB_STEP_SUMMARY"
fi
