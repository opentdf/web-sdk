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
npm version --no-git-tag-version --allow-same-version "$v"
npm publish --access public --tag "$t"

# Wait for npm publish to go through...
sleep 5

if [[ "$GITHUB_STEP_SUMMARY" ]]; then
  echo "### Published ${v} (${t})" >>"$GITHUB_STEP_SUMMARY"
fi
