#!/usr/bin/env bash
# Validate that version number is same across all expected files

set -exuo pipefail

v="${1%%+*}"
t="${2}"

cd lib
npm --no-git-tag-version --allow-same-version version "$v" --tag "$t"
npm publish

sleep 5

cd ../cli

npm --no-git-tag-version --allow-same-version version "$v" --tag "$t"
npm uninstall "@opentdf/client"
npm install "@opentdf/client@$v"
npm publish
