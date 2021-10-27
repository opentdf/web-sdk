#!/usr/bin/env bash
# Validate that version number is same across all expected files

set -euo pipefail

cd lib
npm --no-git-tag-version --allow-same-version version "$1" --tag "$2"
npm publish
