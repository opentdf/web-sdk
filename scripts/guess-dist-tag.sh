#!/usr/bin/env bash
# Validate that version number is same across all expected files

set -euo pipefail

: "${GITHUB_REF:=$(git rev-parse --symbolic-full-name HEAD)}"

NPM_DIST_TAG=aleph
case "${GITHUB_REF}" in
  refs/heads/main)
    NPM_DIST_TAG=beta
    ;;
  refs/heads/release/*)
    NPM_DIST_TAG=rc
    ;;
  refs/heads/feature*)
    NPM_DIST_TAG=alpha
    ;;
  refs/tags/v*)
    NPM_DIST_TAG=latest
    ;;
esac

echo ${NPM_DIST_TAG}
