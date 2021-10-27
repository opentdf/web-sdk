#!/usr/bin/env bash
# Validate that version number is same across all expected files

set -euo pipefail

: "${GITHUB_REF:=$(git rev-parse --abbrev-ref HEAD)}"

PRE_RELEASE_TAG=aleph
case "${GITHUB_REF}" in
  main)
    PRE_RELEASE_TAG=beta
    ;;
  release/*)
    PRE_RELEASE_TAG=rc
    ;;
  feature*)
    PRE_RELEASE_TAG=alpha
    ;;
  v*)
    PRE_RELEASE_TAG=latest
    ;;
esac

echo ${PRE_RELEASE_TAG}
