#!/usr/bin/env bash
# Validate that version number is same across all expected files

set -euo pipefail

: "${GITHUB_REF:=$(git rev-parse --abbrev-ref HEAD)}"

MMP_VER=$(cd lib && node -p "require('./package.json').version")

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
    PRE_RELEASE_TAG=
    ;;
esac

BUILD_META=
if [[ ${GITHUB_RUN_ID:-} ]]; then
  BUILD_META="+${GITHUB_RUN_ID:-0}.${GITHUB_SHA:0:6}"
fi

if [[ $PRE_RELEASE_TAG ]]; then
  echo "${MMP_VER}-${PRE_RELEASE_TAG}.${GITHUB_RUN_NUMBER:-0}${BUILD_META}"
else
  echo "${MMP_VER}"
fi
