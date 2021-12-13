#!/usr/bin/env bash
# Validate that version number is same across all expected files

set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"

: "${DIST_TAG="$("${SCRIPTS_DIR}"/guess-dist-tag.sh)"}"
: "${MMP_VER=$(cd lib && node -p "require('./package.json').version")}"

BUILD_META=
if [[ ${GITHUB_RUN_ID:-} ]]; then
  BUILD_META="+${GITHUB_RUN_ID:-0}.${GITHUB_SHA:0:6}"
fi

if [[ ${DIST_TAG} != latest ]]; then
  echo "${MMP_VER}-${DIST_TAG}.${GITHUB_RUN_NUMBER:-0}${BUILD_META}"
else
  echo "${MMP_VER}"
fi
