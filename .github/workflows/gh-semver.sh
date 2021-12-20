#!/usr/bin/env bash
# Create a pre-release (or release) SemVer for the current file based on its
# git state and 'target' semver found in its package.
#
# Examples:
# 
# Main branches build beta builds:
# ```
#    package.version = 1.2.3
#    branch = main
#    workflow run = 256
#    workflow id = bad
#    git SHA = decaf
#    ----
#    1.2.3-beta.256+bad.decaf
# ```
# 
# Release branches build rc builds:
# ```
#    package.version = 1.2.3
#    branch = release/1.2.3
#    workflow run = 256
#    workflow id = bad
#    git SHA = decaf
#    ----
#    1.2.3-rc.256+bad.decaf
# ```
# 
# Tags go to release:
# ```
#    package.version = 1.2.3
#    tag = v1.2.3
#    workflow run = 256
#    git SHA = decaf
#    ----
#    1.2.3
# ```
#
# 
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
