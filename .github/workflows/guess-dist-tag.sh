#!/usr/bin/env bash
# Guess the desired NPM distribution tag based on current git ref.
# For more info, see: https://docs.npmjs.com/adding-dist-tags-to-packages
# Releases are tagged with `latest`, on tags like `sdk/v1.2.3`
# Release candidates are tagged `rc`, from branches prefixed with `release/`
# Betas are the main branch.
# Alphas can be manually built from feature branches.
# Aleph is the fallback for unknown branch and tag patterns.
# Notably, our dist-tags sort lexicographically from least to most stable.

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
  refs/tags/sdk/v*)
    NPM_DIST_TAG=latest
    ;;
esac

echo ${NPM_DIST_TAG}
