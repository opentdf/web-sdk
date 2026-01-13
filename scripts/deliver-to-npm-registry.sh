#!/usr/bin/env bash
# Validate that version number is same across all expected files

set -exuo pipefail

version="${1%%+*}"
tag="${2}"

# Build provenance flag if NPM_PROVENANCE is set to "true"
provenance_flag=""
if [[ "${NPM_PROVENANCE:-}" == "true" ]]; then
  provenance_flag="--provenance"
fi

cd lib
file=src/version.ts
if ! sed "s|export const version = \'[^']\{1,\}\'; // x-release-please-version\$|export const version = \'${version}\';|" "${file}" >"${file}.tmp"; then
	echo "Failed to insert version [${version}] into file [$file]"
	exit 1
fi
mv "${file}.tmp" "${file}"

npm version --no-git-tag-version --allow-same-version "$version"
npm publish --access public --tag "$tag" $provenance_flag

# Wait for npm publish to go through...
sleep 5

cd "../cli"
npm version --no-git-tag-version --allow-same-version "$version"
npm uninstall "@opentdf/sdk"
npm install "@opentdf/sdk@$version"
npm publish --access public --tag "$tag" $provenance_flag

if [[ "$GITHUB_STEP_SUMMARY" ]]; then
	echo "### Published ${version} (${tag})" >>"$GITHUB_STEP_SUMMARY"
fi
