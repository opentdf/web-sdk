#!/usr/bin/env bash
# Publish SDK and CLI packages to an npm registry

set -exuo pipefail

version="${1%%+*}"
tag="${2}"

cd lib
file=src/version.ts
if ! sed "s|export const version = \'[^']\{1,\}\'; // x-release-please-version\$|export const version = \'${version}\';|" "${file}" >"${file}.tmp"; then
	echo "Failed to insert version [${version}] into file [$file]"
	exit 1
fi
mv "${file}.tmp" "${file}"

npm version --no-git-tag-version --allow-same-version "$version"
npm publish --access public --tag "$tag"

# Wait for the SDK package to appear on the registry before the CLI can install it.
# npm registry propagation can take longer than 5 seconds, so retry with backoff.
max_attempts=6
for attempt in $(seq 1 $max_attempts); do
	if npm view "@opentdf/sdk@$version" version >/dev/null 2>&1; then
		echo "SDK version $version is available on the registry"
		break
	fi
	if [ "$attempt" -eq "$max_attempts" ]; then
		echo "ERROR: SDK version $version not found on registry after $max_attempts attempts"
		exit 1
	fi
	echo "Waiting for SDK $version to propagate (attempt $attempt/$max_attempts)..."
	sleep $(( attempt * 5 ))
done

cd "../cli"
npm version --no-git-tag-version --allow-same-version "$version"
npm uninstall "@opentdf/sdk"
npm install "@opentdf/sdk@$version"
npm publish --access public --tag "$tag"

if [[ "$GITHUB_STEP_SUMMARY" ]]; then
	echo "### Published ${version} (${tag})" >>"$GITHUB_STEP_SUMMARY"
fi
