#!/usr/bin/env bash
# Publish SDK and CLI packages to an npm registry

set -exuo pipefail

version="${1%%+*}"
tag="${2}"

is_published() {
	local result
	if result=$(npm view "$1@$version" version --json --prefer-online); then
		return 0
	fi
	# Only a missing version permits publication; other lookup errors are fatal.
	if node -e 'process.exit(JSON.parse(require("fs").readFileSync(0, "utf8")).error.code === "E404" ? 0 : 1)' <<<"$result"; then
		return 1
	fi
	exit 1
}

cd lib
if is_published @opentdf/sdk; then
	echo "SDK $version already published; skipping"
else
	file=src/version.ts
	if ! sed "s|export const version = \'[^']\{1,\}\'; // x-release-please-version\$|export const version = \'${version}\';|" "${file}" >"${file}.tmp"; then
		echo "Failed to insert version [${version}] into file [$file]"
		exit 1
	fi
	mv "${file}.tmp" "${file}"

	npm version --no-git-tag-version --allow-same-version "$version"
	npm publish --access public --tag "$tag"
fi

cd "../cli"
if is_published @opentdf/ctl; then
	echo "CLI $version already published; skipping"
else
	# Wait for the SDK package to appear on the registry before the CLI can install it.
	# npm registry propagation can take longer than 5 seconds, so retry with backoff.
	max_attempts=12
	for attempt in $(seq 1 $max_attempts); do
		if is_published @opentdf/sdk; then
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

	npm version --no-git-tag-version --allow-same-version "$version"
	npm uninstall "@opentdf/sdk"
	npm install "@opentdf/sdk@$version"
	npm publish --access public --tag "$tag"
fi

if [[ "${GITHUB_STEP_SUMMARY:-}" ]]; then
	echo "### Published ${version} (${tag})" >>"$GITHUB_STEP_SUMMARY"
fi
