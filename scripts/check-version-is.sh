#!/usr/bin/env bash
# Validate that version number is same across all expected files
# If no parameter is found, validates that the lib/package.json is consistent throughout the repo.
#
# Expected usage:
#   ./scripts/check-version-is.sh [expected_version, e.g. from branch or tag name]
# Output:
#   ::error file=Makefile,line=5::Incorrect version line, should be setting it to [1.0.0]

set -euo pipefail

# Parse github.ref context parameter if provided
if [[ ${1:-} =~ refs/heads/release/sdk/v(.*) ]]; then
  minor_version="${BASH_REMATCH[1]}"
  lib_version="$(cd lib && node -p "require('./package.json').version")"
  if [[ $lib_version != $minor_version* ]]; then
    echo "::error file=lib/package.json::lib version [$lib_version] does not start with expected minor version [$minor_version]"
    exit 1
  fi
  expected_version="$lib_version"
elif [[ ${1:-} =~ refs/tags/sdk/v(.*) ]]; then
  expected_version="${BASH_REMATCH[1]}"
elif [[ ${1:-} =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  expected_version="${1}"
else
  lib_version="$(cd lib && node -p "require('./package.json').version")"
  if [[ -n ${1:-} ]]; then
    echo "::error::Unrecognized ref '${1}'; ignored in favor of lib/package.json's version [${lib_version}]"
  fi
  expected_version="${lib_version}"
fi

if ! grep --fixed-strings --line-regexp --quiet "version=${expected_version}" "Makefile"; then
  if grep --quiet "^version=" "Makefile"; then
    echo "::error file=Makefile,line=$(sed -n '/^version/=' Makefile)::Incorrect version line, should be setting it to [${expected_version}]"
  else
    echo "::error file=Makefile::Makefile missing version line [version=${expected_version}]"
  fi
  exit 1
fi

if ! grep --fixed-strings --line-regexp --quiet "export const version = '${expected_version}'; // x-release-please-version" "lib/src/version.ts"; then
  if grep --quiet "^export const version" "lib/src/version.ts"; then
    echo "::error file=lib/src/version.ts,line=$(sed -n '/^export const version/=' lib/src/version.ts)::Incorrect version line, should be setting it to [${expected_version}]"
  else
    echo "::error file=lib/src/version.ts::Missing version line [version=${expected_version}]"
  fi
  exit 1
fi

for x in lib cli web-app; do
  sub_version="$(cd $x && node -p "require('./package.json').version")"
  if [[ $expected_version != "$sub_version" ]]; then
    echo "::error file=${x}/package.json::Incorrect version  [${sub_version}], expected [${expected_version}]"
    exit 1
  fi
done

if [[ "${GITHUB_ACTION:-}" ]]; then
  echo "TARGET_VERSION=$expected_version" >>"$GITHUB_OUTPUT"
else
  echo "SUCCESS: TARGET_VERSION=$expected_version"
fi
