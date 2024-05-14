#!/usr/bin/env bash
# Validate that version number is same across all expected files

set -euo pipefail

lib_version="$(cd lib && node -p "require('./package.json').version")"

expected_version="${1:-$lib_version}"

if ! grep --fixed-strings --line-regexp --quiet "version=${expected_version}" "Makefile"; then
  if grep --quiet "^version=" "Makefile"; then
    echo "::error file=Makefile,line=$(sed -n '/version/=' $f)::Incorrect version line, should be setting it to [${expected_version}]"
  else
    echo "::error file=Makefile::Makefile missing version line [version=${expected_version}]"
  fi
  exit 1
fi

for f in lib{,/tdf3}/src/version.ts; do
  if ! grep --fixed-strings --line-regexp --quiet "export const version = '${expected_version}';" "$f"; then
    if grep --quiet "^export const version" "$f"; then
      echo "::error file=$f,line=$(sed -n '/export const version/=' $f)::Incorrect version line, should be setting it to [${expected_version}]"
    else
      echo "::error file=$f::Missing version line [version=${expected_version}]"
    fi
    exit 1
  fi
done

for x in lib web-app; do
  sub_version="$(cd $x && node -p "require('./package.json').version")"
  if [[ $expected_version != "$sub_version" ]]; then
    echo "::error file=${x}/package.json::Incorrect version  [${sub_version}], expected [${expected_version}]"
    exit 1
  fi
done

if [[ "${GITHUB_ACTION:-}" ]]; then
  echo "TARGET_VERSION=$expected_version" >>$GITHUB_OUTPUT
else
  echo "SUCCESS: TARGET_VERSION=$expected_version"
fi
