#!/usr/bin/env bash
# Validate that version number is same across all expected files

set -euo pipefail

lib_version="$(cd lib && node -p "require('./package.json').version")"

expected_version="${1:-$lib_version}"

if ! grep -Fxq "version=${expected_version}" "Makefile"; then
  echo "::error file=Makefile::Makefile missing version line [version=${expected_version}]"
  exit 1
fi

for f in lib{,/tdf3}/src/version.ts; do
  if ! grep -Fxq "export const version = '${expected_version}'" "$f"; then
    if grep -Fxq "export const version" "$f"; then
      echo "::error file=$f,line=$(sed -n  '/export const version/=' $f)::Incorrect version line, should be setting it to [${expected_version}]"
      exit 1
    else
      echo "::error file=$f::Missing version line [version=${expected_version}]"
    fi
  fi
done

for x in lib cli web-app; do
  sub_version="$(cd $x && node -p "require('./package.json').version")"
  if [[ $expected_version != "$sub_version" ]]; then
    echo "::error file=${x}/package.json::Incorrect version  [${sub_version}], expected [${expected_version}]"
    exit 1
  fi
done

if [[ "${GITHUB_ACTION}" ]]; then
  echo "TARGET_VERSION=$expected_version" >> $GITHUB_OUTPUT
fi
