#!/usr/bin/env bash
# Run `npm version` on all projects in the repo, keeping them synced
#
#    Usage: bump-version [patch|minor|major] (optional message)
#
# Must be in a clean git checkout and creates a new git branch.
# Sample Usage:
#   ./scripts/bump-version minor "Update minor version to allow new feature"

set -euo pipefail

increment_type="${1:-patch}"
detail="${2:-autobump}"

: "${BUMP_EXPECTED_BRANCH:=main}"

if [[ $BUMP_EXPECTED_BRANCH != $(git rev-parse --abbrev-ref HEAD) ]]; then
  echo "Please run this command on the main branch"
  exit 1
elif [[ $(git status --porcelain) ]]; then
  echo "Please run this command on an unmodified checkout"
  exit 1
fi

packages=(lib cli web-app)
old_version=$(cd "${packages[0]}" && node -p "require('./package.json').version")
echo npm --no-git-tag-version version "${increment_type}"
(cd "${packages[0]}" && npm --no-git-tag-version version "${increment_type}")
new_version=$(cd "${packages[0]}" && node -p "require('./package.json').version")

for x in "${packages[@]:1}"; do
  (
    cd "${x}"
    npm --no-git-tag-version version "${new_version}"
  )
done

# multiplatform `sed -i`: https://unix.stackexchange.com/a/92907
case $(sed --help 2>&1) in
  *GNU*) sed_i() { sed -i "$@"; } ;;
  *) sed_i() { sed -i '' "$@"; } ;;
esac

if ! sed_i "s/version=${old_version}/version=${new_version}/" "Makefile"; then
  echo "Unable to change version in makefile"
  exit 1
fi

if ! sed_i "s/export const version = '[^']\{1,\}';\$/export const version = \'${new_version}\';/" lib/src/version.ts; then
  echo "Unable to change version in version files"
  exit 1
fi

if ! scripts/check-version-is.sh "${new_version}"; then
  echo "bump version script fail"
  exit 1
fi

if ! make all; then
  echo "Unable to bump package locks"
  exit 2
fi

commit_message="🆙 ${new_version} ${increment_type} ${detail}"
git checkout -b "feature/bump-${increment_type}-from-${old_version}-to-${new_version}"
git add .
git commit -m "${commit_message}"