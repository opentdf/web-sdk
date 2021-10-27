#!/usr/bin/env bash
# Usage:
#   gh-check "Check Name" "failure"

d=$(
  cat <<EOF
{
  "name": "$1",
  "head_sha": "${GITHUB_SHA}",
  "status": "completed",
  "conclusion": "${2}"
}
EOF
)

echo $d

curl \
  -f \
  -X POST \
  -H "Accept: application/vnd.github.v3+json" \
  -H "authorization: Bearer ${GH_TOKEN}" \
  "${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}/check-runs" \
  -d "${d}"
