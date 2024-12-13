#!/usr/bin/env bash
# shellcheck disable=SC2206,SC1091

# Wrapper for go otdfctl to quickly switch between local and released versions.
#
# Usage: ./otdfctl.sh [otdfctl options]
#
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
PROJECT_ROOT=$(cd -- "$SCRIPT_DIR/../../.." &>/dev/null && pwd)

# shellcheck source=../../test.env
source "$SCRIPT_DIR"/test.env

cmd=("$SCRIPT_DIR"/otdfctl)
if [ ! -f "$SCRIPT_DIR"/otdfctl ]; then
  cmd=(go run github.com/opentdf/otdfctl@${OTDFCTL_REF-latest})
fi

cmd+=(--json)
cmd+=(--host="$PLATFORMURL" --tls-no-verify --log-level=debug)
cmd+=(--with-client-creds='{"clientId":"'$CLIENTID'","clientSecret":"'$CLIENTSECRET'"}')

>&2 echo "${cmd[@]}" "$@"
"${cmd[@]}" "$@"
