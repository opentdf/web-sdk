#!/usr/bin/env bash
# Cross-platform test harness wrapper for the OpenTDF JS CLI.
# Usage: cli.sh supports <feature>
#        cli.sh <cli-args...>
set -eu

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

case "${1:-}" in
  supports)
    case "${2:-}" in
      mechanism-mlkem)
        exit 0
        ;;
      *)
        exit 1
        ;;
    esac
    ;;
  *)
    exec node "${REPO_ROOT}/cli/bin/opentdf.mjs" "$@"
    ;;
esac
