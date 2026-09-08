#!/usr/bin/env bash
# Build the local lib and install it into the web-app.
# Run this after making changes to lib/ before starting the dev server.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$REPO_ROOT/lib"
npm ci
npm pack

cd "$REPO_ROOT/web-app"
npm remove @opentdf/sdk
npm ci
npm install ../lib/opentdf-sdk-*.tgz

echo "Done. Run scripts/dev-local.sh to start the dev server."
