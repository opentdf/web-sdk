#!/usr/bin/env bash
# Start the web-app dev server pointed at a local otdf-local instance.
#
# Prerequisites:
#   - otdf-local backend is running (tests/ dir):
#       uv run otdf-local --instance DSPX-3397 up --services platform,kas
#   - Local lib is built and installed:
#       ./scripts/rebuild-local-lib.sh
#
# DPoP is active by default (the lib sends DPoP tokens on every request).
# To see enforcement (platform rejects non-DPoP tokens), set enforceDPoP: true
# in tests/instances/DSPX-3397/opentdf.yaml, then restart platform:
#   uv run otdf-local --instance DSPX-3397 up --services platform --no-provision
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

KC_REALM="${KC_REALM:-opentdf}"
KC_CLIENT_ID="${KC_CLIENT_ID:-browsertest}"
APP_URL="${APP_URL:-http://localhost:65432}"

# Use the app origin for the OIDC host so browser requests go through
# Vite's /auth proxy instead of hitting Keycloak on port 8888 directly (CORS).
export VITE_TDF_CFG="{\"oidc\":{\"host\":\"${APP_URL}/auth/realms/${KC_REALM}\",\"clientId\":\"${KC_CLIENT_ID}\"},\"kas\":\"${APP_URL}/kas\",\"reader\":\"https://secure.virtru.com/start?htmlProtocol=1\"}"

echo "Starting web-app dev server with:"
echo "  OIDC: ${APP_URL}/auth/realms/${KC_REALM} (proxied)  client=${KC_CLIENT_ID}"
echo "  KAS:  ${APP_URL}/kas (proxied)"
echo ""

cd "$REPO_ROOT/web-app"
npm run dev
