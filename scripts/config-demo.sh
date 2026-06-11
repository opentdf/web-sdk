#!/usr/bin/env bash
# Configure Keycloak for the DPoP browser demo and start the dev server.
#
# Mirrors .github/workflows/roundtrip/config-demo-idp.sh but uses the admin
# REST API directly (no kcadm download needed) and targets an otdf-local
# instance rather than the CI docker-compose stack.
#
# Prerequisites:
#   - Keycloak is running (docker, via otdf-local):
#       uv run otdf-local --instance DSPX-3397 up --services docker
#   - Local lib is built and installed in web-app:
#       ./scripts/rebuild-local-lib.sh
#
# Usage:
#   ./scripts/config-demo.sh           # uses defaults
#   PLATFORM_URL=http://localhost:9080 ./scripts/config-demo.sh
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

KC_URL="${KC_URL:-http://localhost:8888}"
KC_REALM="${KC_REALM:-opentdf}"
KC_ADMIN_USER="${KC_ADMIN_USER:-admin}"
KC_ADMIN_PASSWORD="${KC_ADMIN_PASSWORD:-changeme}"
PLATFORM_URL="${PLATFORM_URL:-http://localhost:8080}"
APP_URL="${APP_URL:-http://localhost:65432}"

echo "Configuring Keycloak at ${KC_URL}/auth/realms/${KC_REALM}"

KC_ADMIN_TOKEN=$(curl -sf "${KC_URL}/auth/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli&username=${KC_ADMIN_USER}&password=${KC_ADMIN_PASSWORD}&grant_type=password" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

_kc() { curl -sf -H "Authorization: Bearer ${KC_ADMIN_TOKEN}" "$@"; }

# Create browsertest public client with DPoP binding enforced.
# Audience maps to PLATFORM_URL so the platform's auth.audience check passes.
if _kc "${KC_URL}/auth/admin/realms/${KC_REALM}/clients?clientId=browsertest" \
    | python3 -c "import sys,json; exit(0 if json.load(sys.stdin) else 1)" 2>/dev/null; then
  echo "browsertest client already exists, skipping creation"
else
  _kc -X POST "${KC_URL}/auth/admin/realms/${KC_REALM}/clients" \
    -H "Content-Type: application/json" \
    -d "{
      \"clientId\": \"browsertest\",
      \"enabled\": true,
      \"redirectUris\": [\"${APP_URL}/\"],
      \"consentRequired\": false,
      \"standardFlowEnabled\": true,
      \"directAccessGrantsEnabled\": true,
      \"serviceAccountsEnabled\": false,
      \"publicClient\": true,
      \"protocol\": \"openid-connect\",
      \"attributes\": {\"dpop.bound.access.tokens\": \"true\"},
      \"protocolMappers\": [{
        \"name\": \"aud\",
        \"protocol\": \"openid-connect\",
        \"protocolMapper\": \"oidc-audience-mapper\",
        \"consentRequired\": false,
        \"config\": {
          \"access.token.claim\": \"true\",
          \"included.custom.audience\": \"${PLATFORM_URL}\"
        }
      }]
    }"
  echo "Created browsertest client (DPoP-bound, audience=${PLATFORM_URL})"
fi

# Create demo user (user1 / testuser123) if not already present.
if _kc "${KC_URL}/auth/admin/realms/${KC_REALM}/users?username=user1" \
    | python3 -c "import sys,json; exit(0 if json.load(sys.stdin) else 1)" 2>/dev/null; then
  echo "user1 already exists, skipping creation"
else
  USER_ID=$(_kc -X POST "${KC_URL}/auth/admin/realms/${KC_REALM}/users" \
    -H "Content-Type: application/json" \
    -D - \
    -d '{"username":"user1","enabled":true,"firstName":"Alice","lastName":"User"}' \
    | grep -i "^location:" | grep -o '[^/]*$' | tr -d '\r')
  _kc -X PUT "${KC_URL}/auth/admin/realms/${KC_REALM}/users/${USER_ID}/reset-password" \
    -H "Content-Type: application/json" \
    -d '{"type":"password","value":"testuser123","temporary":false}'
  echo "Created user1 (password: testuser123)"
fi

echo ""
echo "Keycloak configured. Starting dev server..."
echo ""
exec "${REPO_ROOT}/scripts/dev-local.sh"
