#!/usr/bin/env bash

set -x

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"

# Run kcadm inside the keycloak container instead of downloading the release
# zip. The container ships a JRE matching its own Keycloak version; the host
# does not necessarily -- Keycloak 26's kcadm needs Java 17, while the
# ubuntu-22.04 runner defaults to Java 11 (UnsupportedClassVersionError).
# Using -f makes the compose project resolve from this script's directory, so
# the caller's working directory doesn't matter.
kcadm.sh() {
  docker compose -f "${APP_DIR}/docker-compose.yaml" \
    exec -T keycloak /opt/keycloak/bin/kcadm.sh "$@"
}

# Inside the container Keycloak is reached on its own KC_HTTP_PORT, not through
# the vite dev-server proxy on 65432 that host-side callers use.
kcadm.sh config credentials --server http://localhost:8888/auth \
  --realm master --user admin --password changeme

kcadm.sh create clients -r opentdf \
  -s clientId=browsertest \
  -s enabled=true \
  -s 'redirectUris=["http://localhost:65432/"]' \
  -s consentRequired=false \
  -s standardFlowEnabled=true \
  -s directAccessGrantsEnabled=true \
  -s serviceAccountsEnabled=false \
  -s publicClient=true \
  -s protocol=openid-connect \
  -s 'protocolMappers=[{"name":"aud","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper","consentRequired":false,"config":{"access.token.claim":"true","included.custom.audience":"http://localhost:65432"}}]'

kcadm.sh create clients -r opentdf \
  -s clientId=testclient \
  -s secret=secret \
  -s enabled=true \
  -s standardFlowEnabled=true \
  -s serviceAccountsEnabled=true \
  -s 'protocolMappers=[{"name":"aud","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper","consentRequired":false,"config":{"access.token.claim":"true","included.custom.audience":"http://localhost:65432"}}]'

kcadm.sh create users -r opentdf -s username=user1 -s enabled=true -s firstName=Alice -s lastName=User
kcadm.sh set-password -r opentdf --username user1 --new-password testuser123
