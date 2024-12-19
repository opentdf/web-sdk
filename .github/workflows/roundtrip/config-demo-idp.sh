#!/usr/bin/env bash

set -x

: "${KC_VERSION:=24.0.3}"

if ! which kcadm.sh; then
  KCADM_URL=https://github.com/keycloak/keycloak/releases/download/${KC_VERSION}/keycloak-${KC_VERSION}.zip
  echo "DOWNLOADING ${KCADM_URL}"
  if ! curl --output kc.zip --fail --location "${KCADM_URL}"; then
    echo "[ERROR] Failed to download ${KCADM_URL}"
    exit 3
  fi
  ls -l
  if ! unzip ./kc.zip; then
    echo "[ERROR] Failed to unzip file from ${KCADM_URL}"
    exit 3
  fi
  ls -l
  ls -l "$(pwd)/keycloak-${KC_VERSION}/bin"
  PATH=$PATH:"$(pwd)/keycloak-${KC_VERSION}/bin"
  export PATH
  if ! which kcadm.sh; then
    echo "[ERROR] Failed to find kcadm.sh"
    exit 3
  fi
fi

kcadm.sh config credentials --server http://localhost:65432/auth \
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
  -s 'protocolMappers=[{"name":"aud","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper","consentRequired":false,"config":{"access.token.claim":"true","included.custom.audience":"http://localhost:65432"}}]' \
  -s 'attributes={"dpop.bound.access.tokens":"true"}'

kcadm.sh create clients -r opentdf \
  -s clientId=testclient \
  -s secret=secret \
  -s enabled=true \
  -s standardFlowEnabled=true \
  -s serviceAccountsEnabled=true \
  -s 'protocolMappers=[{"name":"aud","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper","consentRequired":false,"config":{"access.token.claim":"true","included.custom.audience":"http://localhost:65432"}}]'

kcadm.sh create users -r opentdf -s username=user1 -s enabled=true -s firstName=Alice -s lastName=User
kcadm.sh set-password -r opentdf --username user1 --new-password testuser123
