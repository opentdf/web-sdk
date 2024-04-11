: "${KC_VERSION:=24.0.3}"
: "${KC_BROWSERTEST_CLIENT_SECRET:=$(uuidgen)}"

if ! which kcadm.sh; then
  KCADM_URL=https://github.com/keycloak/keycloak/releases/download/${KC_VERSION}/keycloak-${KC_VERSION}.zip
  echo "DOWNLOADING ${KCADM_URL}"
  curl -o kc.zip "${KCADM_URL}"
  unzip kc.zip -d keycloak-${KC_VERSION}
  export PATH=$PATH:$(pwd)/keycloak-${KC_VERSION}/bin
fi

kcadm.sh config credentials --server http://localhost:65432/auth --realm master --user admin <<EOF
changeme
EOF

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

kcadm.sh create users -r opentdf -s username=user1 -s enabled=true
kcadm.sh set-password -r opentdf --username user1 --new-password testuser123
