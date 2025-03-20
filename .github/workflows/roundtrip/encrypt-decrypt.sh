#!/usr/bin/env bash
set -exuo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"

cd "$APP_DIR"

counter=0

_nano_test() {
  counter=$((counter + 1))
  plain="./sample-${counter}.txt"
  echo "Hello World ${counter}" >"./${plain}"
  npx "$1" --log-level DEBUG \
    --kasEndpoint http://localhost:65432/kas \
    --ignoreAllowList \
    --oidcEndpoint http://localhost:65432/auth/realms/opentdf \
    --auth testclient:secret \
    --output sample.txt.ntdf \
    encrypt "${plain}" 

  [ -f sample.txt.ntdf ]

  npx "$2" --log-level DEBUG \
    --kasEndpoint http://localhost:65432/kas \
    --ignoreAllowList \
    --oidcEndpoint http://localhost:65432/auth/realms/opentdf \
    --auth testclient:secret \
    --output sample_out.txt \
    decrypt sample.txt.ntdf

  [ -f sample_out.txt ] && diff "${plain}" sample_out.txt

  echo "Roundtrip nanotdf $1 -> $2 successful!"
  rm -f "${plain}" sample.txt.ntdf sample_out.txt
}

_nano_test @opentdf/ctl @opentdf/ctl

_tdf3_test() {
  counter=$((counter + 1))
  plain="./sample-${counter}.txt"
  echo "Hello World ${counter}" >"${plain}"
  npx "$1" --log-level DEBUG \
    --kasEndpoint http://localhost:65432/kas \
    --ignoreAllowList \
    --oidcEndpoint http://localhost:65432/auth/realms/opentdf \
    --auth testclient:secret \
    --output sample.txt.tdf \
    encrypt "${plain}" \
    --containerType tdf3 

  [ -f sample.txt.tdf ]

  npx "$2" --log-level DEBUG \
    --kasEndpoint http://localhost:65432/kas \
    --ignoreAllowList \
    --oidcEndpoint http://localhost:65432/auth/realms/opentdf \
    --auth testclient:secret \
    --output sample_out.txt \
    --containerType tdf3 \
    decrypt sample.txt.tdf

  [ -f sample_out.txt ] && diff "${plain}" sample_out.txt

  echo "Roundtrip tdf3 $1 -> $2 successful!"
  rm -f "${plain}" sample.txt.tdf sample_out.txt
}

_tdf3_test @opentdf/ctl @opentdf/ctl

_tdf3_inspect_test() {
  counter=$((counter + 1))
  plain="./sample-${counter}.txt"
  echo "Hello World ${counter}" >"${plain}"
  npx "$1" --log-level DEBUG \
    --kasEndpoint http://localhost:65432/kas \
    --ignoreAllowList \
    --oidcEndpoint http://localhost:65432/auth/realms/opentdf \
    --auth testclient:secret \
    --output sample-with-attrs.txt.tdf \
    --attributes 'https://attr.io/attr/a/value/1,https://attr.io/attr/x/value/2' \
    encrypt "${plain}" \
    --containerType tdf3 

  [ -f sample-with-attrs.txt.tdf ]

  npx "$1" --log-level DEBUG \
    inspect sample-with-attrs.txt.tdf > sample_inspect_out.txt

  cat sample_inspect_out.txt

  [ -f sample_inspect_out.txt ]
  grep -q 'https://attr.io/attr/a/value/1'

  echo "Inspect tdf3 successful!"
  rm -f "${plain}" sample-with-attrs.txt.tdf sample_inspect_out.txt
}

_tdf3_inspect_test @opentdf/ctl
