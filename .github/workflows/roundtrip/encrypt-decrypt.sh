#!/usr/bin/env bash
set -e

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"

cd "$APP_DIR"

counter=0

_nano_test() {
  var=$((counter + 1))
  echo "Hello World ${counter}" >./sample.txt
  npx "$1" --log-level DEBUG \
    --kasEndpoint http://localhost:65432/api/kas \
    --oidcEndpoint http://localhost:65432/auth/realms/tdf \
    --auth tdf-client:123-456 \
    --output sample.txt.ntdf \
    encrypt sample.txt \
    --attributes https://example.com/attr/Classification/value/S,https://example.com/attr/COI/value/PRX

  [ -f sample.txt.ntdf ]

  npx "$2" --log-level DEBUG \
    --kasEndpoint http://localhost:65432/api/kas \
    --oidcEndpoint http://localhost:65432/auth/realms/tdf \
    --auth tdf-client:123-456 \
    --output sample_out.txt \
    decrypt sample.txt.ntdf

  [ -f sample_out.txt ] && diff sample.txt sample_out.txt

  echo "Roundtrip nanotdf $1 -> $2 successful!"
  rm -f sample.txt sample.txt.ntdf sample_out.txt
}

_nano_test @opentdf/cli-commonjs @opentdf/cli
_nano_test @opentdf/cli @opentdf/cli-commonjs

_tdf3_test() {
  var=$((counter + 1))
  echo "Hello World ${counter}" >./sample.txt
  npx "$1" --log-level DEBUG \
    --kasEndpoint http://localhost:65432/api/kas \
    --oidcEndpoint http://localhost:65432/auth/realms/tdf \
    --auth tdf-client:123-456 \
    --output sample.txt.tdf \
    encrypt sample.txt \
    --containerType tdf3 \
    --attributes https://example.com/attr/Classification/value/S,https://example.com/attr/COI/value/PRX

  [ -f sample.txt.tdf ]

  npx "$2" --log-level DEBUG \
    --kasEndpoint http://localhost:65432/api/kas \
    --oidcEndpoint http://localhost:65432/auth/realms/tdf \
    --auth tdf-client:123-456 \
    --output sample_out.txt \
    --containerType tdf3 \
    decrypt sample.txt.tdf

  [ -f sample_out.txt ] && diff sample.txt sample_out.txt

  echo "Roundtrip tdf3 $1 -> $2 successful!"
  rm -f sample.txt sample.txt.tdf sample_out.txt
}

_tdf3_test @opentdf/cli-commonjs @opentdf/cli
_tdf3_test @opentdf/cli @opentdf/cli-commonjs
