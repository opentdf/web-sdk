#!/usr/bin/env bash
set -e

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"

cd "$APP_DIR"

echo "Hello World" >./sample.txt

_nano_test() {
  npx "$1" --log-level DEBUG \
    --kasEndpoint http://localhost:65432/api/kas \
    --oidcEndpoint http://localhost:65432/auth/realms/tdf \
    --auth tdf-client:123-456 \
    --output sample.txt.ntdf \
    encrypt sample.txt \
    --attributes https://example.com/attr/Classification/value/S,https://example.com/attr/COI/value/PRX

  npx "$2" --log-level DEBUG \
    --kasEndpoint http://localhost:65432/api/kas \
    --oidcEndpoint http://localhost:65432/auth/realms/tdf \
    --auth tdf-client:123-456 \
    --output sample_out.txt \
    decrypt sample.txt.ntdf

  diff sample.txt sample_out.txt

  echo "Roundtrip nanotdf $1 -> $2 successful!"
}

_nano_test @opentdf/cli-commonjs @opentdf/cli
_nano_test @opentdf/cli @opentdf/cli-commonjs

_tdf3_test() {
  npx "$1" --log-level DEBUG \
    --kasEndpoint http://localhost:65432/api/kas \
    --oidcEndpoint http://localhost:65432/auth/realms/tdf \
    --auth tdf-client:123-456 \
    --output sample.txt.tdf \
    encrypt sample.txt \
    --containerType tdf3 \
    --attributes https://example.com/attr/Classification/value/S,https://example.com/attr/COI/value/PRX

  npx "$2" --log-level DEBUG \
    --kasEndpoint http://localhost:65432/api/kas \
    --oidcEndpoint http://localhost:65432/auth/realms/tdf \
    --auth tdf-client:123-456 \
    --output sample_out.txt \
    decrypt sample.txt.tdf

  diff sample.txt sample_out.txt

  echo "Roundtrip tdf3 $1 -> $2 successful!"
}

_tdf3_test @opentdf/cli-commonjs @opentdf/cli
_tdf3_test @opentdf/cli @opentdf/cli-commonjs
