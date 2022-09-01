#!/usr/bin/env bash
set -e

echo "Hello World!" >./sample.txt

npx @opentdf/cli --log-level DEBUG \
  --kasEndpoint http://localhost:65432/api/kas \
  --oidcEndpoint http://localhost:65432/auth/realms/tdf \
  --auth tdf-client:123-456 \
  --output sample.txt.tdf encrypt sample.txt \
  --attributes https://example.com/attr/Classification/value/S,https://example.com/attr/COI/value/PRX

npx @opentdf/cli --log-level DEBUG \
  --kasEndpoint http://localhost:65432/api/kas \
  --oidcEndpoint http://localhost:65432/auth/realms/tdf \
  --auth tdf-client:123-456 \
  --output sample_out.txt decrypt sample.txt.tdf

diff sample.txt sample_out.txt

echo "Roundtrip successful!"
