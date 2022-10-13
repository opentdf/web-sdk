#!/usr/bin/env bash
set -e

echo "Hello World" >./sample.txt

npx @opentdf/cli --log-level DEBUG \
  --kasEndpoint http://localhost:65432/api/kas \
  --oidcEndpoint http://localhost:65432/auth/realms/tdf \
  --auth tdf-client:123-456 \
  encrypt sample.txt \
  --attributes https://example.com/attr/Classification/value/S,https://example.com/attr/COI/value/PRX \
  >sample.txt.ntdf


npx @opentdf/cli --log-level DEBUG \
  --kasEndpoint http://localhost:65432/api/kas \
  --oidcEndpoint http://localhost:65432/auth/realms/tdf \
  --auth tdf-client:123-456 \
  decrypt sample.txt.ntdf \
  >sample_out.txt

diff sample.txt sample_out.txt

echo "Roundtrip nanotdf successful!"

npx @opentdf/cli --log-level DEBUG \
  --kasEndpoint http://localhost:65432/api/kas \
  --oidcEndpoint http://localhost:65432/auth/realms/tdf \
  --auth tdf-client:123-456 \
  encrypt sample.txt \
  --containerType tdf3 \
  --attributes https://example.com/attr/Classification/value/S,https://example.com/attr/COI/value/PRX \
  >sample.txt.tdf

npx @opentdf/cli --log-level DEBUG \
  --kasEndpoint http://localhost:65432/api/kas \
  --oidcEndpoint http://localhost:65432/auth/realms/tdf \
  --auth tdf-client:123-456 \
  decrypt sample.txt.tdf >sample_out.txt

diff sample.txt sample_out.txt

echo "Roundtrip tdf3 successful!"
