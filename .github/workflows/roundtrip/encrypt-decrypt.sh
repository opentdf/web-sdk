#!/usr/bin/env bash

pwd

mv ../../../opentdf-cli-*.tgz ../../../cli
npm uninstall @opentdf/cli && npm ci && npm i ../../../cli/opentdf-cli-*.tgz

touch ./sample.txt
echo "Hello World!" >> ./sample.txt

npx @opentdf/cli --log-level DEBUG \
--kasEndpoint http://localhost:65432/api/kas \
--oidcEndpoint http://localhost:65432 \
--auth tdf:tdf-client:123-456 \
--output sample.txt.tdf encrypt sample.txt
--attributes https://example.com/attr/Classification/value/S,https://example.com/attr/COI/value/PRX

npx @opentdf/cli --log-level DEBUG \
--kasEndpoint http://localhost:65432/api/kas \
--oidcEndpoint http://localhost:65432 \
--auth tdf:tdf-client:123-456 \
--output sample_out.txt decrypt sample.txt.tdf

diff sample.txt sample_out.txt

echo "Rountrip successful!"