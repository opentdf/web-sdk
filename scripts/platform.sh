#!/usr/bin/env bash

set -eu

# Fetch latest platform code
rm -rf platform lib/src/platform
git clone https://github.com/opentdf/platform.git

# Generate Typescript code
cd lib
npx buf generate ../platform/service
echo "Generated Typescript code from Protobuf files (src: platform/service, dst: lib/src/platform)"
