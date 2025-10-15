#!/usr/bin/env bash

set -eu

# Fetch latest platform code
rm -rf platform lib/src/platform
git clone https://github.com/opentdf/platform.git

# Generate Typescript code
cd lib
# version
PATH="$PWD/node_modules/.bin:$PATH" buf --version
# Ensure we use the local protoc-gen-es from node_modules
PATH="$PWD/node_modules/.bin:$PATH" buf generate ../platform/service
echo "Generated Typescript code from Protobuf files (src: platform/service, dst: lib/src/platform)"
