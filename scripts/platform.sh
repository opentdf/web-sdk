#!/usr/bin/env bash

set -eu

# Fetch latest platform code
rm -rf platform lib/src/platform
git clone https://github.com/opentdf/platform.git

# Generate Typescript code
cmd=$(npx buf --version)
if [ $? -ne 0 ]; then
  npm install @bufbuild/protoc-gen-es @bufbuild/buf @connectrpc/protoc-gen-connect-es
fi
npx buf generate platform/service
echo "Generated Typescript code from Protobuf files (src: platform/service, dst: lib/src/platform)"
