#!/usr/bin/env bash

set -eu


rm -rf platform lib/src/platform

if [ -n "${PLATFORM_SRC:-}" ]; then
  # Use PLATFORM_SRC for buf generate
  echo "Using PLATFORM_SRC: $PLATFORM_SRC"
else
  # Clone latest platform code
  git clone https://github.com/opentdf/platform.git
  PLATFORM_SRC="platform/service"
fi

# Generate Typescript code
cd lib
# version
PATH="$PWD/node_modules/.bin:$PATH" buf --version
# Ensure we use the local protoc-gen-es from node_modules
PATH="$PWD/node_modules/.bin:$PATH" buf generate "$PLATFORM_SRC"
echo "Generated Typescript code from Protobuf files (src: $PLATFORM_SRC, dst: lib/src/platform)"
