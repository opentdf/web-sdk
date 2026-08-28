#!/usr/bin/env bash

set -eu


# Remove generated bindings while preserving hand-written helpers colocated in
# the platform tree.
find lib/src/platform -type f -name '*_pb.ts' -delete

if [ -n "${PLATFORM_SRC:-}" ]; then
  # Use PLATFORM_SRC for buf generate
  echo "Using PLATFORM_SRC: $PLATFORM_SRC"
else
  # Generate from the latest platform schemas published to the BSR.
  PLATFORM_SRC="buf.build/opentdf/platform:main"
  echo "Using PLATFORM_SRC: $PLATFORM_SRC"
fi

# Generate Typescript code
cd lib
# version
PATH="$PWD/node_modules/.bin:$PATH" buf --version
# Ensure we use the local protoc-gen-es from node_modules
if [[ "$PLATFORM_SRC" == buf.build/* ]]; then
  BUF_INPUT="$PLATFORM_SRC"
else
  BUF_INPUT="../$PLATFORM_SRC"
fi
PATH="$PWD/node_modules/.bin:$PATH" buf generate --template buf.gen.yaml "$BUF_INPUT"
echo "Generated Typescript code from Protobuf files (src: $PLATFORM_SRC, dst: lib/src/platform)"
