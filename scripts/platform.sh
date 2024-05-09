#!/usr/bin/env zsh

# Fetch latest platform code
# rm -rf platform
# git clone https://github.com/opentdf/platform.git

# Copy platform protos to proto directory (NOT NECESSARY)
# mkdir -p proto
# cp platform/**/*.proto proto

# Generate Typescript code
npx buf generate platform/service