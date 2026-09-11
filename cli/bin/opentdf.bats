#!/usr/bin/env bats

@test "requires some arguments" {
  run $BATS_TEST_DIRNAME/opentdf.mjs
  echo "$output"
  [[ $output == *"Not enough"* ]]
}

# `encrypt` validates in stages: flags, then oidcEndpoint, then the input file,
# then auth. Each of the next few tests pins one stage by checking that the
# later stages have not run yet -- the assertion on what is *absent* is the one
# that keeps the ordering from drifting back.

@test "rejects an unknown integrity algorithm before anything else" {
  run $BATS_TEST_DIRNAME/opentdf.mjs --segmentIntegrityAlgorithm bogus encrypt noone
  echo "$output"
  [[ $output == *"Invalid values"* ]]
  [[ $output == *"bogus"* ]]
  [[ $output != *"noone"* ]]
}

@test "rejects a GMAC root signature before touching the file" {
  run $BATS_TEST_DIRNAME/opentdf.mjs --rootIntegrityAlgorithm gmac encrypt noone
  echo "$output"
  [ "$status" -eq 1 ]
  [[ $output == *"unsupported root integrity algorithm"* ]]
  [[ $output != *"noone"* ]]
}

@test "requires an oidcEndpoint before opening the input file" {
  run $BATS_TEST_DIRNAME/opentdf.mjs encrypt noone
  echo "$output"
  [ "$status" -eq 1 ]
  [[ $output == *"oidcEndpoint must be specified"* ]]
  [[ $output != *"not accessable"* ]]
}

@test "fails on an unreadable input file" {
  run $BATS_TEST_DIRNAME/opentdf.mjs --kasEndpoint "https://example.com" --oidcEndpoint "http://invalid" --concurrencyLimit 1 --auth "b:c" encrypt noone
  echo "$output"
  [ "$status" -eq 1 ]
  [[ $output == *"File is not accessable [noone]"* ]]
}

# Integrity algorithms are accepted in any casing but must reach the manifest
# uppercase, since readers match the spec's spelling exactly. This runs against a
# closed local port, so it gets as far as the create options and then fails to
# reach the KAS -- hence no $status assertion.
@test "normalizes integrity algorithm casing" {
  echo "hello" > "$BATS_TEST_TMPDIR/plain.txt"
  run $BATS_TEST_DIRNAME/opentdf.mjs --kasEndpoint "http://localhost:9999" --oidcEndpoint "http://localhost:9999" --concurrencyLimit 1 --auth "b:c" --log-level debug --output "$BATS_TEST_TMPDIR/out.tdf" --segmentIntegrityAlgorithm gmac --rootIntegrityAlgorithm HS256 encrypt "$BATS_TEST_TMPDIR/plain.txt"
  echo "$output"
  [[ $output != *"Invalid values"* ]]
  [[ $output == *"\"rootIntegrityAlgorithm\":\"HS256\""* ]]
  [[ $output == *"\"segmentIntegrityAlgorithm\":\"GMAC\""* ]]
}

@test "fails with missing file arguments" {
  run $BATS_TEST_DIRNAME/opentdf.mjs --kasEndpoint "https://example.com" --oidcEndpoint "http://invalid" --concurrencyLimit 1 --auth "b:c" encrypt
  [ "$status" -eq 1 ]
  echo "$output"
  [[ $output == *"Must specify file or pipe"* ]]
}

@test "version command" {
  run $BATS_TEST_DIRNAME/opentdf.mjs --version
  echo "$output"
  [[ $output == *"@opentdf/sdk\":\""* ]]
  [[ $output == *"tdfSpecVersion\":\""* ]]
}
