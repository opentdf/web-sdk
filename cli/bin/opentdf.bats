#!/usr/bin/env bats

@test "requires some arguments" {
  run $BATS_TEST_DIRNAME/opentdf.mjs
  echo "$output"
  [[ $output == *"Not enough"* ]]
}

@test "requires optional arguments" {
  run $BATS_TEST_DIRNAME/opentdf.mjs encrypt noone
  echo "$output"
  [[ $output == *"Missing required"* ]]
}

@test "fails with missing file arguments" {
  run $BATS_TEST_DIRNAME/opentdf.mjs --kasEndpoint https://invalid --oidcEndpoint http://invalid --auth b:c encrypt notafile
  echo "$output"
  [ "$status" -eq 1 ]
  [[ $output == *"File is not accessable"* ]]
}

@test "version command" {
  run $BATS_TEST_DIRNAME/opentdf.mjs --version
  echo "$output"
  [[ $output == *"@opentdf/client\":\""* ]]
  [[ $output == *"@opentdf/cli\":\""* ]]
}
