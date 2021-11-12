#!/usr/bin/env bats

@test "requires some arguments" {
  run $BATS_TEST_DIRNAME/opentdf.mjs
  [[ $output == "Not enough"* ]]
}

@test "requires optional arguments" {
  run $BATS_TEST_DIRNAME/opentdf.mjs encrypt noone
  [[ $output == "Missing required"* ]]
}

@test "fails with missing file arguments" {
  run $BATS_TEST_DIRNAME/opentdf.mjs --kasEndpoint https://invalid --oidcEndpoint http://invalid --auth a:b:c encrypt notafile
  [[ $output == *"no such file or directory"* ]]
}
