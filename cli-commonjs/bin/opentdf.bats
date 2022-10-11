#!/usr/bin/env bats

@test "requires some arguments" {
  run $BATS_TEST_DIRNAME/opentdf.js
  [[ $output == "Not enough"* ]]
}

@test "requires optional arguments" {
  run $BATS_TEST_DIRNAME/opentdf.js encrypt noone
  [[ $output == "Missing required"* ]]
}

@test "fails with missing file arguments" {
  run $BATS_TEST_DIRNAME/opentdf.js --kasEndpoint https://invalid --oidcEndpoint http://invalid --auth b:c encrypt notafile
  [[ $output == *"no such file or directory"* ]]
}

@test "version command" {
  run $BATS_TEST_DIRNAME/opentdf.js --version
  [[ $output == *"@opentdf/client\":\""* ]]
  [[ $output == *"@opentdf/cli\":\""* ]]
}
