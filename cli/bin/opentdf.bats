#!/usr/bin/env bats

@test "fails to parse" {
  run $BATS_TEST_DIRNAME/opentdf.mjs
  [[ $output == *[undefined]* ]]
}

@test "action=encrypt" {
  run $BATS_TEST_DIRNAME/opentdf.mjs --action encrypt
  [[ $output == *[encrypt]* ]]
}
