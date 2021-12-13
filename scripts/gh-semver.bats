#!/usr/bin/env bats

@test "feature branches are alpha I guess" {
  export GITHUB_REF=refs/heads/feature/some-feature
  export GITHUB_RUN_NUMBER=1234
  export MMP_VER="0.0.1"
  run $BATS_TEST_DIRNAME/gh-semver.sh
  echo output=[$output]
  [[ $output == "0.0.1-alpha.1234" ]]
}


@test "unknown branch" {
  export GITHUB_REF=heads/unknown
  export MMP_VER=0.0.1
  run $BATS_TEST_DIRNAME/gh-semver.sh
  echo output=[$output]
  [ "$status" -eq 0 ]
  [ "$output" = "0.0.1-aleph.0" ]
}


@test "all tags go to release" {
  export GITHUB_REF=refs/tags/v12
  export MMP_VER=0.0.1
  export GITHUB_RUN_NUMBER=1234
  run $BATS_TEST_DIRNAME/gh-semver.sh
  echo output=[$output]
  [[ $output == "0.0.1" ]]
}

@test "pre-release metadata" {
  export GITHUB_REF=refs/heads/feature/some-feature
  export GITHUB_RUN_ID=1337
  export GITHUB_RUN_NUMBER=1234
  export GITHUB_SHA=abcdefghij
  export MMP_VER="0.0.1"
  run $BATS_TEST_DIRNAME/gh-semver.sh
  echo output=[$output]
  [[ $output == "0.0.1-alpha.1234+1337.abcdef" ]]
}
