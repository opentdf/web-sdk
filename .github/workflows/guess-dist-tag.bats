#!/usr/bin/env bats

@test "unknown branch" {
  export GITHUB_REF="heads/unknown"
  run $BATS_TEST_DIRNAME/guess-dist-tag.sh
  echo output=[$output]
  [[ $output == "aleph" ]]
}

@test "feature branches are alpha I guess" {
  export GITHUB_REF=refs/heads/feature/some-feature
  run $BATS_TEST_DIRNAME/guess-dist-tag.sh
  echo output=[$output]
  [[ $output == "alpha" ]]
}

@test "main is beta" {
  export GITHUB_REF=refs/heads/main
  run $BATS_TEST_DIRNAME/guess-dist-tag.sh
  echo output=[$output]
  [[ $output == "beta" ]]
}

@test "releases are candidates" {
  export GITHUB_REF=refs/heads/release/something
  run $BATS_TEST_DIRNAME/guess-dist-tag.sh
  echo output=[$output]
  [[ $output == "rc" ]]
}

@test "all tags go to release" {
  export GITHUB_REF=refs/tags/v12
  run $BATS_TEST_DIRNAME/guess-dist-tag.sh
  echo output=[$output]
  [[ $output == "latest" ]]
}
