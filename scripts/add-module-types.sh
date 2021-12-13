#!/usr/bin/env bash
# Adds module type definitions to `dist` folders.
# Allows proper detection of CJS types in older versions of node.
# Explanation: https://www.sensedeep.com/blog/posts/2021/how-to-create-single-source-npm-module.html

fixup() {
  local package="$1"
  shift

  local module_type="$1"
  shift

  cat >"dist/${package}/package.json" <<EOF
{
    "type": "$module_type"
}
EOF
}

if [[ $# -gt 0 ]]; then
  while [[ $# -gt 0 ]]; do
    m="$1"
    shift
    case "$m" in
      cjs)
        fixup "$m" commonjs
        ;;
      es* | node*)
        fixup "$m" module
        ;;
      *)
        echo "Unrecognized module type"
        ;;
    esac
  done
else
  fixup cjs commonjs
  fixup esm module
fi
