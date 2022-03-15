#!/usr/bin/env bash
grep -rli 'process.env.PKG_VERSION' ./dist/* | 
xargs -I@ perl -pi -w -e 's/process.env.PKG_VERSION/'$(npm pkg get version)'/g;' @
