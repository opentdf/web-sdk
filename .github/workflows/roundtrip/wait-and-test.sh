#!/usr/bin/env bash

set -x

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
ROOT_DIR="$(cd "${APP_DIR}/../../.." >/dev/null && pwd)"

APP="${APP_DIR}/encrypt-decrypt.sh"

_configure_app() {
  app_version=$(cd "${ROOT_DIR}/lib" && node -p "require('./package.json').version")
  echo "installing tgz"
  cd "${APP_DIR}" || exit 1
  npm uninstall @opentdf/cli{,-commonjs}
  npm ci
  npm i "../../../opentdf-cli*-${app_version}.tgz"
}

_wait-for() {
  echo "[INFO] In retry loop for quickstarted opentdf backend..."
  limit=5
  for i in $(seq 1 $limit); do
    if sh "${APP}"; then
      return 0
    fi
    if [[ $i == "$limit" ]]; then
      echo "[WARN] Breaking _wait-for loop as we are at limit"
      break
    fi
    sleep_for=$((10 + i * i * 2))
    echo "[INFO] retrying in ${sleep_for} seconds... ( ${i} / $limit ) ..."
    sleep ${sleep_for}
  done
  echo "[ERROR] Couldn't connect to opentdf backend"
  exit 1
}

_configure_app
_wait-for
