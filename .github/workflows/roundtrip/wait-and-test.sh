#!/usr/bin/env bash

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
ROOT_DIR="$(cd "${APP_DIR}/../../.." >/dev/null && pwd)"

APP="${APP_DIR}/encrypt-decrypt.sh"

_configure_app() {
  cli_version=$(cd "${ROOT_DIR}/cli" && node -p "require('./package.json').version")
  if [ -f "${ROOT_DIR}/opentdf-cli-${cli_version}.tgz" ]; then
    echo "installing tgz"
    cp "${ROOT_DIR}/opentdf-cli-${cli_version}.tgz" "${ROOT_DIR}/cli/"
    (
      cd "${APP_DIR}" || exit 1
      npm uninstall @opentdf/cli && npm ci && npm i "../../../cli/opentdf-cli-${cli_version}.tgz"
    )
  else
    npm i
  fi
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