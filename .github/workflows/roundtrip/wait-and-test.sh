#!/usr/bin/env bash

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
ROOT_DIR="$(cd "${APP_DIR}/../../.." >/dev/null && pwd)"

APP="${APP_DIR}/encrypt-decrypt.sh"

_configure_app() {
  app_name="$1"
  app_version=$(cd "${ROOT_DIR}/${app_name}" && node -p "require('./package.json').version")
  if [ -f "${ROOT_DIR}/opentdf-${app_name}-${app_version}.tgz" ]; then
    echo "installing tgz"
    cp "${ROOT_DIR}/opentdf-${app_name}-${app_version}.tgz" "${ROOT_DIR}/${app_name}/"
    (
      cd "${APP_DIR}" || exit 1
      npm uninstall @opentdf/${app_name} && npm ci && npm i "../../../${app_name}/opentdf-${app_name}-${app_version}.tgz"
    )
  else
    echo "npm i all by itself"
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

_configure_app cli
_configure_app cli-commonjs

_wait-for
