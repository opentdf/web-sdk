#!/usr/bin/env bash

set -x

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
ROOT_DIR="$(cd "${APP_DIR}/../../.." >/dev/null && pwd)"
WEB_APP_DIR="$(cd "${ROOT_DIR}/web-app" >/dev/null && pwd)"

_wait-for() {
  echo "[INFO] In retry loop for quickstarted opentdf backend..."
  limit=5
  for i in $(seq 1 $limit); do
    if curl --show-error --fail --insecure http://localhost:65432/api/kas; then
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

_init_server() {
  output=$(mktemp)
  if ! cd "${WEB_APP_DIR}"; then
    echo "[ERROR] unable to cd ${WEB_APP_DIR}"
    exit 2
  fi
  npm uninstall @opentdf/client
  if ! npm ci; then
    echo "[ERROR] Couldn't ci web-app"
    exit 2
  fi
  if ! npm i "../lib/opentdf-client-${app_version}.tgz"; then
    ls -ls ../lib/
    echo "[ERROR] Couldn't install @opentdf/client tarball"
    return 1
  fi
  npm run dev &>"$output" &
  server_pid=$!
  echo "Server pid: $server_pid"
  echo "Output: $output"
  echo "Wait:"
  limit=5
  for i in $(seq 1 $limit); do
    if grep -q -i 'ready' "$output"; then
      return 0
    fi
    if ! ps $server_pid >/dev/null; then
      echo "The server died" >&2
      cat "${output}"
      exit 1
    fi
    if [[ $i == "$limit" ]]; then
      echo "[WARN] Breaking _init_server loop after ${limit} iterations"
      cat "${output}"
      break
    fi
    sleep_for=$((5 + i * i * 2))
    echo "[INFO] retrying in ${sleep_for} seconds... ( ${i} / $limit ) ..."
    sleep ${sleep_for}
  done
}

if ! _configure_app; then
  echo "[ERROR] Couldn't configure our library and app"
  exit 2
fi

if ! _init_server; then
  echo "[ERROR] Couldn't run web app server"
  exit 2
fi

if ! _wait-for; then
  exit 1
fi

if ! cd "${WEB_APP_DIR}"; then
  echo "[ERROR] Couldn't cd to web-app dir, [${WEB_APP_DIR}]"
  exit 2
fi

if ! cd tests; then
  echo "[ERROR] Couldn't open web integration tests folder"
  exit 2
fi

if ! npm i; then
  echo "[ERROR] Unable to install integration tests deps"
  exit 2
fi

if ! npx playwright install --with-deps; then
  echo "[ERROR] Unable to install playwright"
  exit 2
fi

npm test
