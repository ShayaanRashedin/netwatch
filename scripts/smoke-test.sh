#!/usr/bin/env bash

set -euo pipefail

install_prefix="${1:-}"

if [[ -z "${install_prefix}" ]]; then
    echo "Usage: $0 INSTALL_PREFIX" >&2
    exit 2
fi

netwatch_bin="${install_prefix}/bin/netwatch"
api_bin="${install_prefix}/bin/netwatch_api"
web_root="${install_prefix}/share/netwatch/web"

for required in "${netwatch_bin}" "${api_bin}" "${web_root}/index.html"; do
    if [[ ! -e "${required}" ]]; then
        echo "Missing installed artifact: ${required}" >&2
        exit 1
    fi
done

smoke_dir="$(mktemp -d -t netwatch-smoke.XXXXXX)"
api_pid=""

cleanup() {
    if [[ -n "${api_pid}" ]] && kill -0 "${api_pid}" 2>/dev/null; then
        kill -TERM "${api_pid}" 2>/dev/null || true
        wait "${api_pid}" 2>/dev/null || true
    fi
    rm -rf -- "${smoke_dir}"
}

trap cleanup EXIT INT TERM

"${netwatch_bin}" --version | grep -F "NetWatch 1.0.0"
"${api_bin}" --version | grep -F "NetWatch API 1.0.0"
"${netwatch_bin}" --once >/dev/null

port="${NETWATCH_SMOKE_PORT:-18088}"
"${api_bin}" \
    --database "${smoke_dir}/netwatch.db" \
    --listen 127.0.0.1 \
    --port "${port}" \
    >"${smoke_dir}/api.log" 2>&1 &
api_pid=$!

health=""
for _ in {1..50}; do
    if health="$(curl --fail --silent \
        "http://127.0.0.1:${port}/api/health" 2>/dev/null)"; then
        break
    fi

    if ! kill -0 "${api_pid}" 2>/dev/null; then
        cat "${smoke_dir}/api.log" >&2
        exit 1
    fi

    sleep 0.1
done

grep -Fq '"status":"ok"' <<<"${health}"
curl --fail --silent \
    "http://127.0.0.1:${port}/api/summary" \
    | grep -Fq '"event_count":0'
curl --fail --silent \
    "http://127.0.0.1:${port}/" \
    | grep -Fq '<title>NetWatch'

echo "Installed NetWatch smoke test passed."

