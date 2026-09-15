#!/usr/bin/env bash

set -euo pipefail

if command -v netwatch >/dev/null 2>&1; then
    netwatch_bin="$(command -v netwatch)"
    api_bin="$(command -v netwatch_api)"
elif [[ -x ./build/debug/netwatch && -x ./build/debug/netwatch_api ]]; then
    netwatch_bin="./build/debug/netwatch"
    api_bin="./build/debug/netwatch_api"
elif [[ -x ./build/release/netwatch && -x ./build/release/netwatch_api ]]; then
    netwatch_bin="./build/release/netwatch"
    api_bin="./build/release/netwatch_api"
else
    echo "Build or install netwatch and netwatch_api before running the demo." >&2
    exit 1
fi

command -v python3 >/dev/null 2>&1 || {
    echo "The demo requires python3." >&2
    exit 1
}

demo_dir="$(mktemp -d -t netwatch-demo.XXXXXX)"
database="${demo_dir}/netwatch.db"
agent_pid=""
listener_pid=""
api_pid=""

cleanup() {
    for pid in "${api_pid}" "${listener_pid}" "${agent_pid}"; do
        if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
            kill -TERM "${pid}" 2>/dev/null || true
            wait "${pid}" 2>/dev/null || true
        fi
    done
    rm -rf -- "${demo_dir}"
}

trap cleanup EXIT INT TERM

echo "Starting NetWatch and generating a controlled port-4444 signal..."
"${netwatch_bin}" \
    --database "${database}" \
    --interval-ms 200 \
    --retention-days 1 \
    >"${demo_dir}/agent.log" 2>&1 &
agent_pid=$!

sleep 0.5
python3 -m http.server 4444 --bind 0.0.0.0 \
    >"${demo_dir}/listener.log" 2>&1 &
listener_pid=$!
sleep 1.0

if ! kill -0 "${listener_pid}" 2>/dev/null; then
    cat "${demo_dir}/listener.log" >&2
    echo "Unable to start the controlled listener; port 4444 may be busy." >&2
    exit 1
fi

kill -TERM "${listener_pid}"
wait "${listener_pid}" 2>/dev/null || true
listener_pid=""
sleep 0.5

kill -TERM "${agent_pid}"
wait "${agent_pid}"
agent_pid=""

echo
"${netwatch_bin}" --database "${database}" --alerts 10 --min-score 50

echo "Starting the dashboard at http://127.0.0.1:8088"
echo "Press Ctrl+C to stop the demo and remove its temporary data."
"${api_bin}" \
    --database "${database}" \
    --listen 127.0.0.1 \
    --port 8088 &
api_pid=$!
wait "${api_pid}"
