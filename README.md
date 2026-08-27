# NetWatch

[![CI](https://github.com/ShayaanRashedin/netwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/ShayaanRashedin/netwatch/actions/workflows/ci.yml)

NetWatch is a Linux network and process observability agent written in modern C++.
It reads the Linux procfs socket tables, normalizes TCP and UDP sockets across
IPv4 and IPv6, and correlates socket inodes with their owning processes.

The project is being built as a production-oriented observability system rather
than a wrapper around \`ss\` or \`netstat\`. The current milestone provides the
collection layer that later event detection, persistence, and visualization
components will build on.

## Current capabilities

- Parses \`/proc/net/tcp\`, \`tcp6\`, \`udp\`, and \`udp6\`
- Normalizes IPv4 and IPv6 endpoints, ports, states, queues, and socket inodes
- Correlates socket inodes through \`/proc/<pid>/fd\`
- Captures PID, real UID, username, process name, executable, command line, and
  process start time
- Handles shared sockets, duplicate file descriptors, disappearing processes,
  malformed records, and missing procfs tables without terminating collection
- Uses injected procfs roots for deterministic unit testing
- Builds with strict compiler warnings and runs tests in GitHub Actions

## Architecture

\`\`\`mermaid
flowchart LR
    A["/proc/net/{tcp,tcp6,udp,udp6}"] --> B[ProcSocketCollector]
    B --> C[ProcNetSocketParser]
    D["/proc/<pid>/{fd,status,stat,exe,cmdline}"] --> E[ProcessResolver]
    C --> F[SocketRecord]
    E --> G[ProcessInfo]
    F --> H[Enriched socket snapshot]
    G --> H
\`\`\`

The parser operates on streams and the resolver accepts a configurable procfs
root. This keeps Linux I/O at the boundary and makes the core behavior testable
with synthetic procfs fixtures.

## Requirements

- Linux
- A C++20 compiler
- CMake 3.25 or newer
- Ninja
- Git (CMake fetches Catch2 when tests are enabled)

On Ubuntu:

\`\`\`bash
sudo apt update
sudo apt install -y build-essential cmake ninja-build git
\`\`\`

## Build and test

\`\`\`bash
cmake -S . -B build/debug -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build/debug
ctest --test-dir build/debug --output-on-failure
\`\`\`

## Run

\`\`\`bash
./build/debug/netwatch
\`\`\`

Example output:

\`\`\`text
TCP IPv4 127.0.0.1:8080 -> 0.0.0.0:0 LISTEN inode=32808 tx=0 rx=0 owner={pid=4854 process=python3 uid=1000 user=shayaan exe=/usr/bin/python3 cmd="python3 -m http.server 8080" start_ticks=113149}
UDP IPv6 [::]:5353 -> [::]:0 UNCONN inode=42100 tx=0 rx=0 owner=unknown
\`\`\`

Process ownership can be unavailable because of Linux permissions or because a
process exits while the snapshot is being collected. Run with suitable
permissions when a system-wide view is required.

## Repository layout

\`\`\`text
include/netwatch/core/    Domain models
include/netwatch/procfs/  Procfs parser, collector, and resolver interfaces
src/procfs/               Linux procfs implementations
tests/unit/               Deterministic unit tests with synthetic procfs data
.github/workflows/        Continuous integration
\`\`\`

## Roadmap

- [x] IPv4 TCP procfs parsing
- [x] Process-to-socket correlation
- [x] Process identity and command metadata
- [x] IPv4/IPv6 TCP and UDP collection
- [x] Unit tests and Linux CI
- [ ] Snapshot differ and socket lifecycle events
- [ ] Continuous collection with graceful shutdown
- [ ] Bounded event queue and background persistence
- [ ] SQLite event and process storage
- [ ] Behavioral detections and alert scoring
- [ ] REST/WebSocket API and dashboard
- [ ] systemd service, container packaging, demo, and release documentation

## Status

NetWatch is under active development. The collection layer is usable; the
event, storage, detection, and presentation layers are planned next.
