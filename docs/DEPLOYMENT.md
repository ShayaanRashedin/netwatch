# Deployment guide

NetWatch supports a native systemd installation and a Linux Docker Compose
deployment. Native systemd is recommended for long-running host observability;
the container configuration is useful for reproducible evaluation and demos.

## Native installation

Build an optimized version and install it under `/usr`:

```bash
cmake --preset release
cmake --build --preset release
sudo cmake --install build/release
sudo /usr/share/netwatch/scripts/install-systemd.sh
```

Review `/etc/netwatch/netwatch.env`, then enable both services:

```bash
sudo systemctl enable --now netwatch netwatch-api
sudo systemctl status netwatch netwatch-api
curl --fail http://127.0.0.1:8088/api/health
```

The agent runs as root so it can correlate sockets with processes throughout
`/proc`. It writes with group `netwatch` and a restrictive umask. The API runs
as the unprivileged `netwatch` account and binds to loopback by default.

Runtime data is stored under `/var/lib/netwatch`; configuration is stored in
`/etc/netwatch/netwatch.env`. The installer preserves an existing environment
file during upgrades.

To remove the services without deleting recorded data:

```bash
sudo systemctl disable --now netwatch netwatch-api
sudo rm /etc/systemd/system/netwatch.service
sudo rm /etc/systemd/system/netwatch-api.service
sudo systemctl daemon-reload
```

Review `/var/lib/netwatch` separately before deciding whether its database
should be retained or removed.

## Docker Compose

On a Linux Docker host:

```bash
docker compose build
docker compose up -d
docker compose ps
curl --fail http://127.0.0.1:8088/api/health
```

Open `http://127.0.0.1:8088`. Stop the stack with:

```bash
docker compose down
```

The named `netwatch-data` volume persists the SQLite database. `docker compose
down` leaves it intact; only an explicit volume-removal operation deletes it.

The agent uses the host PID and network namespaces plus `SYS_PTRACE` so it can
observe host sockets and correlate process metadata. This configuration is
Linux-specific and intentionally grants visibility that is inappropriate for
an untrusted image. The API is published only on host loopback.

## Release archive

Create the same TGZ format used by tagged releases:

```bash
cmake --preset release
cmake --build --preset release
cpack --config build/release/CPackConfig.cmake -B dist
```

Verify downloaded artifacts against the accompanying `SHA256SUMS` file before
installation.

