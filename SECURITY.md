# Security policy

## Supported versions

Security fixes are applied to the latest `1.x` release and the `main` branch.

## Reporting a vulnerability

Please do not disclose a vulnerability in a public issue. Use the repository's
GitHub **Security** tab to submit a private vulnerability report. If private
reporting is unavailable, contact the maintainer through the GitHub profile and
request a private channel before sharing sensitive details.

Include the affected version, deployment model, reproduction steps, expected
impact, and any suggested mitigation. You should receive an acknowledgement
within seven days.

## Deployment boundaries

- The dashboard binds to `127.0.0.1` by default and does not implement user
  authentication. Do not expose it directly to an untrusted network.
- System-wide process correlation can require elevated Linux permissions.
  Use the supplied hardened service unit and restrict who can modify its
  executable, environment file, and database directory.
- The API is intentionally read-only. Treat changes that introduce mutation,
  remote control, or authentication as security-sensitive design work.
- SQLite files contain process names, executable paths, command lines, users,
  and network endpoints. Protect and retain them according to local policy.
- Containers use host PID/network visibility for observability. Run the
  supplied Compose configuration only on systems where that access is intended.

