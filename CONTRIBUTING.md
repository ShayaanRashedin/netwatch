# Contributing to NetWatch

Thank you for helping improve NetWatch. Keep changes focused, testable, and
easy to review.

## Development setup

Install a C++20 compiler, CMake 3.25+, Ninja, Git, and SQLite development
headers. Then run:

```bash
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

The build surfaces common correctness warnings that should be fixed during review:
`-Wall`, `-Wextra`, `-Wpedantic`, `-Wconversion`, `-Wsign-conversion`, and
`-Wshadow` are enabled for project targets.

## Change guidelines

- Add deterministic tests for new parsing, detection, storage, or API behavior.
- Keep `/proc` parsing separate from policy and presentation logic.
- Preserve queue bounds, transactional persistence, and graceful shutdown.
- Never log secrets or add write operations to the public API without an
  explicit security design.
- Update the README and changelog when behavior or deployment changes.
- Use clear commit messages such as `feat:`, `fix:`, `test:`, or `docs:`.

Before opening a pull request, run the debug tests and installed smoke test:

```bash
cmake --install build/debug --prefix /tmp/netwatch-install
./scripts/smoke-test.sh /tmp/netwatch-install
```

For security vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of
opening a public issue.

