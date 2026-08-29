# Five-minute demo

The controlled demo starts the agent, creates a temporary Python listener on
TCP port 4444, captures the resulting explainable alert, and serves the live
dashboard from an isolated temporary database.

Build the debug configuration and run:

```bash
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
./scripts/demo.sh
```

Expected evidence includes a `suspicious-listening-port` alert with a HIGH
risk score, the `0.0.0.0:4444` endpoint, and correlated Python process details.
Open `http://127.0.0.1:8088` while the script is running. Press Ctrl+C to stop;
the script terminates its child processes and removes its temporary database.

The demo requires `python3` and an available local TCP port 4444. It does not
change firewall rules, install software, or send network traffic outside the
host.

