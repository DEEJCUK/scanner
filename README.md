# i wanted a really quick lightweight scanner i can run in docker so i Claude-ed this in a couple of hours, its for home use on my local network to help me keep an eye on ports opened when i spin up docker containers or K3s containers

## Security Notice

**This application is designed for trusted, private network environments only.**

### Current Security Posture

- **No authentication**: All endpoints are publicly accessible
- **Network binding**: Defaults to 0.0.0.0:8888 (all interfaces)
- **Administrative access**: Database clearing and scan control available to any network user

### Safe Deployment Options

1. **Local only**: Use `--host 127.0.0.1` to bind only to localhost
2. **Firewall protection**: Restrict access via iptables/firewall rules
3. **Trusted networks**: Only deploy on isolated/trusted network segments
4. **Container isolation**: Use Docker networking to control access

### Production Hardening Required

Before production deployment, implement:

- Authentication middleware (API keys, basic auth, or session management)
- Network access controls and rate limiting
- Audit logging for administrative operations
- Input validation hardening

## Network Scanner Web App

A small, lightweight network discovery and port-scanning web application. Designed to be easy to run on modest hardware or in a container.

## Overview

This repository contains a single-file web application:

- network_scanner_app.py — Flask-based web UI and scanner. Uses SQLite for persistence.

The app performs:

- Host discovery (ICMP ping + reverse DNS)
- TCP and optional UDP port scanning (multi-threaded)
- Basic service detection / banner grabbing
- Persistent results in SQLite and a simple change-detection diff between runs
- A small responsive web UI to start/stop scans and view results

## Requirements

- Python 3.8+
- pip packages:
  - Flask

Install:

```bash
pip install Flask
```

## Files

- network_scanner_app.py — main application (web server + scanner)
- data/ — default data directory (created automatically). DB: data/scans.db
- scanner.log — runtime log file (created in working directory)
- templates/ - html interface

Note: The app honors the DATA_DIR environment variable. Example:

```bash
export DATA_DIR=/var/lib/network_scanner
```

If not set, the default is ./data.

## Running

Start the web server (binds to 0.0.0.0:8888 by default):

```bash
python3 network_scanner_app.py --host 0.0.0.0 --port 8888
```

Options:

- --host (default 0.0.0.0)
- --port (default 8888)
- --debug (Flask debug mode)

Open the dashboard in a browser at http://<host>:<port>

## Web UI quick usage

- Enter targets (comma separated) in the Targets field. Accepts:
  - single IP: 10.0.0.5
  - CIDR: 192.168.1.0/24
  - IP range: 10.0.0.1-10.0.0.50 or shorthand 10.0.0.1-50 (last octet)
- Ports input accepts:
  - a single max port (e.g. 1000) to scan 1..1000
  - a list/ranges string e.g. "22,80,443,1-100"
  - the UI sends the raw string and server parses it

Start a scan with Start, stop with Stop. Clear or export results via the provided buttons.

## REST API

- POST /api/scan/start
  - JSON body:
    {
    "targets": ["192.168.1.0/24","10.0.0.1-10"],
    "ports": "22,80,443" // or ports: 1000 (integer)
    }
  - Returns: {success: bool, message: str}

- POST /api/scan/stop
  - Stops a running scan. Returns {success, message}

- GET /api/scan/status
  - Returns scan status including running, progress, total, current_phase, start_time

- GET /api/results
  - Returns in-memory scan results and host inventory

- GET /api/results/export
  - Returns JSON file download of current results

- DELETE /api/results/clear
  - Clears in-memory results (does not remove DB entries)

Notes:

- The server persists scan findings into SQLite (scans.db) after each run.
- The server compares the new scan with the last persisted snapshot and annotates services as "new", "ok", or "removed" which the UI displays.

## Persistence & Data

- DB path is DATA_DIR/scans.db by default ./data/scans.db
- On startup the app loads recent results from the DB and keeps a snapshot for diffing.
- Logs are written to scanner.log.

## Scheduling / Timer

Run periodic scans using one of these simple approaches:

- Cron (recommended for Unix-like systems)
  - Example: run hourly

  ``` shell
  0 * * * * /usr/bin/python3 /path/to/network_scanner_app.py --host 127.0.0.1 --port 8888 >> /var/log/scanner.log 2>&1
  ```

- systemd timer (robust, preferred on systemd systems)
  - Create a service unit that runs the scan and a timer unit to trigger it.

- Lightweight Python scheduler
  - Use the schedule package to invoke the script periodically (easy to run in a container)

  ```python
  import schedule, time, subprocess

  def job():
      subprocess.run(["/usr/bin/python3", "/path/to/network_scanner_app.py",
                      "--host", "127.0.0.1", "--port", "8888"])

  schedule.every(1).hours.do(job)
  while True:
      schedule.run_pending()
      time.sleep(1)
  ```

Choose cron/systemd for reliability; the Python scheduler is simple and portable.

## Lightweight scheduler (UI-configurable)

The app includes a simple scheduler you can configure and control from the web UI:

- Configure:
  - Targets (same format as the Targets field)
  - Ports (same format as the Ports field)
  - Interval (minutes) between scheduled runs
- Start/Stop:
  - Use the Start Schedule / Stop Schedule buttons on the dashboard.
  - The scheduler runs the configured scan in the background. It will not start a new run while a scan is already active.
- API:
  - POST /api/scheduler/start => JSON {targets:[...], ports: "22,80", interval_minutes: 60}
  - POST /api/scheduler/stop
  - GET /api/scheduler/status => { running: bool, config: {...} }

Note: scheduler configuration is kept in memory for the running process. Use the Clear DB button if you want to wipe results and start fresh.

## Design notes / goals

- Single-file application to keep deployment simple.
- Lightweight defaults, minimal external dependencies.
- Designed for periodic runs; change-detection highlights new/removed services.
- Configure DATA_DIR to place the database and preserve results across restarts.
