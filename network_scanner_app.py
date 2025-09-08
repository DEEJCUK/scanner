#!/usr/bin/env python3
"""
Network Scanner Web Application

Fast, efficient network scanning with web interface.
Single process with integrated web server and scanner.
"""

import argparse
import ipaddress
import json
import logging
import os
import platform
import re
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# --- debug logging for container (stdout) and request/response tracing ---
# route-level decorator to catch and log exceptions centrally
from functools import wraps

# ensure Flask logs go to stdout and are DEBUG when DEBUG env is set
debug_mode = os.environ.get("DEBUG", "").lower() in ("1", "true", "yes")
app.logger.setLevel(logging.DEBUG if debug_mode else logging.INFO)
sh = logging.StreamHandler(sys.stdout)
sh.setLevel(logging.DEBUG if debug_mode else logging.INFO)
sh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
# avoid adding duplicate handlers in reload scenarios
if not any(isinstance(h, logging.StreamHandler) for h in app.logger.handlers):
    app.logger.addHandler(sh)


def debug_wrap(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        app.logger.debug("ENTER %s: args=%s kwargs=%s", fn.__name__, args, kwargs)
        try:
            resp = fn(*args, **kwargs)
            app.logger.debug(
                "EXIT %s: response=%s", fn.__name__, getattr(resp, "status", resp)
            )
            return resp
        except Exception as e:
            app.logger.exception("Unhandled exception in %s", fn.__name__)
            # try to surface scanner logger too
            try:
                scanner.logger.exception("Unhandled exception in %s", fn.__name__)
            except Exception:
                pass
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Internal server error",
                        "error": str(e),
                    }
                ),
                500,
            )

    return wrapper


@app.before_request
def _log_request():
    try:
        app.logger.debug(
            "HTTP %s %s - body: %s",
            request.method,
            request.path,
            request.get_data(as_text=True),
        )
    except Exception:
        app.logger.debug(
            "HTTP %s %s - (failed to read body)", request.method, request.path
        )

    # Handle CORS preflight early so browsers don't get 404 for OPTIONS
    if request.method == "OPTIONS":
        resp = app.make_response(("", 204))
        resp.headers["Access-Control-Allow-Origin"] = os.environ.get(
            "CORS_ALLOW_ORIGIN", "*"
        )
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        return resp


@app.after_request
def _log_response(response):
    try:
        app.logger.debug(
            "HTTP %s %s -> %s", request.method, request.path, response.status
        )
    except Exception:
        app.logger.debug("HTTP response logged")
    # Add permissive CORS headers to help browser-based debugging from any origin
    response.headers["Access-Control-Allow-Origin"] = os.environ.get(
        "CORS_ALLOW_ORIGIN", "*"
    )
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


# --- reusable port parsing helper ---
def parse_ports_input(p):
    """Parse ports expression used by API endpoints and scheduler.
    Returns either an integer (for max port) or a list of specific ports.
    Large ranges are kept as ranges to avoid memory issues.
    """
    if p is None:
        return 65535
    if isinstance(p, list):
        return [int(x) for x in p]
    if isinstance(p, int):
        return int(p)

    s = str(p).strip()
    if re.match(r"^\d+$", s):
        return int(s)

    # Check if this is a simple full range like "1-65535"
    if re.match(r"^\d+-\d+$", s):
        parts = s.split("-")
        start = int(parts[0].strip())
        end = int(parts[1].strip())
        if start == 1 and end >= 1000:
            # Return the end port as max for large ranges starting from 1
            return end

    # Parse complex port specifications
    ports = set()
    total_range_size = 0

    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                a = int(a.strip())
                b = int(b.strip())
            except:
                continue
            if b < a:
                continue
            range_size = b - a + 1
            total_range_size += range_size

            # If individual range is very large, don't expand it
            if range_size > 5000:
                # For very large ranges, just add a representative sample
                # The actual scanning will handle the full range
                for val in range(a, min(a + 100, b + 1)):  # Sample first 100 ports
                    if 1 <= val <= 65535:
                        ports.add(val)
            else:
                # Expand smaller ranges normally
                for val in range(a, b + 1):
                    if 1 <= val <= 65535:
                        ports.add(val)
        else:
            try:
                val = int(part)
                if 1 <= val <= 65535:
                    ports.add(val)
            except:
                continue

    # If total would be huge, return as a simple range
    if total_range_size > 10000:
        return 65535  # Scan all ports efficiently

    return sorted(ports)


class NetworkScanner:
    def __init__(self, db_path="scans.db"):
        self.db_path = db_path
        self.init_database()

        # Scanner state
        self.scan_results = []
        self.host_inventory = defaultdict(dict)
        self.scan_status = {
            "running": False,
            "progress": 0,
            "total": 0,
            "current_phase": "idle",
            "start_time": None,
            "results_count": 0,
        }

        # Threading
        self.lock = threading.Lock()
        self.scan_thread = None
        self.interrupted = False

        # Keep last persisted results (set of tuples) to compare diffs after a run
        self.last_persisted_results = set()
        # persisted host metadata loaded from DB
        self.persisted_hosts_info = {}
        self.last_persisted_hosts = set()

        # Configuration
        self.config = {
            "max_threads": 30,
            "udp_threads": 15,
            "rate_limit": 0.005,
            "udp_timeout": 2,
            "tcp_timeout": 1,
            "enable_service_detection": True,
            "enable_host_discovery": True,
            "enable_udp_scan": True,
        }

        # Scheduler state
        self.scheduler_thread = None
        self.scheduler_stop_event = None
        self.scheduler_config = {
            "enabled": False,
            "interval_minutes": 60,
            "targets": ["192.168.1.0/24"],
            "ports": 1000,
            "ports_display": "1-1000",  # Store original user-friendly format for UI display
        }

        self.setup_logging()

    def init_database(self):
        """Initialize SQLite database for persistent storage"""
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    ip TEXT,
                    port INTEGER,
                    protocol TEXT,
                    service TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS hosts (
                    ip TEXT PRIMARY KEY,
                    hostname TEXT,
                    mac_address TEXT,
                    os_hint TEXT,
                    vendor TEXT,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

    def setup_logging(self):
        """Setup logging to file (LOG_FILE) and stdout. Honor DEBUG env var."""
        # choose log path from LOG_FILE or DATA_DIR
        log_file = os.environ.get("LOG_FILE") or os.path.join(
            os.environ.get("DATA_DIR", "./data"), "scanner.log"
        )
        try:
            os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
        except Exception:
            pass

        debug_mode = os.environ.get("DEBUG", "").lower() in ("1", "true", "yes")
        level = logging.DEBUG if debug_mode else logging.INFO

        # Configure basic logging with both file and stdout handlers
        # Use absolute log_file so the container-mounted path is used
        handlers = []
        try:
            handlers.append(logging.FileHandler(log_file))
        except Exception:
            # fallback to stdout-only if file handler cannot be created
            pass
        handlers.append(logging.StreamHandler(sys.stdout))

        logging.basicConfig(
            level=level,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=handlers,
        )

        self.logger = logging.getLogger(__name__)
        self.logger.info(
            "Logging initialized (level=%s, file=%s)",
            "DEBUG" if debug_mode else "INFO",
            log_file,
        )

    # --- network helpers ---
    def parse_ip_range(self, ip_input):
        ips = []
        ip_input = ip_input.strip()
        try:
            if "-" in ip_input and "/" not in ip_input:
                start_str, end_str = ip_input.split("-", 1)
                start_str = start_str.strip()
                end_str = end_str.strip()
                if re.match(r"^\d+$", end_str):
                    base_parts = start_str.split(".")
                    start_octet = int(base_parts[3])
                    end_octet = int(end_str)
                    for i in range(start_octet, min(end_octet + 1, 256)):
                        ip = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{i}"
                        ips.append(ipaddress.IPv4Address(ip))
                else:
                    start_ip = ipaddress.IPv4Address(start_str)
                    end_ip = ipaddress.IPv4Address(end_str)
                    if int(end_ip) < int(start_ip):
                        raise ValueError("End IP must be >= start IP")
                    for val in range(int(start_ip), int(end_ip) + 1):
                        ips.append(ipaddress.IPv4Address(val))
            elif "/" in ip_input:
                network = ipaddress.IPv4Network(ip_input, strict=False)
                ips = list(network.hosts())
                if len(ips) > 2000:
                    raise ValueError(f"Range too large ({len(ips)} hosts). Max 2000.")
            else:
                ips = [ipaddress.IPv4Address(ip_input)]
        except Exception:
            raise
        return ips

    def ping_host(self, ip):
        try:
            cmd = [
                "ping",
                "-c",
                "1",
                "-W",
                "1000" if platform.system() == "Darwin" else "1",
                str(ip),
            ]
            result = subprocess.run(cmd, capture_output=True, timeout=2)
            success = result.returncode == 0

            # Log first few ping attempts for debugging
            if not hasattr(self, "_ping_debug_count"):
                self._ping_debug_count = 0

            if self._ping_debug_count < 5:  # Only log first 5 for debugging
                self.logger.debug(f"Ping command: {' '.join(cmd)}")
                self.logger.debug(
                    f"Ping {ip} result: return_code={result.returncode}, success={success}"
                )
                if result.stderr:
                    self.logger.debug(
                        f"Ping {ip} stderr: {result.stderr.decode('utf-8', errors='ignore').strip()}"
                    )
                self._ping_debug_count += 1

            return success
        except Exception as e:
            self.logger.debug(f"Ping {ip} exception: {e}")
            return False

    def get_hostname(self, ip):
        try:
            return socket.gethostbyaddr(str(ip))[0]
        except Exception:
            return None

    # small cache for IANA lookups
    _iana_cache = {}

    def lookup_iana(self, port, proto="tcp"):
        key = (int(port), proto.lower())
        if key in self._iana_cache:
            return self._iana_cache[key]
        try:
            iana_name = socket.getservbyport(int(port), proto.lower())
            if isinstance(iana_name, bytes):
                iana_name = iana_name.decode("utf-8", errors="ignore")
            iana_name = iana_name.strip() if iana_name else None
        except Exception:
            iana_name = None
        self._iana_cache[key] = iana_name
        return iana_name

    # --- scanning primitives ---
    def test_tcp_port(self, ip, port):
        try:
            time.sleep(self.config["rate_limit"])
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config["tcp_timeout"])
            result = sock.connect_ex((str(ip), port))
            if result == 0:
                service = self.detect_service(sock, ip, port)
                iana = self.lookup_iana(port, "tcp")
                if iana and iana.lower() not in str(service).lower():
                    service = f"{service} ({iana})"
                sock.close()
                with self.lock:
                    port_result = {
                        "ip": str(ip),
                        "port": port,
                        "protocol": "TCP",
                        "service": service,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    self.scan_results.append(port_result)
                    self.scan_status["results_count"] = len(self.scan_results)
                    key = f"{port}/TCP"
                    if str(ip) in self.host_inventory:
                        self.host_inventory[str(ip)]["services"][key] = {
                            "service": service,
                            "status": "ok",
                        }
                return True
            else:
                sock.close()
        except Exception:
            pass
        finally:
            with self.lock:
                self.scan_status["progress"] += 1
        return False

    def detect_service(self, sock, ip, port):
        if not self.config["enable_service_detection"]:
            return "open"
        try:
            if port == 22:
                banner = sock.recv(128)
                if b"SSH-" in banner:
                    return banner.decode("utf-8", errors="ignore").strip()
            elif port == 80:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                response = sock.recv(512)
                if b"HTTP/" in response:
                    return "HTTP"
            elif port == 443:
                return "HTTPS"
            elif port == 21:
                banner = sock.recv(128)
                if b"220" in banner:
                    return "FTP"
            elif port == 25:
                return "SMTP"
            elif port == 53:
                return "DNS"
            elif port == 3389:
                return "RDP"
        except Exception:
            pass
        return f"port {port}"

    def test_udp_port(self, ip, port):
        if not self.config["enable_udp_scan"]:
            with self.lock:
                self.scan_status["progress"] += 1
            return False
        try:
            time.sleep(self.config["rate_limit"] * 2)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.config["udp_timeout"])
            service = self.detect_udp_service(sock, ip, port)
            if service:
                iana = self.lookup_iana(port, "udp")
                if iana and iana.lower() not in str(service).lower():
                    service = f"{service} ({iana})"
                with self.lock:
                    port_result = {
                        "ip": str(ip),
                        "port": port,
                        "protocol": "UDP",
                        "service": service,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    self.scan_results.append(port_result)
                    self.scan_status["results_count"] = len(self.scan_results)
                    key = f"{port}/UDP"
                    if str(ip) in self.host_inventory:
                        self.host_inventory[str(ip)]["services"][key] = {
                            "service": service,
                            "status": "ok",
                        }
                sock.close()
                return True
            else:
                sock.close()
        except Exception:
            pass
        finally:
            with self.lock:
                self.scan_status["progress"] += 1
        return False

    def detect_udp_service(self, sock, ip, port):
        if not self.config["enable_service_detection"]:
            return None
        try:
            if port == 53:
                dns_query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"
                sock.sendto(dns_query, (str(ip), port))
                try:
                    response, addr = sock.recvfrom(512)
                except socket.timeout:
                    return None
                if len(response) > 12:
                    return "DNS"
            elif port == 123:
                ntp_query = b"\x1b" + b"\x00" * 47
                sock.sendto(ntp_query, (str(ip), port))
                try:
                    response, addr = sock.recvfrom(48)
                except socket.timeout:
                    return None
                if len(response) == 48:
                    return "NTP"
            elif port == 161:
                snmp_query = b"\x30\x19\x02\x01\x00\x04\x06public\xa0\x0c\x02\x04\x00\x00\x00\x01\x02\x01\x00\x30\x00"
                sock.sendto(snmp_query, (str(ip), port))
                try:
                    response, addr = sock.recvfrom(1024)
                except socket.timeout:
                    return None
                if b"\x02\x01\x00" in response:
                    return "SNMP"
            elif port == 69:
                tftp_query = b"\x00\x01test\x00netascii\x00"
                sock.sendto(tftp_query, (str(ip), port))
                try:
                    response, addr = sock.recvfrom(512)
                except socket.timeout:
                    return None
                if len(response) >= 4 and response[1] in [1, 5]:
                    return "TFTP"
            elif port == 67:
                return "DHCP"
            elif port == 514:
                return "Syslog"
            else:
                sock.sendto(b"\x00", (str(ip), port))
                try:
                    response, addr = sock.recvfrom(1024)
                    return f"UDP/{port}"
                except socket.timeout:
                    return None
        except socket.timeout:
            return None
        except Exception:
            pass
        return None

    # --- persistence and inventory helpers ---
    def save_results_to_db(self, scan_id):
        with sqlite3.connect(self.db_path) as conn:
            for result in self.scan_results:
                conn.execute(
                    """
                    INSERT INTO scan_results (scan_id, ip, port, protocol, service)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (
                        scan_id,
                        result["ip"],
                        result["port"],
                        result["protocol"],
                        result["service"],
                    ),
                )
            for ip, host_info in self.host_inventory.items():
                conn.execute(
                    """
                    INSERT OR REPLACE INTO hosts (ip, hostname, mac_address, os_hint, vendor)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (
                        ip,
                        host_info.get("hostname"),
                        host_info.get("mac_address"),
                        host_info.get("os_hint"),
                        host_info.get("vendor"),
                    ),
                )

    def load_recent_results(self, hours=24):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT * FROM scan_results 
                WHERE timestamp > datetime('now', '-{} hours')
                ORDER BY timestamp DESC
            """.format(
                    hours
                )
            )
            self.scan_results = []
            for row in cursor:
                svc = row["service"] or ""
                svc = re.sub(
                    r"open\|filtered", "filtered", svc, flags=re.IGNORECASE
                ).strip()
                self.scan_results.append(
                    {
                        "ip": row["ip"],
                        "port": row["port"],
                        "protocol": row["protocol"],
                        "service": svc,
                        "timestamp": row["timestamp"],
                    }
                )
            self.last_persisted_results = set(
                (r["ip"], int(r["port"]), r["protocol"]) for r in self.scan_results
            )
            cursor = conn.execute("SELECT * FROM hosts")
            self.persisted_hosts_info = {}
            self.host_inventory = defaultdict(dict)
            for row in cursor:
                info = {
                    "hostname": row["hostname"],
                    "mac_address": row["mac_address"],
                    "os_hint": row["os_hint"],
                    "vendor": row["vendor"],
                    "services": {},
                    "last_seen": row["last_seen"],
                }
                self.persisted_hosts_info[row["ip"]] = info
                self.host_inventory[row["ip"]] = dict(info)
            self.last_persisted_hosts = set(self.persisted_hosts_info.keys())
            for result in self.scan_results:
                ip = result["ip"]
                proto = (result["protocol"] or "TCP").upper()
                port_key = f"{int(result['port'])}/{proto}"
                if ip in self.host_inventory:
                    self.host_inventory[ip]["services"][port_key] = {
                        "service": result["service"],
                        "status": "ok",
                    }

    # --- scan orchestration ---
    def run_scan(self, targets, ports):
        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        try:
            with self.lock:
                self.scan_results.clear()
                self.host_inventory.clear()
                self.scan_status.update(
                    {
                        "progress": 0,
                        "total": 0,
                        "current_phase": "parsing",
                        "start_time": datetime.now(),
                        "results_count": 0,
                    }
                )
            self.logger.info(f"Starting scan {scan_id}: {targets}, ports: {ports}")

            target_ips = []
            for target in targets:
                target_ips.extend(self.parse_ip_range(target.strip()))

            self.logger.info(
                f"Parsed {len(target_ips)} target IPs: {target_ips[:5]}{'...' if len(target_ips) > 5 else ''}"
            )

            with self.lock:
                self.scan_status["current_phase"] = "discovery"

            alive_hosts = []
            for i, ip in enumerate(target_ips):
                if self.interrupted:
                    break
                self.logger.debug(f"Testing host {i+1}/{len(target_ips)}: {ip}")
                ping_result = self.ping_host(ip)
                self.logger.debug(f"Ping result for {ip}: {ping_result}")

                if ping_result:
                    alive_hosts.append(ip)
                    host_info = {"services": {}}
                    if self.config["enable_host_discovery"]:
                        hostname = self.get_hostname(ip)
                        if hostname:
                            host_info["hostname"] = hostname
                    self.host_inventory[str(ip)] = host_info
                    self.logger.info(f"Found host: {ip}")

                # Update progress during discovery
                if (
                    i % 10 == 0 or i == len(target_ips) - 1
                ):  # Update every 10 IPs or at the end
                    with self.lock:
                        self.scan_status["progress"] = i + 1
                        self.scan_status["total"] = len(target_ips)

            if not alive_hosts:
                self.logger.info("No alive hosts found")
                with self.lock:
                    self.scan_status["running"] = False
                    self.scan_status["current_phase"] = "completed"
                return

            if isinstance(ports, int):
                tcp_ports = list(range(1, ports + 1))
                # For UDP, scan common ports if user specified a large range, otherwise respect the exact range
                if ports > 1000:
                    udp_ports = [
                        53,
                        67,
                        69,
                        123,
                        161,
                        514,
                        1194,
                        4500,
                    ]  # Common UDP services
                else:
                    udp_ports = list(
                        range(1, ports + 1)
                    )  # Same range as TCP for smaller ranges
            else:
                tcp_ports = list(ports)
                udp_ports = list(
                    ports
                )  # Use same ports for UDP as TCP when specific ports given

            with self.lock:
                self.scan_status["current_phase"] = "tcp_scan"
                tcp_total = len(alive_hosts) * len(tcp_ports)
                udp_total = (
                    len(alive_hosts) * len(udp_ports)
                    if self.config["enable_udp_scan"]
                    else 0
                )
                self.scan_status["total"] = tcp_total + udp_total
                self.scan_status["progress"] = 0

            self.logger.info(
                f"Scan plan: TCP ports={len(tcp_ports)}, UDP ports={len(udp_ports) if self.config['enable_udp_scan'] else 0}, hosts={len(alive_hosts)}"
            )

            with ThreadPoolExecutor(max_workers=self.config["max_threads"]) as executor:
                tcp_futures = [
                    executor.submit(self.test_tcp_port, ip, port)
                    for ip in alive_hosts
                    for port in tcp_ports
                ]
                for future in as_completed(tcp_futures):
                    if self.interrupted:
                        break
                    try:
                        future.result()
                    except Exception:
                        continue

            if self.config["enable_udp_scan"] and not self.interrupted:
                with self.lock:
                    self.scan_status["current_phase"] = "udp_scan"
                with ThreadPoolExecutor(
                    max_workers=self.config["udp_threads"]
                ) as executor:
                    udp_futures = [
                        executor.submit(self.test_udp_port, ip, port)
                        for ip in alive_hosts
                        for port in udp_ports
                    ]
                    for future in as_completed(udp_futures):
                        if self.interrupted:
                            break
                        try:
                            future.result()
                        except Exception:
                            continue

            current_set = set(
                (r["ip"], int(r["port"]), r["protocol"]) for r in self.scan_results
            )
            last_set = set(self.last_persisted_results)
            new_findings = current_set - last_set
            removed_findings = last_set - current_set

            for res in self.scan_results:
                ip = res["ip"]
                port = int(res["port"])
                proto = res["protocol"].upper()
                key = f"{port}/{proto}"
                svc = res["service"]
                status = "new" if (ip, port, proto) in new_findings else "ok"
                if ip not in self.host_inventory:
                    self.host_inventory[ip] = {"services": {}}
                self.host_inventory[ip]["services"][key] = {
                    "service": svc,
                    "status": status,
                }

            if removed_findings:
                for ip, port, proto in removed_findings:
                    port_key = f"{port}/{proto}"
                    if ip not in self.host_inventory:
                        self.host_inventory[ip] = {"services": {}, "last_seen": None}
                    if port_key not in self.host_inventory[ip]["services"]:
                        self.host_inventory[ip]["services"][port_key] = {
                            "service": "previously seen",
                            "status": "removed",
                        }

            for ip, info in self.persisted_hosts_info.items():
                if ip not in self.host_inventory:
                    host_copy = dict(info)
                    host_copy.setdefault("services", {})
                    host_copy["status"] = "removed_host"
                    self.host_inventory[ip] = host_copy

            self.save_results_to_db(scan_id)

            # Update snapshots with CURRENT scan results only (not all recent results)
            # This preserves the ability to detect "new" ports in future scans
            current_scan_results = set(
                (r["ip"], int(r["port"]), r["protocol"]) for r in self.scan_results
            )

            # Add current results to the persisted set (don't replace it completely)
            self.last_persisted_results.update(current_scan_results)

            self.logger.info(
                f"Updated persisted results: {len(self.last_persisted_results)} total ports tracked"
            )
            for ip, host in self.host_inventory.items():
                self.persisted_hosts_info.setdefault(
                    ip,
                    {
                        "hostname": host.get("hostname"),
                        "mac_address": host.get("mac_address"),
                        "os_hint": host.get("os_hint"),
                        "vendor": host.get("vendor"),
                        "services": host.get("services", {}),
                        "last_seen": host.get("last_seen"),
                    },
                )
            self.last_persisted_hosts = set(self.persisted_hosts_info.keys())

            self.logger.info(
                f"Scan {scan_id} completed: {len(self.scan_results)} ports found"
            )

        except Exception as e:
            self.logger.error(f"Scan error: {e}")
            raise
        finally:
            with self.lock:
                self.scan_status["running"] = False
                self.scan_status["current_phase"] = "completed"
            try:
                self.scan_thread = None
            except Exception:
                pass

    def start_scan_async(self, targets, ports):
        with self.lock:
            if self.scan_thread and self.scan_thread.is_alive():
                return False, "Scan already running"
            self.scan_status["running"] = True
            self.scan_status["current_phase"] = "queued"
            self.scan_status["progress"] = 0
            self.scan_status["total"] = 0
            self.scan_status["start_time"] = datetime.now()
            self.scan_status["results_count"] = 0
            self.interrupted = False
            self.scan_thread = threading.Thread(
                target=self.run_scan, args=(targets, ports), daemon=True
            )
            self.scan_thread.start()
        return True, "Scan started"

    def stop_scan(self):
        """Request stop of the running scan."""
        with self.lock:
            if self.scan_thread and self.scan_thread.is_alive():
                self.interrupted = True
                return True, "Stop requested"
            return False, "No scan running"

    # --- scheduler ---
    def scheduler_loop(self):
        self.logger.info(
            "Scheduler started, interval=%s min",
            self.scheduler_config.get("interval_minutes"),
        )
        evt = self.scheduler_stop_event
        interval = max(1, int(self.scheduler_config.get("interval_minutes", 60)))
        while not evt.is_set():
            with self.lock:
                running = self.scan_thread and self.scan_thread.is_alive()
            if not running:
                targets = list(self.scheduler_config.get("targets") or [])
                ports = self.scheduler_config.get("ports")
                try:
                    ports_parsed = parse_ports_input(ports)
                except Exception:
                    ports_parsed = ports
                self.start_scan_async(targets, ports_parsed)
            evt.wait(interval * 60)
        self.logger.info("Scheduler stopped")

    def start_scheduler(self, config=None):
        with self.lock:
            if self.scheduler_thread and self.scheduler_thread.is_alive():
                return False, "Scheduler already running"
            if config:
                self.scheduler_config.update(config)
            self.scheduler_stop_event = threading.Event()
            self.scheduler_thread = threading.Thread(
                target=self.scheduler_loop, daemon=True
            )
            self.scheduler_thread.start()
            self.scheduler_config["enabled"] = True
        return True, "Scheduler started"

    def stop_scheduler(self):
        with self.lock:
            if not self.scheduler_thread or not self.scheduler_thread.is_alive():
                self.scheduler_config["enabled"] = False
                return False, "Scheduler not running"
            self.scheduler_stop_event.set()
            self.scheduler_config["enabled"] = False
        return True, "Scheduler stop requested"

    # --- inventory helpers ---
    def get_sorted_hosts(self):
        with self.lock:
            items = list(self.host_inventory.items())
        ip_items = []
        other_items = []
        for k, v in items:
            try:
                ip_val = ipaddress.IPv4Address(k)
                ip_items.append((ip_val, k, v))
            except Exception:
                other_items.append((k, v))
        ip_items.sort(key=lambda t: int(t[0]))
        sorted_hosts = {}
        for _, k, v in ip_items:
            sorted_hosts[k] = v
        for k, v in other_items:
            sorted_hosts[k] = v
        return sorted_hosts

    def build_host_inventory_from_db(self, hours=0):
        host_inv = {}
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            for row in conn.execute("SELECT * FROM hosts"):
                host_inv[row["ip"]] = {
                    "hostname": row["hostname"],
                    "mac_address": row["mac_address"],
                    "os_hint": row["os_hint"],
                    "vendor": row["vendor"],
                    "services": {},
                    "last_seen": row["last_seen"],
                }
            if hours and isinstance(hours, (int, float)) and hours > 0:
                q = conn.execute(
                    """
                    SELECT * FROM scan_results
                    WHERE timestamp > datetime('now', '-{} hours')
                    ORDER BY timestamp DESC
                """.format(
                        int(hours)
                    )
                )
            else:
                q = conn.execute("SELECT * FROM scan_results ORDER BY timestamp DESC")
            for row in q:
                ip = row["ip"]
                proto = (row["protocol"] or "TCP").upper()
                port_key = f"{int(row['port'])}/{proto}"
                svc = row["service"] or ""
                svc = re.sub(
                    r"open\|filtered", "filtered", svc, flags=re.IGNORECASE
                ).strip()
                h = host_inv.setdefault(
                    ip,
                    {
                        "hostname": None,
                        "mac_address": None,
                        "os_hint": None,
                        "vendor": None,
                        "services": {},
                        "last_seen": row["timestamp"],
                    },
                )
                h["services"][port_key] = {"service": svc, "status": "ok"}
        return host_inv

    def get_combined_hosts(self, hours=24):
        """Return union of persisted DB hosts and current in-memory inventory (sorted)."""
        db_inv = self.build_host_inventory_from_db(hours=hours)
        combined = {}
        # start with DB hosts
        for ip, info in db_inv.items():
            combined[ip] = dict(info)
            combined[ip].setdefault("services", {})
        # overlay in-memory
        with self.lock:
            for ip, info in self.host_inventory.items():
                entry = combined.setdefault(ip, {})
                # merge fields
                entry["hostname"] = info.get("hostname") or entry.get("hostname")
                entry["mac_address"] = info.get("mac_address") or entry.get(
                    "mac_address"
                )
                entry["os_hint"] = info.get("os_hint") or entry.get("os_hint")
                entry["vendor"] = info.get("vendor") or entry.get("vendor")
                entry.setdefault("services", {})
                # merge services (in-memory overrides)
                for port_key, svc in info.get("services", {}).items():
                    entry["services"][port_key] = svc
        # sort
        try:
            sorted_keys = sorted(
                combined.keys(), key=lambda k: int(ipaddress.IPv4Address(k))
            )
            return {k: combined[k] for k in sorted_keys}
        except Exception:
            return combined


# Global scanner instance
db_path = os.path.join(os.environ.get("DATA_DIR", "./data"), "scans.db")
os.makedirs(os.path.dirname(db_path), exist_ok=True)
scanner = NetworkScanner(db_path=db_path)
scanner.load_recent_results()

# HTML template moved to templates/index.html


# --- API Routes (unchanged logic) ---
@app.route("/")
def dashboard():
    hosts = scanner.get_combined_hosts(hours=24)
    total_hosts = len(hosts)
    total_ports = sum(len(h.get("services", {})) for h in hosts.values())
    total_services = len(
        {
            svc["service"]
            for h in hosts.values()
            for svc in h.get("services", {}).values()
        }
    )
    stats = {
        "total_hosts": total_hosts,
        "total_ports": total_ports,
        "total_services": total_services,
    }
    return render_template("index.html", hosts=hosts, stats=stats)


# Allow preflight (OPTIONS) and return helpful JSON from scan start
@app.route("/api/scan/start", methods=["POST", "OPTIONS"])
@debug_wrap
def start_scan():
    if request.method == "OPTIONS":
        return jsonify({"success": True, "message": "ok (preflight)"}), 200
    data = request.get_json() or {}
    app.logger.info("API /api/scan/start called with: %s", data)
    targets = data.get("targets", ["192.168.1.0/24"])

    ports_input = data.get(
        "ports", 1000
    )  # Default to first 1000 ports if not specified

    try:
        parsed = parse_ports_input(ports_input)
        app.logger.info(
            "Parsed ports_input: %s -> %s",
            ports_input,
            (
                type(parsed).__name__
                if isinstance(parsed, int)
                else f"list[{len(parsed)}]"
            ),
        )
    except Exception as e:
        app.logger.warning("Invalid ports input: %s", e)
        return jsonify({"success": False, "message": f"Invalid ports: {e}"}), 400

    app.logger.info("Starting scan with targets=%s ports=%s", targets, parsed)
    success, message = scanner.start_scan_async(targets, parsed)
    app.logger.info("start_scan result: %s, %s", success, message)
    return jsonify({"success": success, "message": message})


# Stop scan accepts POST and OPTIONS for browser preflight
@app.route("/api/scan/stop", methods=["POST", "OPTIONS"])
@debug_wrap
def stop_scan_route():
    if request.method == "OPTIONS":
        return jsonify({"success": True, "message": "ok (preflight)"}), 200
    app.logger.info("API /api/scan/stop called")
    success, message = scanner.stop_scan()
    app.logger.info("stop_scan result: %s, %s", success, message)
    return jsonify({"success": success, "message": message})


# Clear results (in-memory) allow preflight
@app.route("/api/results/clear", methods=["DELETE", "OPTIONS"])
@debug_wrap
def clear_results():
    if request.method == "OPTIONS":
        return jsonify({"success": True, "message": "ok (preflight)"}), 200
    with scanner.lock:
        scanner.scan_results.clear()
        scanner.host_inventory.clear()
    return jsonify({"success": True})


# DB clear: accept DELETE and OPTIONS
@app.route("/api/db/clear", methods=["DELETE", "OPTIONS"])
@debug_wrap
def clear_db():
    if request.method == "OPTIONS":
        return jsonify({"success": True, "message": "ok (preflight)"}), 200
    app.logger.info("API /api/db/clear called")
    try:
        with scanner.lock:
            db_file = scanner.db_path
            if os.path.exists(db_file):
                try:
                    os.remove(db_file)
                    app.logger.debug("Removed DB file: %s", db_file)
                except Exception:
                    app.logger.exception(
                        "Failed to remove DB file; will attempt reinit"
                    )

            scanner.init_database()
            app.logger.debug("Recreated DB schema at %s", scanner.db_path)

            # clear in-memory
            scanner.scan_results.clear()
            scanner.host_inventory.clear()
            scanner.persisted_hosts_info.clear()
            scanner.last_persisted_results.clear()
            scanner.last_persisted_hosts.clear()

            try:
                scanner.load_recent_results()
            except Exception:
                app.logger.exception("Failed to reload results after DB recreate")

        app.logger.info("Database cleared and in-memory state reloaded")
        return jsonify(
            {
                "success": True,
                "message": "Database cleared and in-memory state reloaded",
            }
        )
    except Exception as e:
        app.logger.exception("Error clearing DB")
        return jsonify({"success": False, "message": str(e)}), 500


# Scheduler start: accept OPTIONS, validate and return effective config
@app.route("/api/scheduler/start", methods=["POST", "OPTIONS"])
@debug_wrap
def api_scheduler_start():
    if request.method == "OPTIONS":
        return jsonify({"success": True, "message": "ok (preflight)"}), 200
    data = request.get_json() or {}
    app.logger.info("API /api/scheduler/start called with: %s", data)
    cfg = {}
    if "targets" in data:
        cfg["targets"] = data["targets"]
    if "ports" in data:
        ports_val = data["ports"]
        try:
            parsed_ports = parse_ports_input(ports_val)
            cfg["ports"] = parsed_ports
            cfg["ports_display"] = str(ports_val)  # Always show original user input
            app.logger.info(
                "Scheduler ports: %s -> %s",
                ports_val,
                (
                    type(parsed_ports).__name__
                    if isinstance(parsed_ports, int)
                    else f"list[{len(parsed_ports)}]"
                ),
            )
        except Exception as e:
            app.logger.warning("Invalid scheduler ports: %s", e)
            return (
                jsonify({"success": False, "message": f"Invalid scheduler ports: {e}"}),
                400,
            )
    if "interval_minutes" in data:
        try:
            cfg["interval_minutes"] = int(data["interval_minutes"])
        except Exception:
            app.logger.debug("Invalid interval_minutes ignored")

    success, message = scanner.start_scheduler(cfg)
    app.logger.info("start_scheduler result: %s, %s", success, message)
    # return resulting scheduler config and running state for UI
    with scanner.lock:
        running = bool(scanner.scheduler_thread and scanner.scheduler_thread.is_alive())
        conf = dict(scanner.scheduler_config)
    return jsonify(
        {"success": success, "message": message, "running": running, "config": conf}
    )


# Scheduler stop: accept OPTIONS
@app.route("/api/scheduler/stop", methods=["POST", "OPTIONS"])
@debug_wrap
def api_scheduler_stop():
    if request.method == "OPTIONS":
        return jsonify({"success": True, "message": "ok (preflight)"}), 200
    success, message = scanner.stop_scheduler()
    app.logger.info("stop_scheduler result: %s, %s", success, message)
    return jsonify({"success": success, "message": message})


# Scheduler status: return flat keys the UI expects
@app.route("/api/scheduler/status", methods=["GET", "OPTIONS"])
@debug_wrap
def scheduler_status():
    if request.method == "OPTIONS":
        return jsonify({"success": True, "message": "ok (preflight)"}), 200
    with scanner.lock:
        cfg = dict(scanner.scheduler_config)
        running = bool(scanner.scheduler_thread and scanner.scheduler_thread.is_alive())
    # normalize to top-level fields expected by UI
    # Use ports_display for UI, fallback to ports if not available
    ports_display = cfg.get("ports_display", cfg.get("ports"))
    return jsonify(
        {
            "running": running,
            "enabled": bool(cfg.get("enabled")),
            "targets": cfg.get("targets"),
            "ports": ports_display,
            "interval_minutes": cfg.get("interval_minutes"),
        }
    )


@app.route("/api/scan/status", methods=["GET", "OPTIONS"])
@debug_wrap
def scan_status():
    if request.method == "OPTIONS":
        return jsonify({"success": True, "message": "ok (preflight)"}), 200
    with scanner.lock:
        status = dict(scanner.scan_status)
        status["running"] = bool(scanner.scan_thread and scanner.scan_thread.is_alive())
        # Convert datetime to string for JSON serialization
        if status.get("start_time"):
            status["start_time"] = status["start_time"].isoformat()
    app.logger.debug("Scan status response: %s", status)
    return jsonify(status)


@app.route("/api/results/export", methods=["GET", "OPTIONS"])
@debug_wrap
def export_results():
    if request.method == "OPTIONS":
        return jsonify({"success": True, "message": "ok (preflight)"}), 200
    hosts = scanner.get_combined_hosts(hours=24)
    export_data = {
        "timestamp": datetime.now().isoformat(),
        "total_hosts": len(hosts),
        "total_ports": sum(len(h.get("services", {})) for h in hosts.values()),
        "hosts": hosts,
    }

    response = app.response_class(
        response=json.dumps(export_data, indent=2, default=str),
        status=200,
        mimetype="application/json",
    )
    response.headers["Content-Disposition"] = (
        f"attachment; filename=scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    return response


# simple health/debug endpoints to verify POSTs reach the server
@app.route("/api/ping", methods=["GET", "POST", "OPTIONS"])
@debug_wrap
def api_ping():
    """Health/debug ping — accept GET and POST to match various clients."""
    app.logger.info("API /api/ping called, method=%s", request.method)
    if request.method == "OPTIONS":
        return jsonify({"ok": True, "method": "OPTIONS"})
    # accept optional JSON payload
    data = None
    try:
        data = request.get_json(silent=True)
    except Exception:
        data = request.get_data(as_text=True)
    return jsonify(
        {
            "ok": True,
            "method": request.method,
            "received": data,
            "time": datetime.utcnow().isoformat(),
        }
    )


@app.route("/api/logs", methods=["GET"])
@debug_wrap
def api_logs():
    """Return last N lines from configured log file for quick debugging."""
    log_file = os.environ.get("LOG_FILE") or os.path.join(
        os.environ.get("DATA_DIR", "./data"), "scanner.log"
    )
    try:
        n = int(request.args.get("lines", "200"))
    except Exception:
        n = 200

    try:
        # Simple, robust approach: read file and return last n lines.
        # File may be large; this is acceptable for debugging.
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()[-n:]
    except FileNotFoundError:
        return (
            jsonify({"success": False, "message": f"Log file not found: {log_file}"}),
            404,
        )
    except Exception as e:
        app.logger.exception("Failed to read log file")
        return jsonify({"success": False, "message": str(e)}), 500

    # strip trailing newlines for JSON cleanliness
    lines = [ln.rstrip("\n") for ln in lines]
    return jsonify({"success": True, "log_file": log_file, "lines": lines})


def main():
    parser = argparse.ArgumentParser(description="Network Scanner Web App")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind")
    parser.add_argument("--port", type=int, default=8888, help="Port to bind")
    parser.add_argument("--debug", action="store_true", help="Debug mode")
    args = parser.parse_args()
    print(f"Starting Network Scanner on http://{args.host}:{args.port}")
    print("Press Ctrl+C to stop")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
