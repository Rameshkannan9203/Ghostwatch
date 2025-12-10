#!/usr/bin/env python3
"""
GhostWatch v3 - Final (Defensive Network Monitor)

Features:
 - Scary banner
 - Dark hacker theme
 - Network scan (nmap or ping-sweep fallback)
 - WHOIS summary
 - Single IP/Device-ID monitor + beacon generator & HTTP listener
 - Range monitor with new/down detection
 - JSON logging
 - Email alerts with verification, debug mode, fallback SMTP list and retry logic
 - Telegram alerts
 - Optional install to /usr/bin and systemd installer (explicit confirmation required)
"""

import os
import sys
import time
import json
import uuid
import socket
import subprocess
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Optional dependency
try:
    import requests
except Exception:
    requests = None

# ----------------------------
# Paths & Logs
# ----------------------------
HOME = os.path.expanduser("~")
LOG_DIR = os.path.join(HOME, "ghostwatch_logs")
os.makedirs(LOG_DIR, exist_ok=True)

EVENT_LOG = os.path.join(LOG_DIR, "events.json")
SCAN_JSON = os.path.join(LOG_DIR, "scan.json")
ALIVE_JSON = os.path.join(LOG_DIR, "alive.json")
OFFLINE_JSON = os.path.join(LOG_DIR, "offline.json")
SINGLE_JSON = os.path.join(LOG_DIR, "single_monitor.json")
DEVICE_MAP_JSON = os.path.join(LOG_DIR, "device_map.json")

# ----------------------------
# Colors (dark hacker theme)
# ----------------------------
RESET = "\033[0m"
BOLD = "\033[1m"
C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_CYAN = "\033[96m"
C_PURPLE = "\033[95m"
C_GRAY = "\033[90m"
C_WHITE = "\033[97m"

def info(s): print(f"{C_CYAN}{s}{RESET}")
def success(s): print(f"{C_GREEN}{s}{RESET}")
def warn(s): print(f"{C_YELLOW}{s}{RESET}")
def error(s): print(f"{C_RED}{s}{RESET}")
def accent(s): print(f"{C_PURPLE}{s}{RESET}")
def dim(s): print(f"{C_GRAY}{s}{RESET}")
def bold(s): print(f"{BOLD}{C_WHITE}{s}{RESET}")

# ----------------------------
# Banner
# ----------------------------
def scary_banner():
    print(f"""{C_PURPLE}
                .:::::::::::.
             .:::''':::::::''''::.
           .:::'      :::::      ':::.
          :::'   (👁)   :::   (👁)   ':::
         :::            :::            :::
         :::     ▄██████████████▄      :::
         :::    ██████████████████     :::
          :::   ██████████████████    :::
           '::: ▀████████████████▀  .::'
             ':::..             ..:::'
                ':::::::::::::::::'
                     ':::::::::'
                     .:::::::::.
                   .:::::::::::::.
                 .:::::::' '::::::.

██╗    ██╗ █████╗ ████████╗ ██████╗ ██╗  ██╗
██║    ██║██╔══██╗╚══██╔══╝██╔════╝ ██║  ██║
██║ █╗ ██║███████║   ██║   ██║  ███╗███████║
██║███╗██║██╔══██║   ██║   ██║   ██║██╔══██║
╚███╔███╔╝██║  ██║   ██║   ██║   ╚██████╔╝██║  ██║
 ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝

         G H O S T W A T C H
{RESET}""")
    dim("Loaded: nmap | whois | ping | json-logger")
    dim("Mode: Defensive – lab / authorized use only")
    print()

# ----------------------------
# Helpers
# ----------------------------
def now(): return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def append_json(path, entry):
    arr = []
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                arr = json.load(f)
        except Exception:
            arr = []
    arr.append(entry)
    with open(path, "w") as f:
        json.dump(arr, f, indent=2)

def write_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def has_cmd(cmd):
    return subprocess.call(["which", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def run_cmd(cmd):
    try:
        return subprocess.getoutput(cmd)
    except Exception:
        return ""

# ----------------------------
# Network + DNS checks
# ----------------------------
def dns_resolves(host="smtp.gmail.com"):
    try:
        socket.gethostbyname(host)
        return True
    except Exception:
        return False

def check_port(host, port, timeout=5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

# ----------------------------
# Alerts manager with debug, fallback, retry
# ----------------------------
class Alerts:
    def __init__(self):
        # email config
        self.email_enabled = False
        self.email_from = ""
        self.email_pass = ""
        self.email_to = ""
        # telegram config
        self.telegram_enabled = False
        self.tg_token = ""
        self.tg_chat = ""
        # debug and behavior
        self.debug_mode = "normal"   # normal | verbose
        self.debug_scope = "setup_only"  # setup_only | always
        # fallback SMTP servers list (ordered)
        # each entry: (host, port, use_ssl_flag, description)
        self.smtp_fallbacks = [
            ("smtp.gmail.com", 587, False, "Gmail STARTTLS (primary)"),
            ("smtp.gmail.com", 465, True, "Gmail SSL (fallback)"),
            ("smtp-relay.gmail.com", 587, False, "Gmail relay (if configured)"),
            ("localhost", 25, False, "Local MTA (if present)")
        ]
        self.retry_attempts = 3

    def configure_interactive(self):
        print()
        info("Email alerts (Gmail) setup: use an App Password if using Gmail.")
        # choose debug mode
        ch = input("Email debug mode: (1) Normal (2) Verbose (recommended for troubleshooting) [1/2]: ").strip() or "1"
        self.debug_mode = "verbose" if ch == "2" else "normal"
        ds = input("Debug scope: (1) Setup only (2) Always print debug during sends) [1/2]: ").strip() or "1"
        self.debug_scope = "always" if ds == "2" else "setup_only"

        if input("Enable Email alerts? (y/n): ").strip().lower() == "y":
            self.email_enabled = True
            self.email_from = input("Sender Gmail: ").strip()
            self.email_pass = input("Gmail App Password: ").strip()
            self.email_to = input("Recipient email: ").strip()

            # verify DNS
            if not dns_resolves("smtp.gmail.com"):
                error("DNS cannot resolve smtp.gmail.com. Fix DNS (e.g., add 8.8.8.8 to /etc/resolv.conf or set DNS in systemd unit).")
                self.email_enabled = False
            else:
                # attempt connection and authentication using fallback list + retry
                ok = self._test_smtp_with_fallbacks()
                if ok:
                    success("Email configuration OK.")
                else:
                    error("Email configuration failed. Email alerts disabled.")
                    self.email_enabled = False

        print()
        info("Telegram alerts setup")
        if input("Enable Telegram alerts? (y/n): ").strip().lower() == "y":
            if requests is None:
                warn("Python 'requests' is not installed. Install: sudo apt install python3-requests OR pip3 install requests")
                self.telegram_enabled = False
            else:
                self.telegram_enabled = True
                self.tg_token = input("Telegram Bot token: ").strip()
                self.tg_chat = input("Telegram Chat ID: ").strip()
                # quick token test
                try:
                    r = requests.post(f"https://api.telegram.org/bot{self.tg_token}/getMe", timeout=8)
                    if r.status_code == 200 and r.json().get("ok"):
                        success("Telegram token OK.")
                    else:
                        error("Telegram token appears invalid.")
                        self.telegram_enabled = False
                except Exception as e:
                    error(f"Telegram test failed: {e}")
                    self.telegram_enabled = False

    def _print_dbg(self, *args):
        if self.debug_mode == "verbose":
            print(C_GRAY + "[SMTP DEBUG]" + RESET, *args)

    def _test_smtp_server(self, host, port, use_ssl=False, attempts=2):
        """Test SMTP server connectivity and (optional) login attempt"""
        import smtplib
        try:
            if use_ssl:
                self._print_dbg(f"Trying SSL {host}:{port}")
                server = smtplib.SMTP_SSL(host, port, timeout=8)
            else:
                self._print_dbg(f"Trying STARTTLS {host}:{port}")
                server = smtplib.SMTP(host, port, timeout=8)
                server.ehlo()
                if port == 587:
                    server.starttls()
                    server.ehlo()
            # debug level if requested
            if self.debug_mode == "verbose":
                server.set_debuglevel(1)
            # try login if credentials provided
            try:
                if self.email_from and self.email_pass:
                    server.login(self.email_from, self.email_pass)
                    self._print_dbg("AUTH succeeded")
                server.quit()
                return True, None
            except Exception as e:
                server.quit()
                return False, str(e)
        except Exception as e:
            return False, str(e)

    def _test_smtp_with_fallbacks(self):
        """Try fallback list to validate connectivity and auth"""
        last_err = None
        for host, port, use_ssl, desc in self.smtp_fallbacks:
            self._print_dbg(f"Testing {desc} -> {host}:{port} (SSL={use_ssl})")
            if not dns_resolves(host) and host != "localhost":
                self._print_dbg(f"DNS fail for {host}")
                last_err = f"DNS fail for {host}"
                continue
            if not check_port(host, port) and host != "localhost":
                self._print_dbg(f"Port {port} unreachable on {host}")
                last_err = f"Port {port} unreachable on {host}"
                continue
            ok, err = self._test_smtp_server(host, port, use_ssl)
            if ok:
                return True
            else:
                last_err = err
                self._print_dbg(f"Server {host}:{port} test failed: {err}")
        append_json(EVENT_LOG, {"time": now(), "event": "email_test_failed", "error": last_err})
        return False

    def send(self, subject, body):
        timestamp = now()
        full = f"{subject}\nTime: {timestamp}\n\n{body}"

        if self.email_enabled:
            sent = False
            last_error = None
            # try fallback servers in order; for each server retry few times with exponential backoff
            for host, port, use_ssl, desc in self.smtp_fallbacks:
                if host != "localhost" and not dns_resolves(host):
                    self._print_dbg(f"Skipping {host}: cannot resolve")
                    last_error = f"DNS fail {host}"
                    continue
                for attempt in range(1, self.retry_attempts + 1):
                    backoff = (2 ** (attempt-1))
                    try:
                        import smtplib
                        from email.mime.text import MIMEText
                        msg = MIMEText(full)
                        msg['Subject'] = f"GhostWatch: {subject}"
                        msg['From'] = self.email_from
                        msg['To'] = self.email_to
                        if use_ssl:
                            if self.debug_scope == "always" or self.debug_mode == "verbose":
                                print(C_GRAY + f"[DEBUG] Trying SSL {host}:{port} attempt {attempt}" + RESET)
                            server = smtplib.SMTP_SSL(host, port, timeout=10)
                        else:
                            if self.debug_scope == "always" or self.debug_mode == "verbose":
                                print(C_GRAY + f"[DEBUG] Trying STARTTLS {host}:{port} attempt {attempt}" + RESET)
                            server = smtplib.SMTP(host, port, timeout=10)
                            server.ehlo()
                            if port == 587:
                                server.starttls()
                                server.ehlo()
                        # set smtplib debug if verbose
                        if self.debug_scope == "always" or self.debug_mode == "verbose":
                            server.set_debuglevel(1)
                        # login if credentials available
                        if self.email_from and self.email_pass:
                            server.login(self.email_from, self.email_pass)
                        server.send_message(msg)
                        server.quit()
                        success("[+] Email sent")
                        append_json(EVENT_LOG, {"time": now(), "event": "email_sent", "subject": subject, "server": f"{host}:{port}"})
                        sent = True
                        break
                    except Exception as e:
                        last_error = str(e)
                        error(f"[!] Email attempt failed ({host}:{port}): {e}")
                        append_json(EVENT_LOG, {"time": now(), "event": "email_send_attempt_failed", "server": f"{host}:{port}", "error": str(e)})
                        time.sleep(backoff)
                if sent:
                    break
            if not sent:
                error("[!] All email attempts failed. See events log for details.")
                append_json(EVENT_LOG, {"time": now(), "event": "email_all_failed", "last_error": last_error})

        if self.telegram_enabled:
            if requests is None:
                error("[!] requests missing; cannot send Telegram")
            else:
                try:
                    url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
                    r = requests.post(url, data={"chat_id": self.tg_chat, "text": full}, timeout=8)
                    if r.status_code == 200 and r.json().get("ok"):
                        success("[+] Telegram sent")
                        append_json(EVENT_LOG, {"time": now(), "event": "telegram_sent", "subject": subject})
                    else:
                        error("[!] Telegram send failed")
                        append_json(EVENT_LOG, {"time": now(), "event": "telegram_failed", "status_code": r.status_code, "response": r.text})
                except Exception as e:
                    error(f"[!] Telegram send failed: {e}")
                    append_json(EVENT_LOG, {"time": now(), "event": "telegram_failed", "error": str(e)})

# ----------------------------
# Network functions (scan/ping/whois)
# ----------------------------
def ping_alive(ip):
    out = run_cmd(f"ping -c 1 -W 1 {ip}")
    return ("1 received" in out) or ("bytes from" in out) or ("1 packets received" in out)

def nmap_ping_scan(target):
    if has_cmd("nmap"):
        out = run_cmd(f"nmap -sn {target}")
        ips = []
        for line in out.splitlines():
            if "Nmap scan report for" in line:
                ips.append(line.split()[-1])
        return ips
    if "/" in target:
        base = target.split("/")[0]
        parts = base.split(".")
        if len(parts) == 4:
            net = ".".join(parts[:3]) + "."
            ips = []
            for i in range(1,255):
                ip = net + str(i)
                if ping_alive(ip):
                    ips.append(ip)
            return ips
    return []

def whois_summary(ip):
    if not has_cmd("whois"):
        return "(whois missing)"
    out = run_cmd(f"whois {ip}")
    lines = []
    for key in ("OrgName","Organization","Org-Name","country","Country"):
        for l in out.splitlines():
            if key.lower() in l.lower():
                lines.append(l.strip())
                if len(lines) >= 3:
                    break
        if len(lines) >= 3:
            break
    return "\n".join(lines) if lines else "(no whois info)"

# ----------------------------
# Device-ID & beacon
# ----------------------------
def generate_device_id(prefix="GHOST"):
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"

def create_beacon_script(monitor_host="127.0.0.1", monitor_port=8080, device_id=None, filename="beacon.sh"):
    if device_id is None:
        device_id = generate_device_id()
    script = f'''#!/bin/bash
# GhostWatch beacon (lab use only)
DEVICE_ID="{device_id}"
MONITOR="{monitor_host}"
PORT="{monitor_port}"
while true; do
  curl -s "http://$MONITOR:$PORT/ping?device_id=$DEVICE_ID" >/dev/null 2>&1
  sleep 60
done
'''
    with open(filename, "w") as f:
        f.write(script)
    os.chmod(filename, 0o755)
    return filename, device_id

# ----------------------------
# Beacon HTTP server
# ----------------------------
DEVICE_MAP = {}

class BeaconHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/ping":
            self.send_response(404); self.end_headers(); return
        qs = parse_qs(parsed.query)
        did = qs.get("device_id", [None])[0]
        if not did:
            self.send_response(400); self.end_headers(); self.wfile.write(b"missing device_id"); return
        ip = self.client_address[0]
        ts = now()
        DEVICE_MAP[did] = {"ip": ip, "last_seen": ts}
        append_json(EVENT_LOG, {"time": ts, "event": "beacon", "device_id": did, "ip": ip})
        self.send_response(200); self.end_headers(); self.wfile.write(b"OK")

def start_beacon_server(host="0.0.0.0", port=8080):
    server = HTTPServer((host, port), BeaconHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server

# ----------------------------
# Monitoring flows
# ----------------------------
def network_scan_flow(alerts):
    info("Enter target to scan (CIDR or host):")
    target = input("> ").strip()
    if not target:
        warn("No target entered.")
        return
    info(f"Scanning {target} ...")
    ips = nmap_ping_scan(target)
    success(f"Found {len(ips)} hosts.")
    results = []
    for ip in ips:
        who = whois_summary(ip)
        bold(f"Host: {ip}")
        dim(f"WHOIS:\n{who}")
        results.append({"time": now(), "ip": ip, "whois": who})
    write_json(SCAN_JSON, results)
    append_json(EVENT_LOG, {"time": now(), "event": "scan", "target": target, "count": len(ips)})
    success(f"Saved scan -> {SCAN_JSON}")

def monitor_single_flow(alerts):
    info("Single Device / IP Monitor")
    print("1) Monitor by IP")
    print("2) Generate Device-ID + beacon script (run on device)")
    choice = input("> ").strip()
    if choice == "2":
        mh = input("Monitor host/IP (this machine IP reachable by device) [127.0.0.1]: ").strip() or "127.0.0.1"
        port = int(input("HTTP listener port [8080]: ").strip() or "8080")
        fname, did = create_beacon_script(mh, port)
        success(f"Beacon script: {fname}  DEVICE_ID={did}")
        if input("Start HTTP beacon listener now? (y/n): ").strip().lower() == "y":
            start_beacon_server(host="0.0.0.0", port=port)
            success(f"Beacon listener running on port {port}")
        return
    target = input("Enter IP or DEVICE_ID: ").strip()
    if target.upper().startswith("GHOST-"):
        port = int(input("Ensure beacon listener port [8080]: ").strip() or "8080")
        start_beacon_server(host="0.0.0.0", port=port)
        success("Beacon listener started.")
        prev = None
        try:
            while True:
                rec = DEVICE_MAP.get(target)
                if rec:
                    last = datetime.strptime(rec["last_seen"], "%Y-%m-%d %H:%M:%S")
                    delta = (datetime.now() - last).total_seconds()
                    online = delta < 180
                    if online and prev != "ONLINE":
                        m = f"{target} ONLINE via {rec['ip']}"
                        success(m); alerts.send("Device Online", m)
                        append_json(SINGLE_JSON, {"time": now(), "device_id": target, "event": "online", "ip": rec['ip']})
                        prev = "ONLINE"
                    elif (not online) and prev == "ONLINE":
                        m = f"{target} OFFLINE"
                        warn(m); alerts.send("Device Offline", m)
                        append_json(SINGLE_JSON, {"time": now(), "device_id": target, "event": "offline"})
                        prev = "OFFLINE"
                else:
                    if prev != "UNKNOWN":
                        dim(f"Waiting for beacon {target}...")
                        prev = "UNKNOWN"
                time.sleep(10)
        except KeyboardInterrupt:
            info("Stopping device-id monitor.")
        return
    # IP mode
    ip = target
    info(f"Monitoring IP {ip}. Ctrl+C to stop.")
    last = None
    try:
        while True:
            alive = ping_alive(ip)
            if alive and last != True:
                m = f"[ONLINE] {ip}"
                success(m); alerts.send("Host Online", m)
                append_json(SINGLE_JSON, {"time": now(), "ip": ip, "status": "ONLINE"})
                append_json(EVENT_LOG, {"time": now(), "event": "single_online", "ip": ip})
                last = True
            elif (not alive) and last != False:
                m = f"[OFFLINE] {ip}"
                warn(m); alerts.send("Host Offline", m)
                append_json(SINGLE_JSON, {"time": now(), "ip": ip, "status": "OFFLINE"})
                append_json(EVENT_LOG, {"time": now(), "event": "single_offline", "ip": ip})
                last = False
            time.sleep(5)
    except KeyboardInterrupt:
        info("Stopping single IP monitoring.")

def parse_range_input(raw):
    raw = raw.strip()
    if "/" in raw:
        return raw
    if "-" in raw:
        a,b = raw.split("-",1)
        return (a.strip(), b.strip())
    return raw

def ips_from_range(descr):
    if isinstance(descr, tuple):
        start,end = descr
        sa = list(map(int, start.split(".")))
        ea = list(map(int, end.split(".")))
        ips=[]
        cur=sa[:]
        while True:
            ips.append(".".join(map(str, cur)))
            if cur == ea:
                break
            cur[3]+=1
            for i in (3,2,1):
                if cur[i]>255:
                    cur[i]=0
                    cur[i-1]+=1
        return ips
    elif isinstance(descr, str) and "/" in descr:
        return nmap_ping_scan(descr) if has_cmd("nmap") else []
    else:
        return [descr]

def range_monitor_flow(alerts):
    info("Enter CIDR or range (e.g. 192.168.1.0/24 or 192.168.1.10-192.168.1.50):")
    raw = input("> ").strip()
    if not raw:
        warn("No input.")
        return
    parsed = parse_range_input(raw)
    iplist = ips_from_range(parsed)
    info(f"Monitoring {len(iplist)} addresses.")
    known = set()
    if os.path.exists(ALIVE_JSON):
        try:
            known = set([e["ip"] for e in json.load(open(ALIVE_JSON))])
        except Exception:
            known = set()
    try:
        while True:
            live = set([ip for ip in iplist if ping_alive(ip)])
            new = live - known
            down = known - live
            if new:
                for ip in sorted(new):
                    m = f"[NEW] {ip}"
                    success(m)
                    w = whois_summary(ip)
                    append_json(EVENT_LOG, {"time": now(), "event": "new_host", "ip": ip, "whois": w})
                    alerts.send("New Host", f"{ip}\n{w}")
                write_json(ALIVE_JSON, [{"time": now(), "ip": ip} for ip in sorted(live)])
            if down:
                for ip in sorted(down):
                    m = f"[DOWN] {ip}"
                    warn(m)
                    append_json(EVENT_LOG, {"time": now(), "event": "host_down", "ip": ip})
                    append_json(OFFLINE_JSON, {"time": now(), "ip": ip})
                    alerts.send("Host Offline", ip)
                write_json(OFFLINE_JSON, [{"time": now(), "ip": ip} for ip in sorted(down)])
            known = live
            time.sleep(10)
    except KeyboardInterrupt:
        info("Stopping range monitor.")

# ----------------------------
# Installation helpers (explicit permission)
# ----------------------------
def install_to_usr_bin():
    dest = "/usr/bin/ghostwatch"
    src = os.path.abspath(sys.argv[0])
    if src == dest:
        success("Already at /usr/bin/ghostwatch")
        return
    info(f"This will copy the script to {dest} (requires sudo).")
    if input("Proceed? (y/n): ").strip().lower() != "y":
        info("Cancelled.")
        return
    try:
        subprocess.check_call(["sudo","cp",src,dest])
        subprocess.check_call(["sudo","chmod","+x",dest])
        success(f"Copied to {dest}")
        append_json(EVENT_LOG, {"time": now(), "event": "installed_usr_bin", "path": dest})
    except Exception as e:
        error(f"Install failed: {e}")

def create_systemd_service():
    info("This will create /etc/systemd/system/ghostwatch.service and enable it (requires sudo).")
    if input("Proceed? (y/n): ").strip().lower() != "y":
        info("Cancelled.")
        return
    svc = """[Unit]
Description=GhostWatch Monitor
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /usr/bin/ghostwatch
Environment=PYTHONUNBUFFERED=1
DNS=8.8.8.8 1.1.1.1
Restart=always
RestartSec=5
User=root
WorkingDirectory=/

[Install]
WantedBy=multi-user.target
"""
    try:
        tmp="/tmp/ghostwatch.service"
        with open(tmp,"w") as f:
            f.write(svc)
        subprocess.check_call(["sudo","mv",tmp,"/etc/systemd/system/ghostwatch.service"])
        subprocess.check_call(["sudo","systemctl","daemon-reload"])
        subprocess.check_call(["sudo","systemctl","enable","ghostwatch"])
        subprocess.check_call(["sudo","systemctl","start","ghostwatch"])
        success("Systemd service installed and started.")
        append_json(EVENT_LOG, {"time": now(), "event": "systemd_installed"})
    except Exception as e:
        error(f"Systemd installation failed: {e}")
        warn("You can create the file manually and run: sudo systemctl daemon-reload && sudo systemctl enable ghostwatch && sudo systemctl start ghostwatch")

# ----------------------------
# Main
# ----------------------------
def main():
    accent("Recommended: nmap, whois, curl, python3-requests (optional)")
    for cmd,pkg in [("nmap","nmap"),("whois","whois"),("curl","curl")]:
        if has_cmd(cmd):
            success(f"{cmd} OK")
        else:
            warn(f"{cmd} missing (recommended)")

    scary_banner()
    alerts = Alerts()
    alerts.configure_interactive()

    while True:
        print()
        bold("MAIN MENU")
        print("1) Network Scan (WHOIS etc.)")
        print("2) Single Device / IP Monitor (IP or Device-ID)")
        print("3) Network Range Monitor (CIDR or range)")
        print("4) Install to /usr/bin (requires sudo)")
        print("5) Install systemd service (requires sudo)")
        print("6) Exit")
        choice = input("Select > ").strip()
        if choice == "1":
            network_scan_flow(alerts)
        elif choice == "2":
            monitor_single_flow(alerts)
        elif choice == "3":
            range_monitor_flow(alerts)
        elif choice == "4":
            install_to_usr_bin()
        elif choice == "5":
            create_systemd_service()
        elif choice == "6" or choice.lower() == "exit":
            info("Exiting GhostWatch.")
            break
        else:
            warn("Invalid option.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        info("\nInterrupted. Exiting.")
        sys.exit(0)
