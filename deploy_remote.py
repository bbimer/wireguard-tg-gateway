import os
import sys
import paramiko

if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

from dotenv import load_dotenv

load_dotenv()

HOST = sys.argv[1] if len(sys.argv) > 1 else os.getenv("VPS_IP", "127.0.0.1")
USER = sys.argv[2] if len(sys.argv) > 2 else os.getenv("SSH_USER", "root")
PASS = sys.argv[3] if len(sys.argv) > 3 else os.getenv("SSH_PASS", "")

LOCAL_DIR = os.path.dirname(os.path.abspath(__file__))
REMOTE_DIR = "/var/www/netsentinel-vpnbot"

print(f"\n[+] Connecting to VPS SSH {USER}@{HOST}...")

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    ssh.connect(HOST, port=22, username=USER, password=PASS, timeout=30)
    print("[+] SSH Connection Successful!")
except Exception as e:
    print(f"[-] Connection failed: {e}")
    sys.exit(1)

def run_cmd(cmd, ignore_error=False):
    print(f"[>] Executing: {cmd}")
    stdin, stdout, stderr = ssh.exec_command(cmd)
    out = stdout.read().decode('utf-8', errors='ignore')
    err = stderr.read().decode('utf-8', errors='ignore')
    if out:
        print(out)
    if err and not ignore_error:
        print(f"[!] Stderr: {err}")
    return out

print("\n[+] Installing System Packages, WireGuard & PM2 on VPS...")
run_cmd("DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get update -y && DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get install -y python3 python3-pip python3-venv curl wireguard wireguard-tools qrencode iptables")
run_cmd("sysctl -w net.ipv4.ip_forward=1")
run_cmd("grep -q 'net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf")

print(f"\n[+] Creating remote directory {REMOTE_DIR}...")
run_cmd(f"mkdir -p {REMOTE_DIR}")

print("\n[+] Uploading project files via SFTP...")
sftp = ssh.open_sftp()

files_to_upload = [
    "vpn_bot.py",
    "wg_manager.py",
    "config.py",
    "requirements.txt",
    "ecosystem.config.js",
    ".env",
    "README.md"
]

for fname in files_to_upload:
    local_path = os.path.join(LOCAL_DIR, fname)
    remote_path = f"{REMOTE_DIR}/{fname}"
    if os.path.exists(local_path):
        print(f"  Uploading {fname} -> {remote_path}")
        sftp.put(local_path, remote_path)
    else:
        print(f"  [!] Skipping {fname} (not found locally)")

sftp.close()

print("\n[+] Installing Python dependencies on VPS...")
run_cmd(f"cd {REMOTE_DIR} && pip3 install -r requirements.txt")

print("\n[+] Initializing WireGuard wg0 interface & NAT forwarding rules...")
run_cmd(f"cd {REMOTE_DIR} && python3 -c 'import wg_manager; wg_manager.sync_system_wg_conf()'")
run_cmd("systemctl enable wg-quick@wg0 2>/dev/null || true")

print("\n[+] Starting NetSentinel VPN Bot under PM2...")
run_cmd(f"cd {REMOTE_DIR} && pm2 reload ecosystem.config.js || pm2 start ecosystem.config.js")
run_cmd("pm2 save")

print("\n[+] Deployment completed successfully!")
print("[+] Status:")
run_cmd("pm2 status")

ssh.close()
