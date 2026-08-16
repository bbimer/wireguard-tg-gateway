import os
import json
import base64
import subprocess
import io
import time
import re
import shutil
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional
import qrcode
import config

DEFAULT_SUBNET = getattr(config, "WG_SUBNET", "10.8.0")

# --- Curve25519 Pure Python Implementation (Fallback when `wg` CLI is not installed) ---
P = 2**255 - 19
A24 = 121665

def _curve25519_clamp(k: bytearray) -> bytearray:
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return k

def _curve25519_mult(n: int, p: int = 9) -> int:
    x_1 = p
    x_2, z_2 = 1, 0
    x_3, z_3 = p, 1
    swap = 0
    for t in range(254, -1, -1):
        k_t = (n >> t) & 1
        swap ^= k_t
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        swap = k_t
        A = (x_2 + z_2) % P
        AA = (A * A) % P
        B = (x_2 - z_2) % P
        BB = (B * B) % P
        E = (AA - BB) % P
        C = (x_3 + z_3) % P
        D = (x_3 - z_3) % P
        DA = (D * A) % P
        CB = (C * B) % P
        x_3 = ((DA + CB) ** 2) % P
        z_3 = (x_1 * ((DA - CB) ** 2)) % P
        x_2 = (AA * BB) % P
        z_2 = (E * (AA + A24 * E)) % P
    if swap:
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2
    return (x_2 * pow(z_2, P - 2, P)) % P


def sanitize_device_name(name: str) -> str:
    """Sanitizes device names to prevent config injection and filesystem issues"""
    # Replace spaces with underscores and remove non-alphanumeric/hyphen/underscore chars
    cleaned = re.sub(r'[^a-zA-Z0-9_\-а-яА-ЯёЁ]', '_', name.strip())
    # Collapse consecutive underscores
    cleaned = re.sub(r'_+', '_', cleaned).strip('_')
    if not cleaned:
        cleaned = f"device_{int(time.time())}"
    return cleaned[:32]


def format_bytes(bytes_count: int) -> str:
    """Formats byte counts into human-readable strings"""
    if bytes_count < 1024:
        return f"{bytes_count} B"
    elif bytes_count < 1024 * 1024:
        return f"{bytes_count / 1024:.1f} KB"
    elif bytes_count < 1024 * 1024 * 1024:
        return f"{bytes_count / (1024 * 1024):.1f} MB"
    else:
        return f"{bytes_count / (1024 * 1024 * 1024):.2f} GB"


def load_wg_state() -> Dict[str, Any]:
    """Loads WireGuard state from JSON file with backup and recovery handling"""
    if not os.path.exists(config.WG_STATE_FILE_PATH):
        initial = {
            "server_private_key": "",
            "server_public_key": "",
            "server_port": config.WG_PORT,
            "subnet": DEFAULT_SUBNET,
            "devices": []
        }
        save_wg_state(initial)
        return initial
    try:
        with open(config.WG_STATE_FILE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("Corrupted data format")
            if "devices" not in data:
                data["devices"] = []
            return data
    except Exception as e:
        print(f"[!] Error loading wg_devices.json: {e}")
        # Create corrupted backup before resetting
        try:
            backup_path = f"{config.WG_STATE_FILE_PATH}.corrupt_{int(time.time())}"
            shutil.copyfile(config.WG_STATE_FILE_PATH, backup_path)
            print(f"[!] Saved corrupted state backup to {backup_path}")
        except Exception:
            pass
        return {"server_private_key": "", "server_public_key": "", "server_port": config.WG_PORT, "subnet": DEFAULT_SUBNET, "devices": []}


def save_wg_state(data: Dict[str, Any]) -> None:
    """Atomic write to state file to prevent corruption during unexpected terminations"""
    tmp_file = f"{config.WG_STATE_FILE_PATH}.tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp_file, config.WG_STATE_FILE_PATH)
    except Exception as e:
        print(f"[!] Error saving wg_devices.json: {e}")
        if os.path.exists(tmp_file):
            try:
                os.remove(tmp_file)
            except Exception:
                pass


def run_cmd_sync(cmd: List[str], input_data: Optional[str] = None) -> str:
    """Executes a command synchronously and returns stdout"""
    try:
        res = subprocess.run(cmd, input=input_data, capture_output=True, text=True, check=True)
        return res.stdout.strip()
    except Exception:
        return ""


def generate_wg_keys() -> Tuple[str, str]:
    """Generates WireGuard Private and Public keys via wg CLI with pure-Python Curve25519 fallback"""
    priv = run_cmd_sync(["wg", "genkey"])
    if priv:
        pub = run_cmd_sync(["wg", "pubkey"], input_data=priv)
        if pub:
            return priv, pub
    
    # Pure Python Curve25519 fallback
    priv_raw = bytearray(os.urandom(32))
    priv_clamped = _curve25519_clamp(priv_raw)
    priv_int = int.from_bytes(priv_clamped, byteorder='little')
    
    pub_int = _curve25519_mult(priv_int, 9)
    pub_bytes = pub_int.to_bytes(32, byteorder='little')
    
    priv_b64 = base64.b64encode(priv_clamped).decode('utf-8')
    pub_b64 = base64.b64encode(pub_bytes).decode('utf-8')
    return priv_b64, pub_b64


def generate_psk() -> str:
    """Generates a pre-shared symmetric key"""
    psk = run_cmd_sync(["wg", "genpsk"])
    if psk:
        return psk
    return base64.b64encode(os.urandom(32)).decode('utf-8')


def ensure_server_keys() -> Tuple[str, str]:
    """Ensures server private/public keys exist in state"""
    state = load_wg_state()
    if not state.get("server_private_key") or not state.get("server_public_key"):
        priv, pub = generate_wg_keys()
        state["server_private_key"] = priv
        state["server_public_key"] = pub
        save_wg_state(state)
        return priv, pub
    return state["server_private_key"], state["server_public_key"]


def get_next_available_ip() -> str:
    """Finds next available IP address in subnet pool"""
    state = load_wg_state()
    subnet = state.get("subnet", DEFAULT_SUBNET)
    used_ips = {dev["ip"] for dev in state.get("devices", []) if "ip" in dev}
    
    for host_num in range(2, 254):
        ip = f"{subnet}.{host_num}"
        if ip not in used_ips:
            return ip
    raise Exception("WireGuard Subnet IP pool exhausted (max 252 devices)")


def build_client_conf_text(priv_client: str, client_ip: str, pub_server: str, psk: str, vps_ip: str, port: int) -> str:
    """Constructs the WireGuard client configuration file content"""
    dns = getattr(config, "DEFAULT_DNS", "1.1.1.1, 8.8.8.8")
    return (
        f"[Interface]\n"
        f"PrivateKey = {priv_client}\n"
        f"Address = {client_ip}/32\n"
        f"DNS = {dns}\n\n"
        f"[Peer]\n"
        f"PublicKey = {pub_server}\n"
        f"PresharedKey = {psk}\n"
        f"Endpoint = {vps_ip}:{port}\n"
        f"AllowedIPs = 0.0.0.0/0\n"
        f"PersistentKeepalive = 25\n"
    )


def generate_qr_bytes(conf_content: str) -> bytes:
    """Generates PNG QR code byte stream from conf text"""
    qr_img = qrcode.make(conf_content)
    img_byte_arr = io.BytesIO()
    qr_img.save(img_byte_arr, format='PNG')
    return img_byte_arr.getvalue()


def create_device(name: str, vps_ip: str) -> Tuple[Dict[str, Any], bytes, str]:
    """Creates a new WireGuard client device and syncs configuration"""
    clean_name = sanitize_device_name(name)
    state = load_wg_state()
    priv_server, pub_server = ensure_server_keys()
    
    priv_client, pub_client = generate_wg_keys()
    psk = generate_psk()
    client_ip = get_next_available_ip()
    port = state.get("server_port", config.WG_PORT)
    
    device_data = {
        "id": f"dev_{int(os.urandom(4).hex(), 16)}",
        "name": clean_name,
        "ip": client_ip,
        "public_key": pub_client,
        "private_key": priv_client,
        "preshared_key": psk,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    state["devices"].append(device_data)
    save_wg_state(state)
    
    conf_content = build_client_conf_text(
        priv_client=priv_client,
        client_ip=client_ip,
        pub_server=pub_server,
        psk=psk,
        vps_ip=vps_ip,
        port=port
    )
    
    qr_bytes = generate_qr_bytes(conf_content)
    sync_system_wg_conf()
    
    return device_data, qr_bytes, conf_content


def get_device_by_id(device_id: str) -> Optional[Dict[str, Any]]:
    """Finds a device by its ID"""
    state = load_wg_state()
    for dev in state.get("devices", []):
        if dev.get("id") == device_id or dev.get("name") == device_id:
            return dev
    return None


def get_device_bundle(device_id: str, vps_ip: Optional[str] = None) -> Optional[Tuple[Dict[str, Any], bytes, str]]:
    """Retrieves device info, regenerates QR code and client configuration string"""
    device_data = get_device_by_id(device_id)
    if not device_data:
        return None
    
    state = load_wg_state()
    priv_server, pub_server = ensure_server_keys()
    port = state.get("server_port", config.WG_PORT)
    effective_vps_ip = vps_ip or config.VPS_IP or "127.0.0.1"
    
    conf_content = build_client_conf_text(
        priv_client=device_data.get("private_key", ""),
        client_ip=device_data.get("ip", ""),
        pub_server=pub_server,
        psk=device_data.get("preshared_key", ""),
        vps_ip=effective_vps_ip,
        port=port
    )
    qr_bytes = generate_qr_bytes(conf_content)
    return device_data, qr_bytes, conf_content


def list_devices() -> List[Dict[str, Any]]:
    """Returns list of registered devices"""
    state = load_wg_state()
    return state.get("devices", [])


def delete_device(device_id: str) -> bool:
    """Deletes a device and triggers seamless WireGuard sync"""
    state = load_wg_state()
    devices = state.get("devices", [])
    new_devs = [d for d in devices if d.get("id") != device_id and d.get("name") != device_id]
    if len(new_devs) != len(devices):
        state["devices"] = new_devs
        save_wg_state(state)
        sync_system_wg_conf()
        return True
    return False


def get_peer_stats() -> Dict[str, Dict[str, Any]]:
    """
    Parses real-time statistics from `wg show wg0 dump` or `wg show wg0 transfer/latest-handshakes`
    Returns map of public_key -> { 'last_handshake': int, 'rx_bytes': int, 'tx_bytes': int, 'is_online': bool, ... }
    """
    stats: Dict[str, Dict[str, Any]] = {}
    if os.name == 'nt':
        return stats
    
    try:
        # Format: public-key preshared-key endpoint allowed-ips latest-handshake transfer-rx transfer-tx persistent-keepalive
        dump_out = subprocess.run(["wg", "show", "wg0", "dump"], capture_output=True, text=True).stdout
        now_ts = int(time.time())
        
        for line in dump_out.strip().splitlines():
            parts = line.split()
            # Server interface line has 4 parts, peers have 8 parts
            if len(parts) >= 8:
                pub_key = parts[0]
                endpoint = parts[2]
                try:
                    last_handshake = int(parts[4])
                except ValueError:
                    last_handshake = 0
                try:
                    rx_bytes = int(parts[5])
                    tx_bytes = int(parts[6])
                except ValueError:
                    rx_bytes, tx_bytes = 0, 0
                
                is_online = (last_handshake > 0) and ((now_ts - last_handshake) < 180)
                
                handshake_str = "Never"
                if last_handshake > 0:
                    diff = now_ts - last_handshake
                    if diff < 60:
                        handshake_str = f"{diff}s ago"
                    elif diff < 3600:
                        handshake_str = f"{diff // 60}m ago"
                    else:
                        handshake_str = f"{diff // 3600}h ago"
                
                stats[pub_key] = {
                    "endpoint": endpoint if endpoint != "(none)" else None,
                    "last_handshake": last_handshake,
                    "last_handshake_str": handshake_str,
                    "rx_bytes": rx_bytes,
                    "tx_bytes": tx_bytes,
                    "rx_str": format_bytes(rx_bytes),
                    "tx_str": format_bytes(tx_bytes),
                    "is_online": is_online
                }
    except Exception as e:
        print(f"[!] Error reading peer stats from wg: {e}")
    return stats


def get_default_network_interface() -> str:
    """Robust WAN interface detection using config override, ip route, or ip link"""
    if getattr(config, "WAN_INTERFACE", "").strip():
        return config.WAN_INTERFACE.strip()
    try:
        route_out = subprocess.run(["ip", "-4", "route", "show", "default"], capture_output=True, text=True).stdout
        match = re.search(r'dev\s+([a-zA-Z0-9_\-\.]+)', route_out)
        if match:
            return match.group(1)
        
        # Fallback: inspect available non-loopback interfaces
        link_out = subprocess.run(["ip", "-br", "link"], capture_output=True, text=True).stdout
        for line in link_out.splitlines():
            iface = line.split()[0]
            if not iface.startswith(('lo', 'wg', 'docker', 'veth', 'br-', 'virbr')):
                return iface
    except Exception:
        pass
    return "eth0"


def sync_system_wg_conf() -> None:
    """
    Syncs state to Linux /etc/wireguard/wg0.conf.
    Uses seamless `wg syncconf` to prevent dropping existing client tunnels.
    """
    if os.name == 'nt':
        return # Skip system config on Windows development host
    
    state = load_wg_state()
    priv_server = state.get("server_private_key", "")
    port = state.get("server_port", config.WG_PORT)
    subnet = state.get("subnet", DEFAULT_SUBNET)
    wan_iface = get_default_network_interface()
    
    lines = [
        "[Interface]",
        f"PrivateKey = {priv_server}",
        f"Address = {subnet}.1/24",
        f"ListenPort = {port}",
        f"PostUp = iptables -I FORWARD 1 -i wg0 -j ACCEPT; iptables -I FORWARD 1 -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -s {subnet}.0/24 -o {wan_iface} -j MASQUERADE",
        f"PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -s {subnet}.0/24 -o {wan_iface} -j MASQUERADE",
        ""
    ]
    
    for dev in state.get("devices", []):
        lines.append("[Peer]")
        clean_name = sanitize_device_name(dev.get("name", "Device"))
        lines.append(f"# Name: {clean_name}")
        lines.append(f"PublicKey = {dev['public_key']}")
        lines.append(f"PresharedKey = {dev['preshared_key']}")
        lines.append(f"AllowedIPs = {dev['ip']}/32")
        lines.append("")
    
    conf_path = "/etc/wireguard/wg0.conf"
    try:
        os.makedirs("/etc/wireguard", exist_ok=True)
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        
        # Ensure kernel IPv4 forwarding is active
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
        
        # Ensure iptables forwarding and NAT masquerade rules are present
        subprocess.run("iptables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i wg0 -j ACCEPT", shell=True)
        subprocess.run("iptables -C FORWARD -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT", shell=True)
        subprocess.run(f"iptables -t nat -C POSTROUTING -s {subnet}.0/24 -o {wan_iface} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s {subnet}.0/24 -o {wan_iface} -j MASQUERADE", shell=True)

        # Check if wg0 interface is already active
        ip_check = subprocess.run(["ip", "link", "show", "wg0"], capture_output=True, text=True)
        if ip_check.returncode == 0:
            # Seamless live sync using stripped config without taking interface down
            strip_proc = subprocess.run(["wg-quick", "strip", conf_path], capture_output=True, text=True)
            if strip_proc.returncode == 0 and strip_proc.stdout:
                tmp_strip_path = "/tmp/wg0_strip.conf"
                with open(tmp_strip_path, "w", encoding="utf-8") as tf:
                    tf.write(strip_proc.stdout)
                subprocess.run(["wg", "syncconf", "wg0", tmp_strip_path], check=True)
                try:
                    os.remove(tmp_strip_path)
                except Exception:
                    pass
            else:
                # Fallback if strip failed
                subprocess.run("wg-quick down wg0 2>/dev/null || true; wg-quick up wg0 2>/dev/null || true", shell=True)
        else:
            # Interface is down, bring it up cleanly
            subprocess.run(["wg-quick", "up", "wg0"], capture_output=True)
    except Exception as e:
        print(f"[!] Error syncing /etc/wireguard/wg0.conf: {e}")

