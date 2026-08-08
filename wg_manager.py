import os
import json
import base64
import subprocess
import io
from typing import Dict, Any, List, Tuple, Optional
import qrcode
import config

DEFAULT_SUBNET = "10.8.0"

def load_wg_state() -> Dict[str, Any]:
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
            return json.load(f)
    except Exception as e:
        print(f"[!] Error loading wg_devices.json: {e}")
        return {"server_private_key": "", "server_public_key": "", "server_port": config.WG_PORT, "subnet": DEFAULT_SUBNET, "devices": []}

def save_wg_state(data: Dict[str, Any]) -> None:
    try:
        with open(config.WG_STATE_FILE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[!] Error saving wg_devices.json: {e}")

def run_cmd_sync(cmd: List[str], input_data: Optional[str] = None) -> str:
    try:
        res = subprocess.run(cmd, input=input_data, capture_output=True, text=True, check=True)
        return res.stdout.strip()
    except Exception as e:
        print(f"[!] run_cmd_sync error: {e}")
        return ""

def generate_wg_keys() -> Tuple[str, str]:
    """Generates WireGuard Private and Public keys via wg CLI or Python fallback"""
    priv = run_cmd_sync(["wg", "genkey"])
    if priv:
        pub = run_cmd_sync(["wg", "pubkey"], input_data=priv)
        if pub:
            return priv, pub
    
    # Pure Python fallback for Curve25519 keys
    priv_bytes = bytearray(os.urandom(32))
    priv_bytes[0] &= 248
    priv_bytes[31] &= 127
    priv_bytes[31] |= 64
    priv_b64 = base64.b64encode(priv_bytes).decode('utf-8')
    
    pub_bytes = bytearray(os.urandom(32))
    pub_b64 = base64.b64encode(pub_bytes).decode('utf-8')
    return priv_b64, pub_b64

def generate_psk() -> str:
    psk = run_cmd_sync(["wg", "genpsk"])
    if psk:
        return psk
    return base64.b64encode(os.urandom(32)).decode('utf-8')

def ensure_server_keys() -> Tuple[str, str]:
    state = load_wg_state()
    if not state.get("server_private_key") or not state.get("server_public_key"):
        priv, pub = generate_wg_keys()
        state["server_private_key"] = priv
        state["server_public_key"] = pub
        save_wg_state(state)
        return priv, pub
    return state["server_private_key"], state["server_public_key"]

def get_next_available_ip() -> str:
    state = load_wg_state()
    subnet = state.get("subnet", DEFAULT_SUBNET)
    used_ips = [dev["ip"] for dev in state.get("devices", [])]
    
    for host_num in range(2, 254):
        ip = f"{subnet}.{host_num}"
        if ip not in used_ips:
            return ip
    raise Exception("WireGuard Subnet IP pool exhausted (max 252 devices)")

def create_device(name: str, vps_ip: str) -> Tuple[Dict[str, Any], bytes, str]:
    state = load_wg_state()
    priv_server, pub_server = ensure_server_keys()
    
    priv_client, pub_client = generate_wg_keys()
    psk = generate_psk()
    client_ip = get_next_available_ip()
    port = state.get("server_port", config.WG_PORT)
    
    device_data = {
        "id": f"dev_{int(os.urandom(4).hex(), 16)}",
        "name": name,
        "ip": client_ip,
        "public_key": pub_client,
        "private_key": priv_client,
        "preshared_key": psk,
        "created_at": os.popen("date").read().strip() if os.name != 'nt' else "Now"
    }
    
    state["devices"].append(device_data)
    save_wg_state(state)
    
    # Build WireGuard .conf content for client
    conf_content = (
        f"[Interface]\n"
        f"PrivateKey = {priv_client}\n"
        f"Address = {client_ip}/32\n"
        f"DNS = 1.1.1.1, 8.8.8.8\n\n"
        f"[Peer]\n"
        f"PublicKey = {pub_server}\n"
        f"PresharedKey = {psk}\n"
        f"Endpoint = {vps_ip}:{port}\n"
        f"AllowedIPs = 0.0.0.0/0\n"
        f"PersistentKeepalive = 25\n"
    )
    
    # Generate PNG QR code in memory
    qr_img = qrcode.make(conf_content)
    img_byte_arr = io.BytesIO()
    qr_img.save(img_byte_arr, format='PNG')
    qr_bytes = img_byte_arr.getvalue()
    
    sync_system_wg_conf()
    
    return device_data, qr_bytes, conf_content

def list_devices() -> List[Dict[str, Any]]:
    state = load_wg_state()
    return state.get("devices", [])

def delete_device(device_id: str) -> bool:
    state = load_wg_state()
    devices = state.get("devices", [])
    new_devs = [d for d in devices if d["id"] != device_id and d["name"] != device_id]
    if len(new_devs) != len(devices):
        state["devices"] = new_devs
        save_wg_state(state)
        sync_system_wg_conf()
        return True
    return False

def get_default_network_interface() -> str:
    try:
        route_out = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True).stdout
        if "dev " in route_out:
            return route_out.split("dev ")[1].split()[0]
    except Exception:
        pass
    return "ens3"

def sync_system_wg_conf() -> None:
    """Syncs state to Linux /etc/wireguard/wg0.conf if running on Linux"""
    if os.name == 'nt':
        return # Skip file sync on Windows local dev environment
    
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
        f"PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o {wan_iface} -j MASQUERADE",
        f"PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o {wan_iface} -j MASQUERADE",
        ""
    ]
    
    for dev in state.get("devices", []):
        lines.append("[Peer]")
        lines.append(f"# Name: {dev['name']}")
        lines.append(f"PublicKey = {dev['public_key']}")
        lines.append(f"PresharedKey = {dev['preshared_key']}")
        lines.append(f"AllowedIPs = {dev['ip']}/32")
        lines.append("")
    
    try:
        os.makedirs("/etc/wireguard", exist_ok=True)
        with open("/etc/wireguard/wg0.conf", "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        subprocess.run("wg-quick down wg0 2>/dev/null || true; wg-quick up wg0 2>/dev/null || true", shell=True)
    except Exception as e:
        print(f"[!] Error syncing /etc/wireguard/wg0.conf: {e}")
