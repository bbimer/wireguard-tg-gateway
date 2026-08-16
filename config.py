import os
from dotenv import load_dotenv

load_dotenv()

VPN_BOT_TOKEN = os.getenv("VPN_BOT_TOKEN", "").strip()
ADMIN_CHAT_ID = int(os.getenv("ADMIN_CHAT_ID", "0").strip() or 0)
VPS_IP = os.getenv("VPS_IP", "127.0.0.1").strip()
WG_PORT = int(os.getenv("WG_PORT", "51820").strip() or 51820)
DEFAULT_DNS = os.getenv("DEFAULT_DNS", "1.1.1.1, 8.8.8.8").strip()
WG_SUBNET = os.getenv("WG_SUBNET", "10.8.0").strip()
WAN_INTERFACE = os.getenv("WAN_INTERFACE", "").strip()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WG_STATE_FILE_PATH = os.path.join(BASE_DIR, "wg_devices.json")
