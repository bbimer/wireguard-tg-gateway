import os
from dotenv import load_dotenv

load_dotenv()

VPN_BOT_TOKEN = os.getenv("VPN_BOT_TOKEN", "").strip()
ADMIN_CHAT_ID = int(os.getenv("ADMIN_CHAT_ID", "0").strip() or 0)
VPS_IP = os.getenv("VPS_IP", "127.0.0.1").strip()
WG_PORT = int(os.getenv("WG_PORT", "51820").strip() or 51820)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WG_STATE_FILE_PATH = os.path.join(BASE_DIR, "wg_devices.json")
