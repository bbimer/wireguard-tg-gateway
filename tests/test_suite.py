import os
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

# Set mock dummy bot token before any imports to satisfy aiogram validation
os.environ.setdefault("VPN_BOT_TOKEN", "1234567890:AAHeOwaiG1HTRmoBfcBI6qW77HRCu7Cp5Zc")
os.environ.setdefault("ADMIN_CHAT_ID", "123456789")
os.environ.setdefault("VPS_IP", "198.51.100.1")

import unittest
import tempfile
import json
import base64
import py_compile
from unittest.mock import patch, MagicMock

# Add repo directory to path
REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO_DIR)

import config
import wg_manager
import vpn_bot


class TestWireGuardSuite(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        print("\n" + "="*60)
        print("[+] RUNNING NETSENTINEL WIREGUARD VPN GATEWAY TEST SUITE")
        print("="*60)

    def test_01_syntax_compilation(self):
        """Test that all python source files compile without syntax errors"""
        files = ["config.py", "wg_manager.py", "vpn_bot.py"]
        for f in files:
            path = os.path.join(REPO_DIR, f)
            print(f"[*] Checking compilation: {f}...")
            py_compile.compile(path, doraise=True)
        print("  [PASS] All Python files compiled cleanly.")

    def test_02_curve25519_key_generation(self):
        """Test WireGuard keypair generation and PSK generation"""
        priv, pub = wg_manager.generate_wg_keys()
        self.assertEqual(len(base64.b64decode(priv)), 32, "Private key must be 32 bytes")
        self.assertEqual(len(base64.b64decode(pub)), 32, "Public key must be 32 bytes")
        self.assertTrue(priv.endswith("="), "Private key should be base64 padded")
        self.assertTrue(pub.endswith("="), "Public key should be base64 padded")
        
        psk = wg_manager.generate_psk()
        self.assertEqual(len(base64.b64decode(psk)), 32, "PSK must be 32 bytes")
        print(f"  [PASS] Curve25519 Keygen & PSK: Priv={priv[:8]}... Pub={pub[:8]}... PSK={psk[:8]}...")

    def test_03_device_name_sanitizer(self):
        """Test device name sanitization against injection and corrupt filenames"""
        test_cases = [
            ("iPhone 15 Pro", "iPhone_15_Pro"),
            ("Мой Телефон 2026!", "Мой_Телефон_2026"),
            ("   Spaces   ", "Spaces"),
            (";; rm -rf / ;;", "rm_-rf"),
            ("allowed_ips=0.0.0.0/0", "allowed_ips_0_0_0_0_0"),
            ("", ""), # Should fallback to device_<ts>
            ("a" * 100, ("a" * 100)[:32]) # Max 32 chars
        ]
        
        for raw, expected in test_cases:
            res = wg_manager.sanitize_device_name(raw)
            if not raw.strip():
                self.assertTrue(res.startswith("device_"))
            else:
                self.assertEqual(res, expected)
        print("  [PASS] Device name sanitizer blocked injection attacks.")

    def test_04_format_bytes(self):
        """Test human readable byte formatting"""
        self.assertEqual(wg_manager.format_bytes(512), "512 B")
        self.assertEqual(wg_manager.format_bytes(1024 * 50), "50.0 KB")
        self.assertEqual(wg_manager.format_bytes(1024 * 1024 * 150), "150.0 MB")
        self.assertEqual(wg_manager.format_bytes(int(1024 * 1024 * 1024 * 3.45)), "3.45 GB")
        print("  [PASS] Byte formatting: B, KB, MB, GB formats verified.")

    def test_05_device_lifecycle_and_ip_allocation(self):
        """Test complete device creation, IP pool allocation, QR generation, bundle retrival and deletion"""
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", encoding="utf-8", delete=False) as tf:
            json.dump({"server_private_key": "", "server_public_key": "", "server_port": 51820, "subnet": "10.8.0", "devices": []}, tf)
            temp_state_file = tf.name

        try:
            with patch.object(config, 'WG_STATE_FILE_PATH', temp_state_file):
                # 1. Ensure server keys
                priv_srv, pub_srv = wg_manager.ensure_server_keys()
                self.assertTrue(priv_srv and pub_srv)
                
                # 2. Create device 1
                dev1, qr1, conf1 = wg_manager.create_device("Workstation-Alpha", "198.51.100.1")
                self.assertEqual(dev1["name"], "Workstation-Alpha")
                self.assertEqual(dev1["ip"], "10.8.0.2")
                self.assertTrue(qr1.startswith(b'\x89PNG\r\n\x1a\n'), "QR code must be a valid PNG")
                self.assertIn("[Interface]", conf1)
                self.assertIn("Address = 10.8.0.2/32", conf1)
                self.assertIn(f"PublicKey = {pub_srv}", conf1)
                
                # 3. Create device 2 (check IP increment)
                dev2, qr2, conf2 = wg_manager.create_device("Mobile-Node-Beta", "198.51.100.1")
                self.assertEqual(dev2["ip"], "10.8.0.3")
                
                # 4. List devices
                devices = wg_manager.list_devices()
                self.assertEqual(len(devices), 2)
                
                # 5. Get device bundle (re-issuing QR without recreating peer)
                bundle = wg_manager.get_device_bundle(dev1["id"])
                self.assertIsNotNone(bundle)
                b_dev, b_qr, b_conf = bundle
                self.assertEqual(b_dev["id"], dev1["id"])
                self.assertEqual(b_conf, conf1)
                
                # 6. Delete device 1
                deleted = wg_manager.delete_device(dev1["id"])
                self.assertTrue(deleted)
                devices_after = wg_manager.list_devices()
                self.assertEqual(len(devices_after), 1)
                self.assertEqual(devices_after[0]["id"], dev2["id"])
                
                # 7. Next IP should re-use 10.8.0.2
                dev3, _, _ = wg_manager.create_device("Tablet-Gamma", "198.51.100.1")
                self.assertEqual(dev3["ip"], "10.8.0.2")
                
        finally:
            if os.path.exists(temp_state_file):
                os.remove(temp_state_file)
        print("  [PASS] Device lifecycle, IP recycling & config generation verified.")

    def test_06_peer_stats_parsing(self):
        """Test parsing real-time statistics from simulated wg show dump output"""
        mock_dump = (
            "server_priv_key\tserver_pub_key\t51820\toff\n"
            "PUB_PEER_ONLINE\tPSK1\t198.51.100.5:54321\t10.8.0.2/32\t1700000050\t10485760\t52428800\t25\n"
            "PUB_PEER_OFFLINE\tPSK2\t(none)\t10.8.0.3/32\t0\t0\t0\toff\n"
        )
        
        with patch("subprocess.run") as mock_subproc, \
             patch("time.time", return_value=1700000080): # 30s after handshake
            
            mock_subproc.return_value = MagicMock(stdout=mock_dump, returncode=0)
            
            # Temporary override os.name to test Linux parser on Windows host
            with patch("os.name", "posix"):
                stats = wg_manager.get_peer_stats()
                
                self.assertIn("PUB_PEER_ONLINE", stats)
                self.assertTrue(stats["PUB_PEER_ONLINE"]["is_online"])
                self.assertEqual(stats["PUB_PEER_ONLINE"]["last_handshake_str"], "30s ago")
                self.assertEqual(stats["PUB_PEER_ONLINE"]["rx_str"], "10.0 MB")
                self.assertEqual(stats["PUB_PEER_ONLINE"]["tx_str"], "50.0 MB")
                
                self.assertIn("PUB_PEER_OFFLINE", stats)
                self.assertFalse(stats["PUB_PEER_OFFLINE"]["is_online"])
                self.assertEqual(stats["PUB_PEER_OFFLINE"]["last_handshake_str"], "Never")
        print("  [PASS] wg dump peer stats parser & online indicator verified.")

    def test_07_telegram_bot_handlers_and_security(self):
        """Test admin authentication and Telegram callback data limits"""
        with patch.object(config, 'ADMIN_CHAT_ID', 987654321):
            self.assertTrue(vpn_bot.is_admin(987654321))
            self.assertFalse(vpn_bot.is_admin(123456789))
            
        with patch.object(config, 'ADMIN_CHAT_ID', 0):
            # When admin ID is 0 or unset, open mode is allowed with security warning
            self.assertTrue(vpn_bot.is_admin(999999))
            
        # Test callback data length constraint (Telegram limit is 64 bytes)
        with patch("wg_manager.list_devices") as mock_list, \
             patch("wg_manager.get_peer_stats", return_value={}):
            mock_list.return_value = [
                {"id": "dev_1234567890abcdef", "name": "TestDevice", "ip": "10.8.0.2", "public_key": "PUBKEY"}
            ]
            kb = vpn_bot.build_main_keyboard()
            for row in kb.inline_keyboard:
                for btn in row:
                    if btn.callback_data:
                        self.assertLessEqual(len(btn.callback_data.encode('utf-8')), 64, 
                                             f"Callback data too long: {btn.callback_data}")
        print("  [PASS] Telegram security filter & 64-byte callback constraints verified.")


if __name__ == "__main__":
    unittest.main(verbosity=2)
