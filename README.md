# NetSentinel WireGuard Telegram Gateway

Automated WireGuard VPN tunnel orchestration service and QR-code onboarding bot built with Python 3.10+, Aiogram 3.x, and Linux kernel network interface management.

Designed for automated client keypair generation, subnet IP allocation, live peer activity telemetry, zero-downtime hot-reloads, and instant iOS/Android device onboarding.

---

## System Architecture

```text
+-------------------------------------------------------------------+
|                        Client Infrastructure                      |
|                                                                   |
|   +-------------------+              +------------------------+   |
|   |  iOS / Android    |              |  Desktop Workstations  |   |
|   |  WireGuard Client |              |  WireGuard Tunnel      |   |
|   +---------+---------+              +-----------+------------+   |
+-------------|------------------------------------|----------------+
              | (Encrypted UDP / Port 51820)       |
              +------------------+-----------------+
                                 |
                                 v
+-------------------------------------------------------------------+
|                        Linux VPS Gateway                          |
|                                                                   |
|   +-----------------------------------------------------------+   |
|   |                 Linux Kernel Netfilter / NAT              |   |
|   |                 (IPTables MASQUERADE / ens3 / eth0)       |   |
|   +------------------------------+----------------------------+   |
|                                  |                                |
|   +------------------------------+----------------------------+   |
|   |                 WireGuard Interface (wg0)                 |   |
|   |                 Subnet: 10.8.0.0/24 (Configurable)        |   |
|   +------------------------------+----------------------------+   |
|                                  |                                |
|   +------------------------------+----------------------------+   |
|   |                 NetSentinel Gateway Daemon                |   |
|   |                 (Python 3.10 / Aiogram 3.x / PM2)         |   |
|   +-----------------------------------------------------------+   |
|                                                                   |
+-------------------------------------------------------------------+
```

---

## Core Features & Capabilities

- **Automated Keypair & PSK Generation**: Programmatically generates Curve25519 private/public keypairs and 256-bit preshared symmetric keys (PSK) for each registered peer.
- **In-Memory QR Code Rendering**: Renders WireGuard configuration payloads directly into memory streams (`io.BytesIO`) using `qrcode` and `Pillow`, preventing transient disk I/O leaks.
- **Live Peer Telemetry & Handshake Monitoring**: Parses kernel interface dump (`wg show wg0 dump`) in real time to report online indicators (🟢 Online / ⚪ Offline), last handshake timestamps, and cumulative RX/TX transfer statistics.
- **Zero-Downtime Hot-Reload (`wg syncconf`)**: Uses stripped live configuration synchronization (`wg syncconf`) to add or revoke peers dynamically without resetting the `wg0` network interface or disconnecting active sessions.
- **On-Demand Device Bundle Re-issue**: Allows administrators to view detailed device metrics and re-generate QR codes / `.conf` files directly from Telegram at any time.
- **Dynamic WAN Interface Resolution**: Automatically inspects kernel routing tables (`ip -4 route show default` and `ip -br link`) to detect WAN interfaces (`ens3`, `eth0`) with manual override support (`WAN_INTERFACE`).
- **Input Sanitization & Security Isolation**: Sanitizes device identifiers against shell/INI injection attacks and enforces strict Telegram admin verification (`ADMIN_CHAT_ID`).

---

## Technical Specifications

| Component | Specification |
|---|---|
| Runtime | Python 3.10+ |
| Framework | Aiogram 3.x (Asyncio) |
| Core Tunnel Protocol | WireGuard (UDP/51820) |
| Cryptographic Primitives | Curve25519 / ChaCha20-Poly1305 / 256-bit PSK |
| Default Subnet | 10.8.0.0/24 (Configurable via `WG_SUBNET`) |
| DNS Resolvers | 1.1.1.1, 8.8.8.8 |
| Process Management | PM2 / systemd (`wg-quick@wg0`) |

---

## Environment Configuration

Copy the example configuration file:

```bash
cp .env.example .env
```

### Configuration Parameters

```env
# Telegram Bot Token from @BotFather
VPN_BOT_TOKEN=YOUR_BOT_TOKEN_HERE

# Telegram Admin User ID (to restrict access)
ADMIN_CHAT_ID=YOUR_TELEGRAM_ID_HERE

# VPS Public IP Address (accessible by clients)
VPS_IP=YOUR_SERVER_IP_HERE
WG_PORT=51820

# Optional Settings
DEFAULT_DNS=1.1.1.1, 8.8.8.8
WG_SUBNET=10.8.0
# WAN_INTERFACE=eth0
```

---

## Deployment & Setup

### 1. Installation

Install required Python dependencies:

```bash
pip install -r requirements.txt
```

### 2. Local Execution

To run the daemon locally:

```bash
python vpn_bot.py
```

### 3. Remote VPS Automated Deployment

The repository includes an automated SSH/SFTP deployment handler (`deploy_remote.py`). Run the deployment script to provision dependencies, configure kernel IP forwarding, synchronize WireGuard state, and initialize PM2 daemonization:

```bash
python deploy_remote.py [HOST] [USER] [PASS]
```

---

## Automated Test Suite

The repository includes a comprehensive unit and integration test suite covering Curve25519 cryptography, IP pool lifecycle, injection sanitization, peer statistics parsing, and Telegram callback constraints.

Run the test suite:

```bash
python tests/test_suite.py
```

---

## Security Audit & Isolation Standards

1. **Credentials Separation**: Sensitive runtime parameters (`.env`, `wg_devices.json`, session state) are excluded from version control via `.gitignore`.
2. **Key Storage Security**: Server and peer private keys are stored with restricted file system permissions on the host system.
3. **No External Network Dependencies**: Cryptographic key generation features an embedded pure-Python Curve25519 fallback for maximum operational reliability across diverse host environments.

---

## License

Distributed under the MIT License. See `LICENSE` for details.
