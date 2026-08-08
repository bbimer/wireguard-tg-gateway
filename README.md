# NetSentinel WireGuard Telegram Gateway

Automated WireGuard VPN tunnel orchestration service and QR-code onboarding bot built with Python, Aiogram 3.x, and Linux kernel network interface management.

Designed for network isolation, automated client keypair generation, subnet IP allocation, and instant iOS/Android device onboarding.

---

## Overview

NetSentinel WireGuard Gateway automates the deployment and device management lifecycle for private WireGuard Virtual Private Networks. It provides a secure Telegram interface allowing administrators to issue encrypted client configurations, allocate dedicated internal IP addresses within a `/24` CIDR subnet, and generate inline QR codes for zero-friction mobile deployment.

### System Architecture

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
|   |                 (IPTables MASQUERADE / ens3)              |   |
|   +------------------------------+----------------------------+   |
|                                  |                                |
|   +------------------------------+----------------------------+   |
|   |                 WireGuard Interface (wg0)                 |   |
|   |                 Subnet: 10.8.0.0/24                       |   |
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

## Core Capabilities

- **Automated Keypair Generation**: Programmatically generates Curve25519 private/public keypairs and 256-bit preshared keys for each registered peer.
- **In-Memory QR Code Rendering**: Renders WireGuard configuration payloads directly into memory streams (`io.BytesIO`) using `qrcode` and `Pillow`, preventing transient disk I/O leaks.
- **Dynamic WAN Interface Resolution**: Automatically inspects kernel routing tables (`ip route show default`) to detect primary WAN interfaces (`ens3`, `eth0`) and configure appropriate Netfilter IPTables MASQUERADE rules.
- **UFW Firewall Rule Enforcement**: Configures Uncomplicated Firewall (UFW) rules, enabling UDP port 51820 ingress and default packet forwarding policy (`DEFAULT_FORWARD_POLICY="ACCEPT"`).
- **Asynchronous Event Processing**: Built on `aiogram 3.x` and `asyncio` for non-blocking message dispatching and state management.
- **Access Control & Security**: Restricts command execution to configured administrator chat identifiers via Telegram user ID verification.

---

## Technical Specifications

| Component | Specification |
|---|---|
| Runtime | Python 3.10+ |
| Framework | Aiogram 3.3.0 (Asyncio) |
| Core Tunnel Protocol | WireGuard (UDP/51820) |
| Default Subnet | 10.8.0.0/24 |
| DNS Resolvers | 1.1.1.1, 8.8.8.8 |
| Process Management | PM2 / systemd (`wg-quick@wg0`) |

---

## Environment Configuration

Copy the example environment configuration file and update the variables:

```bash
cp .env.example .env
```

### Configuration Parameters

```env
VPN_BOT_TOKEN=YOUR_BOT_TOKEN_HERE
ADMIN_CHAT_ID=YOUR_TELEGRAM_ID_HERE
VPS_IP=YOUR_SERVER_IP_HERE
WG_PORT=51820
```

---

## Deployment & Setup

### 1. Installation

Install required Python dependencies:

```bash
pip install -r requirements.txt
```

### 2. Local Execution

To start the gateway daemon locally:

```bash
python vpn_bot.py
```

### 3. Remote VPS Automated Deployment

The repository includes an automated SSH/SFTP deployment handler (`deploy_remote.py`). Run the deployment script to provision dependencies, configure kernel parameters, update UFW firewall policies, and initialize PM2 daemonization:

```bash
python deploy_remote.py [HOST] [USER] [PASS]
```

---

## Security Audit & Isolation Standards

1. **Credentials Separation**: Sensitive runtime parameters (`.env`, `wg_devices.json`) are excluded from version control via `.gitignore`.
2. **Key Storage Security**: Server and peer private keys are stored with restricted file system permissions on the host system.
3. **No External Dependencies**: Cryptographic primitives rely strictly on standard system utilities (`wg`, `openssl`) and verified Python cryptography packages.

---

## License

Distributed under the MIT License. See `LICENSE` for details.
