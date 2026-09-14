# 🛡️ goGuard

> A lightweight, real-time host threat detection & automated IP blocking daemon written in Go.

![Author](https://img.shields.io/badge/Author-Eric%20Pino-blue?style=flat-square)
![Go Version](https://img.shields.io/badge/Go-1.19%2B-00ADD8?style=flat-square&logo=go)
![License](https://img.shields.io/badge/License-MIT-blue.style=flat-square)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)

**goGuard** is a fast, low-resource alternative to `fail2ban`. It tails web server access logs in real-time, inspects incoming traffic against high-precision regex threat patterns, tracks suspicious IP hit frequencies, and automatically blocks attacking hosts at both the local Linux firewall level (`iptables`) and the cloud edge (`Cloudflare Firewall API`).

---

## Features

- **Real-Time Log Inspection**: Tails server access logs (e.g. Nginx, Apache) instantly with near-zero latency.
- **High-Precision Threat Detection**: Detects modern web attack vectors without blocking benign traffic:
  - **SQL Injection (SQLi)**: Union queries, information schema probing, sleep tests.
  - **Cross-Site Scripting (XSS)**: Script tags, inline event handlers (`onerror`, `onload`), `javascript:` schemes.
  - **Path Traversal & Recon**: `../` traversals, `/etc/passwd`, `.env`, `.git/config`, `wp-config.php`.
  - **Remote Code Execution (RCE)**: Shell operators, binary invocations (`curl`, `wget`, `nc`, `bash`), PHP code evaluation.
  - **SSTI & JNDI/Log4j**: `${jndi:ldap://...}`, `{{ ... }}` template injection.
  - **Admin Probes**: `/phpmyadmin`, `/wp-admin`, `/xmlrpc.php` automated scanners.
- **Dual IP Blocking Engine**:
  - **Linux `iptables`**: Drops packets at the host kernel level (`iptables -A INPUT -s <IP> -j DROP`).
  - **Cloudflare API**: Blocks offending IPs at the global edge before they reach your infrastructure.
- ⏱️ **Sliding Window Hit Counter**: Prevents false positive bans by requiring `N` hits within a configurable time window (e.g., 3 hits within 60 seconds).
- ⚪ **IP Whitelisting**: Exclude trusted static IPs or CIDR blocks (e.g., `127.0.0.1`, `10.0.0.0/8`) from ever being banned.
- **Telegram Notifications**: Receive instant alert messages with the attacker's IP, matched URL, and hit count directly in your Telegram channel.
- **Minimal Resource Footprint**: Single compiled binary running with minimal CPU and memory overhead.

---

## 🚀 Quick Start

### Prerequisites

- **Go 1.19+** (if compiling from source)
- **Linux Environment** (for `iptables` blocking mode) with `root` or `sudo` privileges.

<details>
<summary><b>📦 Installing Go on Linux (Click to expand)</b></summary>

**Ubuntu / Debian:**

```bash
sudo apt update && sudo apt install -y golang
```

**RHEL / CentOS / Rocky Linux:**

```bash
sudo dnf install -y golang
```

**Manual Install (Latest Go Tarball):**

```bash
# Download Go 1.24 tarball
wget https://go.dev/dl/go1.24.0.linux-amd64.tar.gz

# Extract to /usr/local
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz

# Add Go to PATH
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Verify installation
go version
```

</details>

### Option A: Standard Binary Install

1. **Clone the repository:**

   ```bash
   git clone https://github.com/your-username/goGuard.git
   cd goGuard
   ```

2. **Configure environment settings:**

   ```bash
   cp .env.example .env
   ```

   Edit `.env` with your log path and API credentials.

3. **Build and run the binary:**
   ```bash
   go build -o goGuard .
   sudo ./goGuard
   ```

---

### Option B: Docker & Docker Compose Install 🐳

1. **Clone the repository & setup `.env`:**

   ```bash
   git clone https://github.com/your-username/goGuard.git
   cd goGuard
   cp .env.example .env
   ```

2. **Start goGuard container:**

   ```bash
   docker compose up -d
   ```

3. **Check container status & logs:**
   ```bash
   docker compose logs -f
   docker exec -it goguard /app/goGuard --status
   ```

---

### 📊 Check Daemon Status & Threat Metrics

```bash
./goGuard --status
```

**Sample Output:**

```text
==================================================
 goGuard Status Report
==================================================
 Status:           RUNNING  (PID: 12345)
 Uptime:           2 hours 14 minutes
 Log File Tailed:  /var/log/nginx/access.log
 Blocking Mode:    both
 Max Hits Window:  3 hits / 60s
 Whitelisted IPs:  127.0.0.1, ::1

 Threat Metrics:
 --------------------------------------------------
 Total Log Lines Processed:  14,520
 Total Threats Detected:     18
 Total IPs Banned:           2

 Currently Blocked IPs:
 --------------------------------------------------
  192.168.1.100      (Blocked at 2026-07-27 19:40:12)
  10.0.0.45          (Blocked at 2026-07-27 20:05:01)
==================================================
```

---

## Configuration (`.env`)

| Variable                  | Default Value               | Description                                                           |
| :------------------------ | :-------------------------- | :-------------------------------------------------------------------- |
| `LOG_FILE_PATH`           | `/var/log/nginx/access.log` | Path(s) to log file(s). Supports single files, comma-separated lists (e.g. `/var/log/nginx/a.log,/var/log/nginx/b.log`), and glob patterns (e.g. `/var/log/nginx/*-access.log`). |
| `BLOCK_MODE`              | `both`                      | Defensive action mode: `both`, `cloudflare`, or `iptables`.           |
| `MAX_HITS`                | `3`                         | Number of threat hits required from an IP before triggering a ban.    |
| `TIME_WINDOW_SECONDS`     | `60`                        | Time window in seconds for tracking IP threat hits.                   |
| `WHITELIST_IPS`           | `127.0.0.1,::1`             | Comma-separated list of IPs or CIDR subnets to exclude from blocking. |
| `WHITELIST_CLOUDFLARE`    | `true`                      | Automatically whitelist all official Cloudflare IPv4 & IPv6 CIDRs.    |
| `CLOUDFLARE_API_ENDPOINT` | _(Standard CF API)_         | Cloudflare Firewall Access Rules API URL template.                    |
| `CLOUDFLARE_ZONE_ID`      | `ZONE_ID`                   | Cloudflare Zone ID for edge blocking.                                 |
| `CLOUDFLARE_API_KEY`      | `KEY`                       | Cloudflare API Bearer token.                                          |
| `TELEGRAM_BOT_KEY`        | `KEYS`                      | Telegram Bot API token.                                               |
| `TELEGRAM_CHAT_ID`        | `ID`                        | Telegram Chat ID for security alerts.                                 |

---

## 🐧 Running as a Systemd Service

To run **goGuard** as a background service on Linux:

1. Create a systemd service file:

   ```bash
   sudo nano /etc/systemd/system/goguard.service
   ```

2. Paste the following configuration:

   ```ini
   [Unit]
   Description=goGuard Host Threat Detection Daemon
   After=network.target

   [Service]
   Type=simple
   User=root
   WorkingDirectory=/opt/goGuard
   ExecStart=/opt/goGuard/goGuard
   Restart=always
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   ```

3. Enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable goguard
   sudo systemctl start goguard
   sudo systemctl status goguard
   ```

## Author

**Eric Pino**
**cire@hey.com**

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
