# Ghostwatch
👁️‍🗨️ GhostWatch v3
Advanced Network Presence & Device Monitoring Framework

Real-time subnet monitoring, device presence alerts, email & Telegram notifications, and systemd-based auto-startup — designed exclusively for your own LAN / AD domain / lab network.

<p align="center"> <img src="https://dummyimage.com/600x200/111/00ffea&text=GHOSTWATCH+v3" /> </p> <p align="center"> <b>Version:</b> 3.0 • <b>Status:</b> Stable • <b>License:</b> Restricted Personal Use </p>
<p align="center"> <img src="https://img.shields.io/badge/Python-3.8%2B-blue" /> <img src="https://img.shields.io/badge/Monitoring-LAN%20%2F%20Subnet-green" /> <img src="https://img.shields.io/badge/Alerts-Email%20%7C%20Telegram-orange" /> <img src="https://img.shields.io/badge/Startup-systemd-lightgrey" /> <img src="https://img.shields.io/badge/Security-Cybersecurity%20Student-success" /> </p>
# 🔮 GhostWatch v3 LAN Device Monitoring | Subnet Watcher | Alert Engine

**GhostWatch v3** is a self-contained, legal, local-network monitoring system for:

- Active Directory labs  
- Small office networks  
- Home labs / cybersecurity labs  
- Internal corporate mini-setups  

It **does not bypass security or perform unauthorized scanning**. Designed entirely for your own network.

---

## 📌 Features

### Network Tools
- **Whois lookup**  
- **External / Local IP discovery**  
- **Device fingerprinting**  
- **CIDR range expanding**  
- **ARP-based detection**  
- **ICMP ping sweeps**  

### Single Device Monitor (With Alerts)
GhostWatch can monitor a single IP or Device-ID and alert when:

- Device goes **Online**  
- Device goes **Offline**  

**Supports:**  
- Alert Channel Status  
  - Gmail Email Alerts: Yes  
  - Telegram Alerts: Yes  
  - JSON logging: Yes  
  - TXT logs: Yes  

### Subnet / Range Monitor
You can monitor:

- `192.168.1.0/24`  
- `10.0.0.1 – 10.0.0.254`  
- Custom CIDR blocks  

**Functions:**  
- Detect newly appeared devices  
- Detect devices that went offline  

**Save logs:**  
- `online.json`  
- `offline.json`  
- `new_devices.json`  

---

## ⚙️ Auto-Start on Boot (systemd)
Service file location:  
`/etc/systemd/system/ghostwatch.service`  

GhostWatch starts automatically when the system boots.

---

## 📁 Project Structure (GitHub Layout)
GhostWatch/
│
├── ghostwatch.py
├── README.md
│
├── screenshots/
│   ├── menu.png
│   ├── scan.png
│   └── alerts.png
│
├── config/
│   └── ghostwatch.json
│
├── logs/
│   ├── online.json
│   ├── offline.json
│   └── new_devices.json
│
└── systemd/
    └── ghostwatch.service



---

## 🔧 Installation

```bash
git clone https://github.com/yourusername/GhostWatch.git
cd GhostWatch
chmod +x ghostwatch.py
sudo mv ghostwatch.py /usr/bin/ghostwatch
sudo cp systemd/ghostwatch.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ghostwatch
sudo systemctl start ghostwatch
📤 Email Alerts Setup (Gmail)
Step 1 — Enable 2-Step Verification
Go to: Google Security
Enable 2-Step verification.

Step 2 — Create an App Password
Go to: Google App Passwords
Select:

App: Mail

Device: Your Computer

Copy the 16-character password.

Step 3 — Add into GhostWatch
Inside the tool:

yaml

Enable Email Alerts? (y/n): y
Sender Gmail: your@gmail.com
Gmail App Password: abcd efgh ijkl mnop
Recipient Email: alert-recipient@gmail.com
📨 Telegram Alerts Setup
Step 1 — Create a bot
Go to Telegram → Search BotFather
Run command: /newbot
Receive BOT TOKEN.

Step 2 — Get your Chat ID
Start chat with: myidbot
Send: /getid
Bot replies with your Chat ID.

Step 3 — Enter into GhostWatch
yaml

Enable Telegram Alerts? (y/n): y
Bot Token: 123456789:ABCDEF
Chat ID: 987654321
🖼️ Screenshots (placeholders for GitHub)
Main Menu: menu.png

Scan Output: scan.png

Alerts Example: alerts.png

⚙️ systemd Service
ini

[Unit]
Description=GhostWatch Monitor
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /usr/bin/ghostwatch.py
Environment="PYTHONUNBUFFERED=1"
Restart=always
RestartSec=5
User=root
DNS=8.8.8.8 1.1.1.1

[Install]
WantedBy=multi-user.target
🧪 Example Output (Real Tool)
less

[+] Scanning 192.168.1.0/24...
[+] Live: 192.168.1.10 (NEW DEVICE)
[+] Online: 12 devices
[+] Offline: 3 devices
[+] Log saved → logs/new_devices.json
[+] Email alert sent successfully.
⚠️ Legal Disclaimer
GhostWatch is intended only for:

Your own LAN

Your own home / lab network

Your organization’s internal network where you have authorization

Unauthorized network monitoring is illegal. Only use GhostWatch where you have full permission.

💬 About the Developer
Created for a Cybersecurity Student learning:

Network monitoring

Active Directory

Defensive security

Real-time alert engineering



