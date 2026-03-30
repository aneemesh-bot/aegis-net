# Aegis-Net: Layer-2 Security Daemon

Aegis-Net is a lightweight, multiprocessing Python security daemon designed to actively monitor, detect, and mitigate Layer-2 network attacks in hostile or congested environments (like university dorms or public enterprise networks). 

It currently features dual-engine protection against **ARP Cache Poisoning** and **802.11 Deauthentication/Disassociation** attacks.

## 🛡️ Core Features

* **Parallel Processing Architecture:** Utilizes Python's `multiprocessing` library to run the ARP and Wi-Fi defense engines on separate CPU cores, ensuring zero packet drops even under heavy network load.
* **Stateful ARP Defense (The "Brains"):** Replaces vulnerable local ARP caches with an authoritative SQLite database. It silently registers new devices on first use but instantly flags and mitigates overlapping IP claims (ARP Spoofing) via Gratuitous ARP (GARP) bursts.
* **Leaky-Bucket Wi-Fi Defense:** Employs a highly efficient token-bucket algorithm to track 802.11 management frame sequence numbers. It mathematically distinguishes between normal network jitter/packet drops and active, malicious frame injection.
* **Graceful Hardware Management:** Includes custom bash scripts that cleanly detach and reattach wireless adapters from `NetworkManager` for monitor mode, avoiding the destructive network drops caused by tools like `airmon-ng`.

## 📂 Repository Structure

```text
aegis-net/
├── main.py                     # Main orchestrator and multiprocessing entry point
├── requirements.txt            # Python dependencies
├── core/                       # Shared daemon utilities
│   ├── database.py             # Authoritative SQLite DB manager
│   ├── logger.py               # Centralized logging configuration
│   └── sniffer.py              # Base Scapy asynchronous sniffer class
├── modules/
│   ├── arp/                    # ARP Defense Subsystem
│   │   ├── monitor.py          # Sniffs and parses raw ARP frames
│   │   ├── state.py            # Evaluates claims against the DB
│   │   └── mitigator.py        # Deploys GARP corrections
│   └── wifi/                   # Wi-Fi Defense Subsystem
│       ├── monitor.py          # Sniffs 802.11 management frames
│       ├── seq_analyzer.py     # Leaky-bucket sequence analysis
│       └── mitigator.py        # Handles alerts and active responses
├── scripts/                    # Hardware configuration scripts
│   ├── setup_monitor.sh        # Safely enables monitor mode
│   └── teardown_monitor.sh     # Restores managed mode and NetworkManager
├── utils/
│   └── validators.py           # Regex-based MAC and IP sanitization
└── tests/                      # Unit testing suite
    ├── test_arp_state.py       
    └── test_seq_analyzer.py    
```

## ⚙️ Prerequisites

* **OS:** A Linux environment (Debian/Ubuntu, Kali, or Raspberry Pi OS recommended).
* **Permissions:** Root privileges (`sudo`) are required to manipulate network interfaces and sniff raw sockets.
* **Hardware:** A primary network connection (Ethernet or Wi-Fi) and a secondary Wi-Fi adapter that supports **Monitor Mode** (e.g., an Alfa Network card).

## 🚀 Installation

1. **Install System Dependencies:**
   Aegis-Net requires standard low-level networking tools to manage interfaces and capture packets.
   ```bash
   sudo apt-get update
   sudo apt-get install -y tcpdump iw iproute2 network-manager
   ```

2. **Install Python Dependencies:**
   ```bash
   pip3 install -r requirements.txt
   ```

## 🛠️ Usage Guide

### 1. Prepare the Hardware
Before starting the daemon, you must place your dedicated Wi-Fi adapter into monitor mode. Our setup script safely sidelines `NetworkManager` so it doesn't interfere.

*(If you don't know your interface name, just run the script without arguments and it will list them for you).*

```bash
chmod +x scripts/*.sh
sudo ./scripts/setup_monitor.sh wlan1
```

### 2. Launch the Daemon
Start the Aegis-Net orchestrator. You must specify which interface to use for ARP defense (your active connection to the network) and which to use for Wi-Fi defense (the monitor mode adapter).

```bash
sudo python3 main.py --arp-iface wlan0 --wifi-iface wlan1
```

**Checking Alerts:** If an attack is detected, the daemon will automatically deploy active mitigation and print a critical warning to the console. For a permanent audit trail, all confirmed attacks are cleanly appended to the dedicated log file:
```bash
tail -f log.txt
```

### 3. Clean Teardown
When you are done monitoring, stop the daemon (`Ctrl+C`). Then, use the teardown script to safely restore your adapter to normal managed mode and restart your system's network services.

```bash
sudo ./scripts/teardown_monitor.sh wlan1
```

## 🧪 Testing

You can verify the core logic engines (the Leaky Bucket and the Authoritative DB) without needing active hardware or root privileges by running the test suite:

```bash
pytest tests/
```

## ⚠️ Disclaimer
**Educational and Defensive Use Only.** This tool is designed to protect networks and analyze layer-2 vulnerabilities. Do not use Aegis-Net to monitor networks or intercept traffic for which you do not have explicit authorization. The authors are not responsible for any misuse or damage caused by this software.
```

