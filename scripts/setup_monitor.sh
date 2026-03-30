#!/usr/bin/env bash

# Aegis-Net: Monitor Mode Setup Script
# Configures a specified wireless interface into monitor mode.

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run this script as root (sudo)."
  exit 1
fi

# Check if an interface argument was provided
if [ -z "$1" ]; then
  echo "Usage: $0 <interface_name>"
  echo "Example: $0 wlan0"
  exit 1
fi

INTERFACE=$1

echo "[*] Configuring $INTERFACE for monitor mode..."

# 1. Check if the interface exists
if ! ip link show "$INTERFACE" > /dev/null 2>&1; then
    echo "[-] Error: Interface $INTERFACE does not exist."
    exit 1
fi

# 2. Bring the interface down
echo "[*] Bringing $INTERFACE down..."
ip link set "$INTERFACE" down
sleep 1

# 3. Change the interface type to monitor
echo "[*] Setting $INTERFACE to monitor mode..."
iw dev "$INTERFACE" set type monitor

# Check if the iw command succeeded
if [ $? -ne 0 ]; then
    echo "[-] Error: Failed to set monitor mode. Does your adapter support it?"
    # Attempt to bring it back up in managed mode just in case
    iw dev "$INTERFACE" set type managed
    ip link set "$INTERFACE" up
    exit 1
fi

# 4. Bring the interface back up
echo "[*] Bringing $INTERFACE back up..."
ip link set "$INTERFACE" up
sleep 1

# 5. Verify the mode
CURRENT_MODE=$(iw dev "$INTERFACE" info | grep type | awk '{print $2}')

if [ "$CURRENT_MODE" = "monitor" ]; then
    echo "[+] Success! $INTERFACE is now in monitor mode."
    echo "[!] Note: If NetworkManager interferes, you may need to run 'airmon-ng check kill'."
else
    echo "[-] Failed. $INTERFACE is currently in '$CURRENT_MODE' mode."
    exit 1
fi