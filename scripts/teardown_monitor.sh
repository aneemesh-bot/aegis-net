#!/usr/bin/env bash

# Aegis-Net: Monitor Mode Teardown Script
# Restores the interface to managed mode and restarts NetworkManager.

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run this script as root (sudo)."
  exit 1
fi

if [ -z "$1" ]; then
  echo "Usage: $0 <interface_name>"
  echo "Example: $0 wlan1"
  exit 1
fi

INTERFACE=$1

echo "[*] Restoring $INTERFACE to managed mode..."

if ! ip link show "$INTERFACE" > /dev/null 2>&1; then
    echo "[-] Error: Interface $INTERFACE does not exist."
    exit 1
fi

# 1. Bring interface down
echo "[*] Bringing $INTERFACE down..."
ip link set "$INTERFACE" down
sleep 1

# 2. Change back to standard managed mode
echo "[*] Setting $INTERFACE to managed mode..."
iw dev "$INTERFACE" set type managed

if [ $? -ne 0 ]; then
    echo "[-] Warning: Failed to set managed mode cleanly. Forcing reset..."
fi

# 3. Reattach to NetworkManager
if command -v nmcli &> /dev/null; then
    echo "[*] Reattaching $INTERFACE to NetworkManager..."
    nmcli device set "$INTERFACE" managed yes
fi

# 4. Bring interface back up
echo "[*] Bringing $INTERFACE back up..."
ip link set "$INTERFACE" up
sleep 1

# 5. Restart NetworkManager to clear state and re-associate with Wi-Fi networks
echo "[*] Restarting NetworkManager service. You may lose internet briefly..."
systemctl restart NetworkManager

# Give it a few seconds to spin back up
sleep 3

# 6. Verify the mode
CURRENT_MODE=$(iw dev "$INTERFACE" info | grep type | awk '{print $2}')

if [ "$CURRENT_MODE" = "managed" ]; then
    echo "[+] Success! $INTERFACE restored to managed mode and NetworkManager restarted."
else
    echo "[-] Notice: Interface is in '$CURRENT_MODE' mode. You might need to check your adapter."
fi