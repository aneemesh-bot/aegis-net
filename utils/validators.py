import re

def is_valid_mac(mac: str) -> bool:
    """
    Validates that a string is a properly formatted MAC address.
    Matches formats like 00:1A:2B:3C:4D:5E or 00-1A-2B-3C-4D-5E.
    """
    pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    return bool(pattern.match(mac))

def is_valid_ipv4(ip: str) -> bool:
    """
    Validates that a string is a properly formatted IPv4 address.
    """
    pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    return bool(pattern.match(ip))

def sanitize_mac(mac: str) -> str:
    """
    Normalizes a MAC address to lowercase with colon separators 
    for consistent database storage.
    """
    if not is_valid_mac(mac):
        raise ValueError(f"Invalid MAC address format: {mac}")
    return mac.replace("-", ":").lower()