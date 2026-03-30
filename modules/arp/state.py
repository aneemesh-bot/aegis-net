import logging
from typing import Optional, Callable
from core.database import DatabaseManager

logger = logging.getLogger(__name__)

class ArpStateManager:
    """
    Evaluates incoming ARP packets against the authoritative database
    to detect ARP cache poisoning and spoofing attacks.
    """
    def __init__(self, db: DatabaseManager, mitigation_callback: Optional[Callable[[str, str, str], None]] = None) -> None:
        """
        Args:
            db (DatabaseManager): The initialized core database.
            mitigation_callback: Triggered on attack. Passes (attacker_mac, spoofed_ip, true_mac).
        """
        self.db: DatabaseManager = db
        self.mitigation_callback: Optional[Callable[[str, str, str], None]] = mitigation_callback

    def evaluate_arp_packet(self, claimed_ip: str, claimed_mac: str) -> None:
        """
        Core detection logic corresponding to Modules 2 & 3.
        """
        # 1. Retrieve the authoritative MAC for this IP
        authoritative_mac = self.db.get_mac_for_ip(claimed_ip)

        if not authoritative_mac:
            # Device not in database. In a strict environment, we might drop this.
            # For a dorm, we assume the first broadcast is legitimate (Trust First Use),
            # or we require a DHCP helper script to populate the DB.
            logger.debug(f"New device detected. Registering {claimed_ip} -> {claimed_mac}")
            self.db.add_authorized_mapping(claimed_ip, claimed_mac)
            return

        # 2. Check for MAC mismatch (Classic ARP Spoofing / MitM)
        if authoritative_mac.lower() != claimed_mac.lower():
            logger.critical(
                f"ARP SPOOFING DETECTED! "
                f"MAC {claimed_mac} is claiming IP {claimed_ip}. "
                f"Authoritative MAC is {authoritative_mac}."
            )
            
            if self.mitigation_callback:
                self.mitigation_callback(claimed_mac, claimed_ip, authoritative_mac)
            return

        # 3. Check for 1-to-Many MAC mapping anomalies (Module 3 requirement)
        # If an attacker uses their real MAC to claim the whole subnet's IPs
        associated_ips = self.db.get_ips_for_mac(claimed_mac)
        if len(associated_ips) > 2:
            # A client having 1-2 IPs (e.g., IPv4 + IPv6 or Docker bridges) is normal.
            # Claiming 3+ IPs is highly suspicious in a dorm Wi-Fi setting.
            logger.warning(
                f"ANOMALY: MAC {claimed_mac} is claiming multiple IPs: {associated_ips}"
            )