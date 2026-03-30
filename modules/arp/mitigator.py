import logging
from scapy.all import sendp
from scapy.layers.l2 import Ether, ARP

logger = logging.getLogger(__name__)

class ArpMitigator:
    """
    Actively defends against ARP spoofing by injecting Gratuitous ARP (GARP)
    replies into the network to correct poisoned caches.
    """

    def __init__(self, interface: str) -> None:
        """
        Initializes the ARP Mitigator.

        Args:
            interface (str): The network interface to send packets out of (e.g., 'eth0' or 'wlan0').
        """
        self.interface: str = interface

    def trigger_mitigation(self, attacker_mac: str, spoofed_ip: str, true_mac: str) -> None:
        """
        Crafts and broadcasts a Gratuitous ARP reply to restore the true IP-MAC mapping.

        Args:
            attacker_mac (str): The MAC address of the device attempting the spoof (for logging/targeted actions).
            spoofed_ip (str): The IP address that is being hijacked (usually the gateway).
            true_mac (str): The authoritative MAC address for the spoofed IP from our database.
        """
        logger.warning(
            f"Initiating Active Mitigation! Broadcasting true MAC ({true_mac}) "
            f"for IP ({spoofed_ip}) to counter attacker ({attacker_mac})."
        )

        # Crafting the Gratuitous ARP Reply
        # Ether dst="ff:ff:ff:ff:ff:ff" -> Layer 2 Broadcast to reach all switches/clients
        # ARP op=2 -> ARP Reply
        # psrc=spoofed_ip, pdst=spoofed_ip -> Characteristic of GARP: source and destination IP are the same
        # hwsrc=true_mac -> The payload we want to force into everyone's cache
        # hwdst="ff:ff:ff:ff:ff:ff" -> Layer 3 Broadcast
        
        garp_packet = Ether(dst="ff:ff:ff:ff:ff:ff", src=true_mac) / \
                      ARP(op=2, 
                          hwsrc=true_mac, 
                          psrc=spoofed_ip, 
                          hwdst="ff:ff:ff:ff:ff:ff", 
                          pdst=spoofed_ip)

        try:
            # We send a burst of packets (count=5) to ensure the network receives the correction, 
            # overwhelming any competing packets the attacker is simultaneously sending.
            sendp(
                garp_packet, 
                iface=self.interface, 
                count=5, 
                inter=0.1, 
                verbose=False
            )
            logger.info(f"Successfully broadcasted 5 GARP corrections for {spoofed_ip}.")
        except Exception as e:
            logger.error(f"Failed to inject Gratuitous ARP packets: {e}")
            
        # Optional: We could also craft a targeted Unicast ARP reply directly to the attacker, 
        # pointing the gateway's IP to a non-existent MAC (a "black hole") to break their connection.