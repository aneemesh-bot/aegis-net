import logging
from typing import Callable, Optional
from scapy.all import AsyncSniffer
from scapy.layers.l2 import ARP

logger = logging.getLogger(__name__)

class ArpMonitor:
    """
    Asynchronous ARP packet sniffer. Captures ARP broadcasts and replies,
    passing the claims to the state manager for verification.
    """

    def __init__(self, interface: str, state_evaluator_callback: Callable[[str, str], None]) -> None:
        """
        Args:
            interface (str): The network interface to sniff on (e.g., 'eth0' or 'wlan0').
            state_evaluator_callback: The function from ArpStateManager to evaluate the packet.
                                      Expects (claimed_ip, claimed_mac).
        """
        self.interface: str = interface
        self.state_evaluator_callback: Callable[[str, str], None] = state_evaluator_callback
        self.sniffer: Optional[AsyncSniffer] = None

    def _process_packet(self, pkt) -> None:
        """Extracts the IP and MAC claims from the ARP packet."""
        if ARP in pkt:
            # op=1 is 'who-has' (request), op=2 is 'is-at' (reply)
            # We care about both, as an attacker can poison using malicious requests OR replies.
            claimed_ip = pkt[ARP].psrc
            claimed_mac = pkt[ARP].hwsrc

            # Pass the extracted claims to the ArpStateManager
            self.state_evaluator_callback(claimed_ip, claimed_mac)

    def start(self) -> None:
        """Starts the asynchronous ARP sniffer."""
        logger.info(f"Starting ARP monitor on {self.interface}...")
        try:
            self.sniffer = AsyncSniffer(
                iface=self.interface,
                filter="arp",       # BPF filter ensures we ONLY see ARP traffic
                prn=self._process_packet,
                store=False         # Prevent memory leaks
            )
            self.sniffer.start()
            logger.info("ARP monitor is running in the background.")
        except Exception as e:
            logger.error(f"Failed to start ARP sniffer: {e}")
            raise

    def stop(self) -> None:
        """Stops the sniffer safely."""
        if self.sniffer and self.sniffer.running:
            logger.info("Stopping ARP monitor...")
            self.sniffer.stop()
            self.sniffer.join()
            logger.info("ARP monitor stopped.")