import logging
from typing import Callable
from scapy.layers.l2 import ARP

# Import our new base class
from core.sniffer import BaseSniffer

logger = logging.getLogger(__name__)

class ArpMonitor(BaseSniffer):
    """
    Asynchronous ARP packet sniffer. Captures ARP broadcasts and replies,
    passing the claims to the state manager for verification.
    """

    def __init__(self, interface: str, state_evaluator_callback: Callable[[str, str], None]) -> None:
        """
        Args:
            interface (str): The network interface to sniff on.
            state_evaluator_callback: Function from ArpStateManager.
        """
        self.state_evaluator_callback: Callable[[str, str], None] = state_evaluator_callback
        bpf_filter: str = "arp"
        
        # Initialize the base sniffer
        super().__init__(interface=interface, bpf_filter=bpf_filter, callback=self._process_packet)

    def _process_packet(self, pkt) -> None:
        """Extracts the IP and MAC claims from the ARP packet."""
        if ARP in pkt:
            claimed_ip = pkt[ARP].psrc
            claimed_mac = pkt[ARP].hwsrc
            self.state_evaluator_callback(claimed_ip, claimed_mac)

    def start(self) -> None:
        """Overrides base start to provide a specific module name for logs."""
        super().start(name="ARP Monitor")

    def stop(self) -> None:
        """Overrides base stop to provide a specific module name for logs."""
        super().stop(name="ARP Monitor")