import logging
from typing import Callable
from scapy.packet import Packet
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Disas

# Import our new base class
from core.sniffer import BaseSniffer

logger = logging.getLogger(__name__)

class WifiMonitor(BaseSniffer):
    """
    Asynchronous 802.11 monitor designed to capture and parse
    Deauthentication and Disassociation management frames.
    """

    def __init__(self, interface: str, packet_callback: Callable[[dict], None]) -> None:
        """
        Args:
            interface (str): The wireless interface in monitor mode.
            packet_callback (Callable): The sequence analyzer function.
        """
        self.packet_callback: Callable[[dict], None] = packet_callback
        bpf_filter: str = "type mgt subtype deauth or type mgt subtype disassoc"
        
        # Initialize the base sniffer with our specific filter and parsing method
        super().__init__(interface=interface, bpf_filter=bpf_filter, callback=self._process_packet)

    def _process_packet(self, pkt: Packet) -> None:
        """Internal callback to parse raw Dot11 frames."""
        if not pkt.haslayer(Dot11):
            return

        sta_mac: str = str(pkt.addr1)
        ap_mac: str = str(pkt.addr2)
        
        frame_type: str = "UNKNOWN"
        reason_code: int = 0
        
        if pkt.haslayer(Dot11Deauth):
            frame_type = "DEAUTH"
            reason_code = int(pkt[Dot11Deauth].reason)
        elif pkt.haslayer(Dot11Disas):
            frame_type = "DISASSOC"
            reason_code = int(pkt[Dot11Disas].reason)
        else:
            return

        sequence_control: int = pkt[Dot11].SC if pkt[Dot11].SC else 0
        sequence_number: int = sequence_control >> 4

        event_data: dict = {
            "type": frame_type,
            "source_mac": ap_mac,
            "dest_mac": sta_mac,
            "reason_code": reason_code,
            "sequence_number": sequence_number
        }

        self.packet_callback(event_data)

    def start(self) -> None:
        """Overrides base start to provide a specific module name for logs."""
        super().start(name="Wi-Fi Monitor")

    def stop(self) -> None:
        """Overrides base stop to provide a specific module name for logs."""
        super().stop(name="Wi-Fi Monitor")