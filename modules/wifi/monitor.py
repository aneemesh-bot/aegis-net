import logging
from typing import Callable, Optional
from scapy.all import AsyncSniffer
from scapy.packet import Packet
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Disas

logger = logging.getLogger(__name__)

class WifiMonitor:
    """
    Asynchronous 802.11 monitor designed to capture and parse
    Deauthentication and Disassociation management frames.
    """

    def __init__(self, interface: str, packet_callback: Callable[[dict], None]) -> None:
        """
        Initializes the Wi-Fi monitor.

        Args:
            interface (str): The wireless interface in monitor mode (e.g., 'wlan0mon').
            packet_callback (Callable[[dict], None]): The function to call when a threat frame is detected.
        """
        self.interface: str = interface
        self.packet_callback: Callable[[dict], None] = packet_callback
        self.sniffer: Optional[AsyncSniffer] = None
        
        # BPF filter: type 0 is Management, subtype 12 is Deauth, subtype 10 is Disassoc
        self.bpf_filter: str = "type mgt subtype deauth or type mgt subtype disassoc"

    def _process_packet(self, pkt: Packet) -> None:
        """
        Internal callback to parse the raw Scapy packet and extract relevant state data.
        
        Args:
            pkt (Packet): The captured 802.11 packet.
        """
        if not pkt.haslayer(Dot11):
            return

        # 802.11 Frame Addresses:
        # addr1 = Destination (Receiver)
        # addr2 = Source (Transmitter)
        # addr3 = BSSID (Access Point)
        sta_mac: str = str(pkt.addr1)
        ap_mac: str = str(pkt.addr2)
        
        # Determine frame type and reason code
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

        # Extract the sequence number. 
        # The Sequence Control (SC) field is 16 bits: 4 bits fragment number, 12 bits sequence number.
        # We bit-shift right by 4 to isolate the sequence number.
        sequence_control: int = pkt[Dot11].SC if pkt[Dot11].SC else 0
        sequence_number: int = sequence_control >> 4

        # Package the extracted data into a clean dictionary for the sequence analyzer
        event_data: dict = {
            "type": frame_type,
            "source_mac": ap_mac,
            "dest_mac": sta_mac,
            "reason_code": reason_code,
            "sequence_number": sequence_number
        }

        # Pass to the logic engine/sequence analyzer
        self.packet_callback(event_data)

    def start(self) -> None:
        """Starts the asynchronous packet sniffer."""
        logger.info(f"Starting Wi-Fi monitor on {self.interface}...")
        try:
            self.sniffer = AsyncSniffer(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._process_packet,
                store=False  # Do not keep packets in memory to prevent memory leaks
            )
            self.sniffer.start()
            logger.info("Wi-Fi monitor is running in the background.")
        except Exception as e:
            logger.error(f"Failed to start Wi-Fi sniffer: {e}")
            raise

    def stop(self) -> None:
        """Stops the asynchronous packet sniffer."""
        if self.sniffer and self.sniffer.running:
            logger.info("Stopping Wi-Fi monitor...")
            self.sniffer.stop()
            self.sniffer.join()
            logger.info("Wi-Fi monitor stopped.")