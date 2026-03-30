import logging
from typing import Callable, Optional
from scapy.all import AsyncSniffer

logger = logging.getLogger(__name__)

class BaseSniffer:
    """
    Abstract base class for network sniffers. 
    Handles the boilerplate of starting and stopping Scapy's AsyncSniffer safely.
    """
    def __init__(self, interface: str, bpf_filter: str, callback: Callable) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.callback = callback
        self.sniffer: Optional[AsyncSniffer] = None

    def start(self, name: str = "Sniffer") -> None:
        """Starts the asynchronous packet sniffer."""
        logger.info(f"Starting {name} on {self.interface} with filter '{self.bpf_filter}'...")
        try:
            self.sniffer = AsyncSniffer(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self.callback,
                store=False  # Crucial for preventing memory leaks
            )
            self.sniffer.start()
            logger.info(f"{name} is running in the background.")
        except Exception as e:
            logger.error(f"Failed to start {name}: {e}")
            raise

    def stop(self, name: str = "Sniffer") -> None:
        """Stops the sniffer cleanly."""
        if self.sniffer and self.sniffer.running:
            logger.info(f"Stopping {name}...")
            self.sniffer.stop()
            self.sniffer.join()
            logger.info(f"{name} stopped.")