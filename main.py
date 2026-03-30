import time
import signal
import logging
import argparse
import sys
from multiprocessing import Process

# Core and ARP Modules
from core.database import DatabaseManager
from modules.arp.monitor import ArpMonitor
from modules.arp.state import ArpStateManager
from modules.arp.mitigator import ArpMitigator

# Wi-Fi Modules
from modules.wifi.monitor import WifiMonitor
from modules.wifi.seq_analyzer import SequenceAnalyzer
from modules.wifi.mitigator import WifiMitigator

# Configure global logging for the orchestrator
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(name)s: %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("Aegis-Net-Daemon")

def run_arp_subsystem(interface: str) -> None:
    """
    Initializes and runs the ARP defense subsystem in a dedicated process.
    """
    logger.info(f"Initializing ARP Subsystem on {interface}...")
    
    # 1. Instantiate the authoritative database
    db = DatabaseManager()
    
    # 2. Instantiate the mitigator (The "Fists")
    mitigator = ArpMitigator(interface=interface)
    
    # 3. Instantiate the state manager, passing the DB and the mitigator callback (The "Brains")
    state_manager = ArpStateManager(
        db=db, 
        mitigation_callback=mitigator.trigger_mitigation
    )
    
    # 4. Instantiate and start the sniffer, passing the state evaluation callback (The "Eyes")
    monitor = ArpMonitor(
        interface=interface, 
        state_evaluator_callback=state_manager.evaluate_arp_packet
    )
    
    monitor.start()
    
    # Keep process alive until signaled
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
        logger.info("ARP Subsystem shutting down gracefully.")

def run_wifi_subsystem(interface: str) -> None:
    """
    Initializes and runs the Wi-Fi deauth defense subsystem in a dedicated process.
    """
    logger.info(f"Initializing Wi-Fi Subsystem on {interface}...")
    
    # 1. Instantiate the mitigator (The "Fists/Alerts")
    mitigator = WifiMitigator()
    
    # 2. Instantiate the sequence analyzer with the leaky bucket logic (The "Brains")
    analyzer = SequenceAnalyzer(
        mitigation_callback=mitigator.trigger_mitigation
    )
    
    # 3. Instantiate and start the sniffer (The "Eyes")
    monitor = WifiMonitor(
        interface=interface, 
        packet_callback=analyzer.analyze_packet
    )
    
    monitor.start()
    
    # Keep process alive until signaled
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
        logger.info("Wi-Fi Subsystem shutting down gracefully.")

def main() -> None:
    """Main entry point for the Aegis-Net Daemon."""
    parser = argparse.ArgumentParser(description="Aegis-Net: Enterprise Dorm Network Protection Daemon")
    parser.add_argument("--arp-iface", required=True, help="Interface for ARP monitoring (e.g., eth0 or wlan0)")
    parser.add_argument("--wifi-iface", required=True, help="Interface for Wi-Fi monitoring in monitor mode (e.g., wlan0mon)")
    
    args = parser.parse_args()

    logger.info("Starting Aegis-Net Security Daemon...")

    # Define multiprocessing targets
    arp_process = Process(target=run_arp_subsystem, args=(args.arp_iface,), daemon=True)
    wifi_process = Process(target=run_wifi_subsystem, args=(args.wifi_iface,), daemon=True)

    def signal_handler(sig, frame):
        logger.info("Interrupt received, shutting down subsystems...")
        # Since processes are daemonized, terminating the main process will clean them up,
        # but explicit termination is cleaner.
        arp_process.terminate()
        wifi_process.terminate()
        arp_process.join()
        wifi_process.join()
        logger.info("Aegis-Net shutdown complete.")
        sys.exit(0)

    # Bind the graceful shutdown handler to SIGINT (Ctrl+C)
    signal.signal(signal.SIGINT, signal_handler)

    # Start the parallel security engines
    arp_process.start()
    wifi_process.start()

    logger.info("Aegis-Net is fully operational. Monitoring for threats...")

    # Main process wait loop
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()