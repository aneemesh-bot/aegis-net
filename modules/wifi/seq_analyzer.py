import time
import logging
from typing import Dict, Tuple, Callable, Optional

logger = logging.getLogger(__name__)

class ClientState:
    """Tracks the sequence state and anomaly score for a specific MAC pair."""
    def __init__(self, initial_seq: int) -> None:
        self.last_seq: int = initial_seq
        self.anomaly_score: float = 0.0
        self.last_time: float = time.time()


class SequenceAnalyzer:
    """
    Analyzes 802.11 sequence numbers using a Leaky Bucket algorithm 
    to detect injected Deauthentication and Disassociation frames.
    """

    def __init__(self, mitigation_callback: Optional[Callable[[str, str], None]] = None) -> None:
        """
        Initializes the sequence analyzer.

        Args:
            mitigation_callback: Function to call when an attack is confirmed. 
                                 Passes (attacker_spoofed_mac, target_mac).
        """
        # Dictionary key: (tx_mac, rx_mac), Value: ClientState
        self.states: Dict[Tuple[str, str], ClientState] = {}
        
        # Leaky Bucket Configuration
        self.MAX_SEQ_GAP: int = 10         # Normal frame drops allowed before flagging
        self.PENALTY: float = 1.0          # Score added per suspicious frame
        self.LEAK_RATE: float = 0.5        # Score reduction per second
        self.BUCKET_CAPACITY: float = 5.0  # Threshold to trigger confirmed attack alert
        
        self.mitigation_callback: Optional[Callable[[str, str], None]] = mitigation_callback

    def _calculate_gap(self, seq1: int, seq2: int) -> int:
        """
        Calculates the absolute distance between two 12-bit sequence numbers,
        accounting for the 4095 -> 0 wraparound.
        """
        return min((seq1 - seq2) % 4096, (seq2 - seq1) % 4096)

    def analyze_packet(self, event_data: dict) -> None:
        """
        Consumes the dictionary from the WifiMonitor and evaluates it for spoofing.
        """
        tx_mac: str = event_data["source_mac"]
        rx_mac: str = event_data["dest_mac"]
        current_seq: int = event_data["sequence_number"]
        frame_type: str = event_data["type"]

        session_key: Tuple[str, str] = (tx_mac, rx_mac)

        # Initialize tracking for a new connection pair
        if session_key not in self.states:
            self.states[session_key] = ClientState(current_seq)
            return

        state: ClientState = self.states[session_key]
        current_time: float = time.time()

        # 1. Leak the bucket based on time elapsed since last check
        time_diff: float = current_time - state.last_time
        state.anomaly_score = max(0.0, state.anomaly_score - (time_diff * self.LEAK_RATE))
        state.last_time = current_time

        # 2. Analyze the sequence number gap
        gap: int = self._calculate_gap(current_seq, state.last_seq)

        if gap > self.MAX_SEQ_GAP:
            # Anomaly detected: Sequence number jump is too high.
            # Add water (penalty) to the leaky bucket.
            state.anomaly_score += self.PENALTY
            
            logger.debug(
                f"Suspicious {frame_type}. {tx_mac} -> {rx_mac}. "
                f"Seq Gap: {gap}. Bucket: {state.anomaly_score:.2f}/{self.BUCKET_CAPACITY}"
            )

            # 3. Check for Bucket Overflow (Confirmed Attack)
            if state.anomaly_score >= self.BUCKET_CAPACITY:
                logger.critical(
                    f"DEAUTH ATTACK CONFIRMED! Target: {rx_mac}, Spoofed AP: {tx_mac}."
                )
                
                # Trigger the active defense mechanism
                if self.mitigation_callback:
                    self.mitigation_callback(tx_mac, rx_mac)
                
                # Drain the bucket to avoid alert flooding
                state.anomaly_score = 0.0
        else:
            # Packet sequence is valid. 
            # Crucially, we ONLY update the known sequence number if the packet is legitimate.
            # This prevents attackers from poisoning our tracker with their randomized numbers.
            state.last_seq = current_seq