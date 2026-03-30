import pytest
from modules.wifi.seq_analyzer import SequenceAnalyzer

def test_normal_sequence_progression():
    """Test that normal, slightly gapped sequence numbers do not trigger an alert."""
    alerts = []
    # Mock mitigation callback simply appends to our local list
    analyzer = SequenceAnalyzer(mitigation_callback=lambda ap, sta: alerts.append((ap, sta)))
    
    # Simulate normal progression with a minor dropped packet gap
    analyzer.analyze_packet({"type": "DEAUTH", "source_mac": "AP", "dest_mac": "STA", "sequence_number": 10, "reason_code": 7})
    analyzer.analyze_packet({"type": "DEAUTH", "source_mac": "AP", "dest_mac": "STA", "sequence_number": 12, "reason_code": 7})
    
    assert len(alerts) == 0
    assert analyzer.states[("AP", "STA")].anomaly_score == 0.0

def test_deauth_attack_triggers_mitigation():
    """Test that a rapid injection of out-of-sequence frames overflows the bucket."""
    alerts = []
    analyzer = SequenceAnalyzer(mitigation_callback=lambda ap, sta: alerts.append((ap, sta)))
    
    # Establish baseline sequence
    analyzer.analyze_packet({"type": "DEAUTH", "source_mac": "AP", "dest_mac": "STA", "sequence_number": 10, "reason_code": 7})
    
    # Simulate attacker spamming forged frames with a random sequence number (1000)
    for _ in range(6):
        analyzer.analyze_packet({"type": "DEAUTH", "source_mac": "AP", "dest_mac": "STA", "sequence_number": 1000, "reason_code": 7})
    
    # The bucket should have overflowed, triggering exactly 1 mitigation alert
    assert len(alerts) == 1
    assert alerts[0] == ("AP", "STA")