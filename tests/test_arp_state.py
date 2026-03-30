import os
import pytest
from core.database import DatabaseManager
from modules.arp.state import ArpStateManager

@pytest.fixture
def setup_test_db():
    """Pytest fixture to create and tear down a temporary test database."""
    test_db_path = "test_aegis.db"
    db = DatabaseManager(db_path=test_db_path)
    yield db
    # Cleanup after test runs
    if os.path.exists(test_db_path):
        os.remove(test_db_path)

def test_arp_spoof_detection(setup_test_db):
    """Test that an attacker claiming a registered IP triggers an alert."""
    alerts = []
    state_manager = ArpStateManager(
        db=setup_test_db, 
        mitigation_callback=lambda attacker, ip, true_mac: alerts.append(attacker)
    )
    
    gateway_ip = "192.168.1.1"
    true_mac = "aa:bb:cc:dd:ee:ff"
    attacker_mac = "11:22:33:44:55:66"
    
    # 1. Register the valid gateway
    setup_test_db.add_authorized_mapping(gateway_ip, true_mac, is_static=True)
    
    # 2. Simulate attacker sending a forged ARP reply claiming to be the gateway
    state_manager.evaluate_arp_packet(gateway_ip, attacker_mac)
    
    # 3. Verify the alert fired with the attacker's MAC
    assert len(alerts) == 1
    assert alerts[0] == attacker_mac

def test_trust_first_use(setup_test_db):
    """Test that a new, unseen IP/MAC combo is silently registered."""
    alerts = []
    state_manager = ArpStateManager(
        db=setup_test_db, 
        mitigation_callback=lambda attacker, ip, true_mac: alerts.append(attacker)
    )
    
    # Evaluate a totally new device
    state_manager.evaluate_arp_packet("10.0.0.5", "aa:11:bb:22:cc:33")
    
    assert len(alerts) == 0
    assert setup_test_db.get_mac_for_ip("10.0.0.5") == "aa:11:bb:22:cc:33"