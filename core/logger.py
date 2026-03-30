import logging
import sys

def setup_loggers() -> None:
    """
    Initializes the centralized logging configuration for Aegis-Net.
    Sets up a standard console logger for daemon status and a dedicated 
    file logger for critical security alerts.
    """
    # 1. Standard Console Logger (for system status and debug)
    base_formatter = logging.Formatter('%(asctime)s - [%(levelname)s] - %(name)s: %(message)s')
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(base_formatter)
    
    # Apply to the root logger so all modules inherit it
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    
    # Prevent duplicate handlers if called multiple times
    if not root_logger.handlers:
        root_logger.addHandler(console_handler)

    # 2. Dedicated Alert Logger (for confirmed attacks)
    alert_logger = logging.getLogger("AegisAlerts")
    alert_logger.setLevel(logging.CRITICAL)
    
    # Route only critical alerts to log.txt
    if not any(isinstance(h, logging.FileHandler) for h in alert_logger.handlers):
        file_handler = logging.FileHandler("log.txt")
        alert_formatter = logging.Formatter('%(asctime)s - [AEGIS SECURITY ALERT] - %(message)s')
        file_handler.setFormatter(alert_formatter)
        alert_logger.addHandler(file_handler)
        
        # Prevent these alerts from double-printing to the console
        alert_logger.propagate = False 

def get_alert_logger() -> logging.Logger:
    """Returns the dedicated alert logger."""
    return logging.getLogger("AegisAlerts")