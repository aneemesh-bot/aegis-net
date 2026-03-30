import sqlite3
import hashlib
import logging
from typing import Optional, List, Tuple

logger = logging.getLogger(__name__)

class DatabaseManager:
    """
    Core database manager for Aegis-Net.
    Maintains the authoritative state of the network.
    """
    def __init__(self, db_path: str = "data/aegis.db") -> None:
        self.db_path: str = db_path
        self._init_db()

    def _init_db(self) -> None:
        """Initializes the database schema if it does not exist."""
        query = """
        CREATE TABLE IF NOT EXISTS authorized_devices (
            ip_address TEXT NOT NULL,
            mac_address TEXT NOT NULL,
            mapping_hash TEXT PRIMARY KEY,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_static BOOLEAN DEFAULT 0
        );
        """
        with self._get_connection() as conn:
            conn.execute(query)
            # Create indexes for fast lookups during high network traffic
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ip ON authorized_devices(ip_address);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_mac ON authorized_devices(mac_address);")
        logger.info(f"Database initialized at {self.db_path}")

    def _get_connection(self) -> sqlite3.Connection:
        """Returns a context-managed SQLite connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def generate_hash(ip_address: str, mac_address: str) -> str:
        """Generates a unique hash for an IP-MAC pair."""
        raw_string = f"{ip_address}|{mac_address}".encode('utf-8')
        return hashlib.sha256(raw_string).hexdigest()

    def add_authorized_mapping(self, ip_address: str, mac_address: str, is_static: bool = False) -> bool:
        """Registers a known-good device mapping (Module 1)."""
        mapping_hash = self.generate_hash(ip_address, mac_address)
        query = """
        INSERT OR IGNORE INTO authorized_devices (ip_address, mac_address, mapping_hash, is_static)
        VALUES (?, ?, ?, ?)
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(query, (ip_address, mac_address, mapping_hash, is_static))
                return cursor.rowcount > 0
        except sqlite3.Error as e:
            logger.error(f"DB Error inserting mapping: {e}")
            return False

    def get_mac_for_ip(self, ip_address: str) -> Optional[str]:
        """Retrieves the authoritative MAC for a given IP."""
        query = "SELECT mac_address FROM authorized_devices WHERE ip_address = ?"
        with self._get_connection() as conn:
            row = conn.execute(query, (ip_address,)).fetchone()
            return row["mac_address"] if row else None

    def get_ips_for_mac(self, mac_address: str) -> List[str]:
        """Retrieves all IPs associated with a single MAC (Module 3 constraint check)."""
        query = "SELECT ip_address FROM authorized_devices WHERE mac_address = ?"
        with self._get_connection() as conn:
            rows = conn.execute(query, (mac_address,)).fetchall()
            return [row["ip_address"] for row in rows]