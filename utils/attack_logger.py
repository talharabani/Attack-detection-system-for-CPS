"""
Attack logging and database management.
Stores all detected attacks in a JSON database for dashboard display.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class AttackLogger:
    """
    Manages attack logging to a JSON database.
    Stores attacks with all details for dashboard display.
    """
    
    def __init__(self, db_path: str = "attack_database.json"):
        """
        Initialize attack logger.
        
        Args:
            db_path: Path to JSON database file
        """
        self.db_path = Path(db_path)
        self.attacks: List[Dict] = []
        self.max_attacks = 1000  # Maximum attacks to store
        self._load_database()
    
    def _load_database(self):
        """Load attacks from database file."""
        try:
            if self.db_path.exists():
                with open(self.db_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.attacks = data.get("attacks", [])
                    logger.info(f"Loaded {len(self.attacks)} attacks from database")
            else:
                self.attacks = []
                logger.info("No existing database found, starting fresh")
        except Exception as e:
            logger.error(f"Error loading attack database: {e}")
            self.attacks = []
    
    def _save_database(self):
        """Save attacks to database file."""
        try:
            # Limit to max_attacks (keep most recent)
            if len(self.attacks) > self.max_attacks:
                self.attacks = self.attacks[-self.max_attacks:]
            
            data = {
                "last_updated": datetime.now().isoformat(),
                "total_attacks": len(self.attacks),
                "attacks": self.attacks
            }
            
            with open(self.db_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            logger.debug(f"Saved {len(self.attacks)} attacks to database")
        except Exception as e:
            logger.error(f"Error saving attack database: {e}")
    
    def log_attack(
        self,
        attack_type: str,
        source_ip: str,
        severity: str = "MEDIUM",
        details: Optional[Dict] = None,
        timestamp: Optional[datetime] = None
    ) -> Dict:
        """
        Log an attack to the database.
        
        Args:
            attack_type: Type of attack (e.g., "DDoS/Flooding")
            source_ip: Source IP address
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
            details: Additional attack details (packet_count, port_count, etc.)
            timestamp: Attack timestamp (defaults to now)
            
        Returns:
            Dictionary with logged attack information
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        attack_entry = {
            "id": len(self.attacks) + 1,
            "attack_type": attack_type,
            "src_ip": source_ip,
            "severity": severity,
            "timestamp": timestamp.isoformat(),
            "details": details or {}
        }
        
        # Add formatted timestamp for display
        attack_entry["timestamp_display"] = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        
        self.attacks.append(attack_entry)
        self._save_database()
        
        logger.info(f"Logged attack: {attack_type} from {source_ip} (Severity: {severity})")
        
        return attack_entry
    
    def get_all_attacks(self) -> List[Dict]:
        """
        Get all attacks from database.
        
        Returns:
            List of attack dictionaries
        """
        return self.attacks.copy()
    
    def get_attacks_by_ip(self, ip: str) -> List[Dict]:
        """
        Get all attacks from a specific IP.
        
        Args:
            ip: Source IP address
            
        Returns:
            List of attack dictionaries from that IP
        """
        return [a for a in self.attacks if a.get("src_ip") == ip]
    
    def get_recent_attacks(self, limit: int = 10) -> List[Dict]:
        """
        Get most recent attacks.
        
        Args:
            limit: Maximum number of attacks to return
            
        Returns:
            List of most recent attack dictionaries
        """
        return sorted(
            self.attacks,
            key=lambda x: x.get("timestamp", ""),
            reverse=True
        )[:limit]
    
    def get_attack_statistics(self) -> Dict:
        """
        Get attack statistics.
        
        Returns:
            Dictionary with statistics
        """
        if not self.attacks:
            return {
                "total_attacks": 0,
                "today_attacks": 0,
                "by_severity": {},
                "by_type": {},
                "unique_ips": 0
            }
        
        today = datetime.now().date()
        today_attacks = sum(
            1 for a in self.attacks
            if datetime.fromisoformat(a["timestamp"]).date() == today
        )
        
        by_severity = {}
        by_type = {}
        unique_ips = set()
        
        for attack in self.attacks:
            severity = attack.get("severity", "UNKNOWN")
            attack_type = attack.get("attack_type", "Unknown")
            src_ip = attack.get("src_ip", "")
            
            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_type[attack_type] = by_type.get(attack_type, 0) + 1
            if src_ip:
                unique_ips.add(src_ip)
        
        return {
            "total_attacks": len(self.attacks),
            "today_attacks": today_attacks,
            "by_severity": by_severity,
            "by_type": by_type,
            "unique_ips": len(unique_ips)
        }
    
    def clear_database(self):
        """Clear all attacks from database."""
        self.attacks = []
        self._save_database()
        logger.info("Attack database cleared")

