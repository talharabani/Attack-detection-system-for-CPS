"""
Notification rate limiting and management.
Prevents spam notifications for the same attack.
"""

import time
from datetime import datetime, timedelta
from typing import Dict, Optional
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class NotificationManager:
    """
    Manages notification rate limiting to prevent spam.
    
    Rules:
    - If attack is from a DIFFERENT IP → Always send notification
    - If attack is from the SAME IP → Only one notification (rate limited to once per minute)
    
    This ensures you get notified about new attackers immediately,
    but won't be spammed by the same IP continuing to attack.
    """
    
    def __init__(self, rate_limit_seconds: int = 60):
        """
        Initialize notification manager.
        
        Args:
            rate_limit_seconds: Minimum seconds between notifications (default: 60)
        """
        self.rate_limit_seconds = rate_limit_seconds
        
        # Track last notification time per IP: {ip: timestamp}
        self.last_notification_time: Dict[str, float] = {}
        
        # Track active attacks per IP: {ip: attack_info}
        self.active_attacks: Dict[str, Dict] = {}
        
        # Track attack start time per IP: {ip: timestamp}
        self.attack_start_time: Dict[str, float] = {}
    
    def should_send_notification(self, source_ip: str, attack_info: Dict) -> bool:
        """
        Check if notification should be sent for this attack.
        
        Rules:
        - If attack is from a DIFFERENT IP → Always send notification
        - If attack is from the SAME IP → Only one notification (rate limited)
        
        Args:
            source_ip: Source IP address
            attack_info: Attack information dictionary
            
        Returns:
            True if notification should be sent, False otherwise
        """
        if not source_ip or source_ip == "unknown":
            return True  # Always notify for unknown IPs
        
        current_time = time.time()
        
        # Check if this IP has been seen before
        if source_ip in self.active_attacks:
            # Same IP - check rate limit
            last_notification = self.last_notification_time.get(source_ip, 0)
            time_since_last = current_time - last_notification
            
            if time_since_last < self.rate_limit_seconds:
                # Too soon since last notification for this IP
                logger.debug(
                    f"Rate limit: Skipping notification for {source_ip} "
                    f"(same IP, ongoing attack). {int(self.rate_limit_seconds - time_since_last)}s remaining"
                )
                return False
        
        # New IP or rate limit passed - allow notification
        return True
    
    def record_notification(self, source_ip: str, attack_info: Dict):
        """
        Record that a notification was sent.
        
        Args:
            source_ip: Source IP address
            attack_info: Attack information dictionary
        """
        if not source_ip or source_ip == "unknown":
            return
        
        current_time = time.time()
        
        # Record notification time by IP only (not IP+attack_type)
        self.last_notification_time[source_ip] = current_time
        
        # Mark IP as active (track by IP only)
        self.active_attacks[source_ip] = attack_info.copy()
        self.active_attacks[source_ip]["last_seen"] = current_time
        self.active_attacks[source_ip]["first_seen"] = self.attack_start_time.get(source_ip, current_time)
        
        # Record attack start time if new IP
        if source_ip not in self.attack_start_time:
            self.attack_start_time[source_ip] = current_time
            logger.info(f"New attacking IP detected: {source_ip} - Notification sent")
        else:
            logger.debug(f"Notification sent for ongoing attack from {source_ip}")
    
    def update_attack_status(self, source_ip: str, attack_info: Dict):
        """
        Update status of an ongoing attack (without sending notification).
        
        Args:
            source_ip: Source IP address
            attack_info: Attack information dictionary
        """
        if not source_ip or source_ip == "unknown":
            return
        
        # Update last seen time for this IP
        if source_ip in self.active_attacks:
            self.active_attacks[source_ip]["last_seen"] = time.time()
            # Update attack info if it changed
            self.active_attacks[source_ip].update(attack_info)
    
    def clear_inactive_attacks(self, inactive_threshold_seconds: int = 300):
        """
        Clear attacks that haven't been seen recently.
        
        Args:
            inactive_threshold_seconds: Seconds of inactivity before clearing (default: 5 minutes)
        """
        current_time = time.time()
        inactive_ips = []
        
        for ip, attack_data in self.active_attacks.items():
            last_seen = attack_data.get("last_seen", 0)
            if current_time - last_seen > inactive_threshold_seconds:
                inactive_ips.append(ip)
        
        for ip in inactive_ips:
            del self.active_attacks[ip]
            if ip in self.attack_start_time:
                del self.attack_start_time[ip]
            logger.debug(f"Cleared inactive attack from IP: {ip}")
    
    def is_attack_active(self, source_ip: str, attack_type: str = None) -> bool:
        """
        Check if an attack is currently active from this IP.
        
        Args:
            source_ip: Source IP address
            attack_type: Type of attack (optional, not used for tracking)
            
        Returns:
            True if attack is active from this IP, False otherwise
        """
        return source_ip in self.active_attacks
    
    def get_active_attacks(self) -> Dict[str, Dict]:
        """
        Get all currently active attacks.
        
        Returns:
            Dictionary of active attacks
        """
        return self.active_attacks.copy()
    
    def reset(self):
        """Reset all tracking (useful for testing)."""
        self.last_notification_time.clear()
        self.active_attacks.clear()
        self.attack_start_time.clear()
        logger.info("Notification manager reset")

