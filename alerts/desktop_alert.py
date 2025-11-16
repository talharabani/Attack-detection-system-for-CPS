"""
Desktop notification alert system.
Sends toast notifications to the desktop when attacks are detected.
"""

import logging
from typing import Dict, Optional

try:
    from plyer import notification
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False
    logging.warning("Plyer not available. Desktop notifications will be disabled.")

from utils.helper import load_config


logger = logging.getLogger(__name__)


class DesktopAlert:
    """
    Sends desktop notifications for detected attacks.
    """
    
    def __init__(self):
        """Initialize desktop alert system."""
        self.enabled = True
        
        if not PLYER_AVAILABLE:
            logger.warning("Plyer not available. Desktop alerts disabled.")
            self.enabled = False
            return
        
        # Load configuration
        try:
            config = load_config()
            self.enabled = config.get("alerts", {}).get("desktop", {}).get("enabled", True)
        except Exception as e:
            logger.warning(f"Could not load config: {e}")
        
        if self.enabled:
            logger.info("Desktop alert system initialized")
    
    def _format_attack_message(self, attack_info: Dict) -> tuple:
        """
        Format attack information into title and message.
        
        Args:
            attack_info: Dictionary containing attack information
            
        Returns:
            Tuple of (title, message)
        """
        attack_type = attack_info.get("attack_type", "Unknown Attack")
        severity = attack_info.get("severity", "UNKNOWN")
        
        title = f"🚨 {attack_type} Detected"
        
        # Build message
        message_parts = []
        
        # Add severity
        message_parts.append(f"Severity: {severity}")
        
        # Add source IP if available
        src_ip = attack_info.get("src_ip")
        if src_ip and src_ip != "unknown":
            message_parts.append(f"Source IP: {src_ip}")
        
        # Add attack-specific details
        if attack_type == "DDoS/Flooding" or attack_type == "Ping Flood Attack (ICMP)":
            packet_count = attack_info.get("packet_count", 0)
            packet_rate = attack_info.get("packet_rate", 0)
            icmp_ping_count = attack_info.get("icmp_ping_count", 0)
            
            if attack_type == "Ping Flood Attack (ICMP)":
                message_parts.append(f"ICMP Ping Packets: {icmp_ping_count}")
                message_parts.append(f"Total Packets: {packet_count}")
            else:
                message_parts.append(f"Packets: {packet_count}")
            message_parts.append(f"Rate: {packet_rate:.2f} pkt/s")
        
        elif attack_type == "Port Scanning":
            port_count = attack_info.get("port_count", 0)
            message_parts.append(f"Ports scanned: {port_count}")
        
        elif attack_type == "Brute Force Login":
            attempt_count = attack_info.get("attempt_count", 0)
            usernames = attack_info.get("usernames_attempted", [])
            message_parts.append(f"Failed attempts: {attempt_count}")
            if usernames:
                message_parts.append(f"Users: {', '.join(usernames[:3])}")
        
        elif attack_type == "Intrusion Attempt":
            subtype = attack_info.get("subtype", "")
            if subtype:
                message_parts.append(f"Type: {subtype}")
            suspicious_cmd = attack_info.get("suspicious_command")
            if suspicious_cmd:
                message_parts.append(f"Command: {suspicious_cmd[:50]}")
        
        elif attack_type == "CPS Attack":
            subtype = attack_info.get("attack_subtype", "")
            protocol = attack_info.get("protocol", "")
            if subtype:
                message_parts.append(f"Type: {subtype}")
            if protocol:
                message_parts.append(f"Protocol: {protocol}")
            details = attack_info.get("details", {})
            if details:
                for key, value in list(details.items())[:2]:
                    message_parts.append(f"{key}: {value}")
        
        message = "\n".join(message_parts)
        
        return title, message
    
    def send_alert(self, attack_info: Dict):
        """
        Send desktop notification for detected attack.
        
        Args:
            attack_info: Dictionary containing attack information
        """
        if not self.enabled or not PLYER_AVAILABLE:
            return
        
        try:
            title, message = self._format_attack_message(attack_info)
            
            # Send notification
            notification.notify(
                title=title,
                message=message,
                app_name="RealTimeAttackDetection",
                timeout=10  # Show for 10 seconds
            )
            
            logger.info(f"Desktop alert sent: {attack_info.get('attack_type')}")
        
        except Exception as e:
            logger.error(f"Error sending desktop alert: {e}")
    
    def test_notification(self):
        """
        Send a test notification to verify the system works.
        """
        test_attack = {
            "attack_type": "Test Alert",
            "severity": "INFO",
            "src_ip": "127.0.0.1",
            "message": "This is a test notification from RealTimeAttackDetection"
        }
        
        self.send_alert(test_attack)

