"""
Telegram bot alert system.
Sends alerts to Telegram when attacks are detected.
"""

import logging
import requests
from typing import Dict, Optional

from utils.helper import load_config


logger = logging.getLogger(__name__)


class TelegramAlert:
    """
    Sends Telegram messages for detected attacks.
    """
    
    def __init__(self):
        """Initialize Telegram alert system."""
        self.enabled = False
        self.bot_token = None
        self.chat_id = None
        self.api_url = None
        
        # Load configuration
        try:
            config = load_config()
            telegram_config = config.get("alerts", {}).get("telegram", {})
            self.enabled = telegram_config.get("enabled", False)
            self.bot_token = telegram_config.get("bot_token", "")
            self.chat_id = telegram_config.get("chat_id", "")
            
            if self.enabled:
                if not self.bot_token or self.bot_token == "YOUR_TELEGRAM_BOT_TOKEN":
                    logger.warning("Telegram bot token not configured. Telegram alerts disabled.")
                    self.enabled = False
                elif not self.chat_id or self.chat_id == "YOUR_CHAT_ID":
                    logger.warning("Telegram chat ID not configured. Telegram alerts disabled.")
                    self.enabled = False
                else:
                    self.api_url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
                    logger.info("Telegram alert system initialized")
        
        except Exception as e:
            logger.warning(f"Could not load config: {e}")
    
    def _format_attack_message(self, attack_info: Dict) -> str:
        """
        Format attack information into Telegram message.
        
        Args:
            attack_info: Dictionary containing attack information
            
        Returns:
            Formatted message string
        """
        attack_type = attack_info.get("attack_type", "Unknown Attack")
        severity = attack_info.get("severity", "UNKNOWN")
        timestamp = attack_info.get("timestamp", 0)
        
        # Emoji based on severity
        severity_emoji = {
            "LOW": "⚠️",
            "MEDIUM": "🔶",
            "HIGH": "🔴",
            "CRITICAL": "🚨"
        }
        emoji = severity_emoji.get(severity, "⚠️")
        
        # Build message
        message_lines = [
            f"{emoji} *{attack_type} Detected*",
            "",
            f"*Severity:* {severity}",
        ]
        
        # Add source IP if available
        src_ip = attack_info.get("src_ip")
        if src_ip and src_ip != "unknown":
            message_lines.append(f"*Source IP:* `{src_ip}`")
        
        # Add attack-specific details
        if attack_type == "DDoS/Flooding" or attack_type == "Ping Flood Attack (ICMP)":
            packet_count = attack_info.get("packet_count", 0)
            packet_rate = attack_info.get("packet_rate", 0)
            time_window = attack_info.get("time_window", 0)
            icmp_ping_count = attack_info.get("icmp_ping_count", 0)
            
            if attack_type == "Ping Flood Attack (ICMP)":
                message_lines.extend([
                    f"*ICMP Ping Packets:* {icmp_ping_count}",
                    f"*Total Packets:* {packet_count}",
                    f"*Rate:* {packet_rate:.2f} packets/sec",
                    f"*Time Window:* {time_window}s",
                    f"*Protocol:* ICMP Echo Request"
                ])
            else:
                message_lines.extend([
                    f"*Packets:* {packet_count}",
                    f"*Rate:* {packet_rate:.2f} packets/sec",
                    f"*Time Window:* {time_window}s"
                ])
        
        elif attack_type == "Port Scanning":
            port_count = attack_info.get("port_count", 0)
            scan_rate = attack_info.get("scan_rate", 0)
            scanned_ports = attack_info.get("scanned_ports", [])
            message_lines.extend([
                f"*Ports Scanned:* {port_count}",
                f"*Scan Rate:* {scan_rate:.2f} ports/sec"
            ])
            if scanned_ports:
                ports_str = ", ".join(map(str, scanned_ports[:20]))
                if port_count > 20:
                    ports_str += f" ... (+{port_count - 20} more)"
                message_lines.append(f"*Ports:* `{ports_str}`")
        
        elif attack_type == "Brute Force Login":
            attempt_count = attack_info.get("attempt_count", 0)
            attempt_rate = attack_info.get("attempt_rate", 0)
            usernames = attack_info.get("usernames_attempted", [])
            message_lines.extend([
                f"*Failed Attempts:* {attempt_count}",
                f"*Attempt Rate:* {attempt_rate:.2f} attempts/sec"
            ])
            if usernames:
                users_str = ", ".join(usernames[:10])
                if len(usernames) > 10:
                    users_str += f" ... (+{len(usernames) - 10} more)"
                message_lines.append(f"*Usernames:* `{users_str}`")
        
        elif attack_type == "Intrusion Attempt":
            subtype = attack_info.get("subtype", "")
            if subtype:
                message_lines.append(f"*Type:* {subtype}")
            
            suspicious_cmd = attack_info.get("suspicious_command")
            if suspicious_cmd:
                message_lines.append(f"*Command:* `{suspicious_cmd[:100]}`")
            
            username = attack_info.get("username")
            if username and username != "unknown":
                message_lines.append(f"*Username:* `{username}`")
            
            pid = attack_info.get("pid")
            if pid:
                message_lines.append(f"*Process ID:* {pid}")
        
        elif attack_type == "CPS Attack":
            subtype = attack_info.get("attack_subtype", "")
            protocol = attack_info.get("protocol", "")
            
            if subtype:
                message_lines.append(f"*Attack Type:* {subtype}")
            if protocol:
                message_lines.append(f"*Protocol:* `{protocol}`")
            
            details = attack_info.get("details", {})
            if details:
                for key, value in list(details.items())[:3]:
                    message_lines.append(f"*{key.replace('_', ' ').title()}:* `{value}`")
            
            modbus_info = attack_info.get("modbus_info")
            if modbus_info:
                message_lines.append(f"*Function:* {modbus_info.get('function_name', 'Unknown')}")
                if modbus_info.get("address"):
                    message_lines.append(f"*Address:* {modbus_info.get('address')}")
        
        # Add timestamp
        from datetime import datetime
        if timestamp:
            dt = datetime.fromtimestamp(timestamp)
            message_lines.append(f"*Time:* {dt.strftime('%Y-%m-%d %H:%M:%S')}")
        
        message = "\n".join(message_lines)
        return message
    
    def send_alert(self, attack_info: Dict):
        """
        Send Telegram message for detected attack.
        
        Args:
            attack_info: Dictionary containing attack information
        """
        if not self.enabled:
            return
        
        try:
            message = self._format_attack_message(attack_info)
            
            # Send message to Telegram
            payload = {
                "chat_id": self.chat_id,
                "text": message,
                "parse_mode": "Markdown"
            }
            
            response = requests.post(
                self.api_url,
                json=payload,
                timeout=10
            )
            
            response.raise_for_status()
            
            logger.info(f"Telegram alert sent: {attack_info.get('attack_type')}")
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending Telegram alert: {e}")
        except Exception as e:
            logger.error(f"Unexpected error sending Telegram alert: {e}")
    
    def test_notification(self):
        """
        Send a test message to verify the system works.
        """
        test_attack = {
            "attack_type": "Test Alert",
            "severity": "INFO",
            "src_ip": "127.0.0.1",
            "timestamp": __import__("time").time(),
            "message": "This is a test notification from RealTimeAttackDetection"
        }
        
        self.send_alert(test_attack)

