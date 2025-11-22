"""
Discord webhook alert system.
Sends alerts to Discord when attacks are detected.
"""

import logging
import requests
from typing import Dict, Optional
from datetime import datetime

from utils.helper import load_config


logger = logging.getLogger(__name__)


class DiscordAlert:
    """
    Sends Discord messages via webhook for detected attacks.
    """
    
    def __init__(self):
        """Initialize Discord alert system."""
        self.enabled = False
        self.webhook_url = None
        
        # Load configuration
        try:
            config = load_config()
            discord_config = config.get("alerts", {}).get("discord", {})
            self.enabled = discord_config.get("enabled", False)
            self.webhook_url = discord_config.get("webhook_url", "")
            
            if self.enabled:
                if not self.webhook_url or self.webhook_url == "YOUR_DISCORD_WEBHOOK_URL":
                    logger.warning("Discord webhook URL not configured. Discord alerts disabled.")
                    self.enabled = False
                else:
                    logger.info("Discord alert system initialized")
        
        except Exception as e:
            logger.warning(f"Could not load config: {e}")
    
    def _format_attack_embed(self, attack_info: Dict) -> Dict:
        """
        Format attack information into Discord embed.
        
        Args:
            attack_info: Dictionary containing attack information
            
        Returns:
            Discord embed dictionary
        """
        attack_type = attack_info.get("attack_type", "Unknown Attack")
        severity = attack_info.get("severity", "UNKNOWN")
        timestamp = attack_info.get("timestamp", 0)
        src_ip = attack_info.get("src_ip", "Unknown")
        
        # Color based on severity
        color_map = {
            "LOW": 0xFFFF00,      # Yellow
            "MEDIUM": 0xFFA500,   # Orange
            "HIGH": 0xFF0000,     # Red
            "CRITICAL": 0x8B0000  # Dark Red
        }
        color = color_map.get(severity, 0x808080)  # Default gray
        
        # Emoji based on severity
        severity_emoji = {
            "LOW": "⚠️",
            "MEDIUM": "🔶",
            "HIGH": "🔴",
            "CRITICAL": "🚨"
        }
        emoji = severity_emoji.get(severity, "⚠️")
        
        # Build embed
        embed = {
            "title": f"{emoji} {attack_type} Detected",
            "color": color,
            "fields": [],
            "timestamp": datetime.utcnow().isoformat() if timestamp else None,
            "footer": {
                "text": "RealTime Attack Detection System"
            }
        }
        
        # Add severity field
        embed["fields"].append({
            "name": "Severity",
            "value": severity,
            "inline": True
        })
        
        # Add source IP
        if src_ip and src_ip != "unknown":
            embed["fields"].append({
                "name": "Source IP",
                "value": f"`{src_ip}`",
                "inline": True
            })
        
        # Add attack-specific details
        if attack_type == "DDoS/Flooding" or attack_type == "Ping Flood Attack":
            packet_count = attack_info.get("packet_count", 0)
            packet_rate = attack_info.get("packet_rate", 0)
            time_window = attack_info.get("time_window", 0)
            
            if attack_type == "Ping Flood Attack":
                embed["fields"].extend([
                    {
                        "name": "ICMP Ping Packets",
                        "value": f"{int(packet_count):,}",
                        "inline": True
                    },
                    {
                        "name": "Packet Rate",
                        "value": f"{packet_rate:.2f} packets/sec",
                        "inline": True
                    },
                    {
                        "name": "Time Window",
                        "value": f"{time_window}s",
                        "inline": True
                    },
                    {
                        "name": "Protocol",
                        "value": "ICMP Echo Request",
                        "inline": True
                    }
                ])
            else:
                embed["fields"].extend([
                    {
                        "name": "Packets",
                        "value": f"{int(packet_count):,}",
                        "inline": True
                    },
                    {
                        "name": "Packet Rate",
                        "value": f"{packet_rate:.2f} packets/sec",
                        "inline": True
                    },
                    {
                        "name": "Time Window",
                        "value": f"{time_window}s",
                        "inline": True
                    }
                ])
        
        elif attack_type == "Port Scanning":
            port_count = attack_info.get("port_count", 0)
            scan_rate = attack_info.get("scan_rate", 0)
            scanned_ports = attack_info.get("scanned_ports", [])
            
            embed["fields"].extend([
                {
                    "name": "Ports Scanned",
                    "value": f"{port_count}",
                    "inline": True
                },
                {
                    "name": "Scan Rate",
                    "value": f"{scan_rate:.2f} ports/sec",
                    "inline": True
                }
            ])
            
            if scanned_ports:
                ports_str = ", ".join(map(str, scanned_ports[:20]))
                if port_count > 20:
                    ports_str += f" ... (+{port_count - 20} more)"
                embed["fields"].append({
                    "name": "Scanned Ports",
                    "value": f"`{ports_str}`",
                    "inline": False
                })
        
        elif attack_type == "Brute Force Login":
            attempt_count = attack_info.get("attempt_count", 0)
            attempt_rate = attack_info.get("attempt_rate", 0)
            usernames = attack_info.get("usernames_attempted", [])
            
            embed["fields"].extend([
                {
                    "name": "Failed Attempts",
                    "value": f"{attempt_count}",
                    "inline": True
                },
                {
                    "name": "Attempt Rate",
                    "value": f"{attempt_rate:.2f} attempts/sec",
                    "inline": True
                }
            ])
            
            if usernames:
                users_str = ", ".join(usernames[:10])
                if len(usernames) > 10:
                    users_str += f" ... (+{len(usernames) - 10} more)"
                embed["fields"].append({
                    "name": "Targeted Usernames",
                    "value": f"`{users_str}`",
                    "inline": False
                })
        
        elif attack_type == "Intrusion Attempt":
            subtype = attack_info.get("subtype", "")
            if subtype:
                embed["fields"].append({
                    "name": "Attack Type",
                    "value": subtype,
                    "inline": True
                })
            
            suspicious_cmd = attack_info.get("suspicious_command")
            if suspicious_cmd:
                embed["fields"].append({
                    "name": "Suspicious Command",
                    "value": f"`{suspicious_cmd[:200]}`",
                    "inline": False
                })
            
            username = attack_info.get("username")
            if username and username != "unknown":
                embed["fields"].append({
                    "name": "Username",
                    "value": f"`{username}`",
                    "inline": True
                })
        
        elif attack_type == "CPS Attack":
            subtype = attack_info.get("attack_subtype", "")
            protocol = attack_info.get("protocol", "")
            
            if subtype:
                embed["fields"].append({
                    "name": "Attack Type",
                    "value": subtype,
                    "inline": True
                })
            if protocol:
                embed["fields"].append({
                    "name": "Protocol",
                    "value": f"`{protocol}`",
                    "inline": True
                })
            
            # Add Modbus-specific details if available
            modbus_info = attack_info.get("modbus_info")
            if modbus_info:
                function_name = modbus_info.get("function_name", "Unknown")
                embed["fields"].append({
                    "name": "Modbus Function",
                    "value": f"`{function_name}`",
                    "inline": True
                })
                if modbus_info.get("address"):
                    embed["fields"].append({
                        "name": "Modbus Address",
                        "value": f"`{modbus_info.get('address')}`",
                        "inline": True
                    })
        
        elif "Modbus" in attack_type or attack_type in ["Modbus Attack", "Modbus Command Injection", "Unauthorized Modbus Write"]:
            # Handle Modbus-specific attacks
            subtype = attack_info.get("attack_subtype", "")
            protocol = attack_info.get("protocol", "Modbus")
            
            embed["fields"].append({
                "name": "Protocol",
                "value": "Modbus",
                "inline": True
            })
            
            if subtype:
                embed["fields"].append({
                    "name": "Attack Subtype",
                    "value": subtype,
                    "inline": True
                })
            
            # Get Modbus-specific information
            modbus_info = attack_info.get("modbus_info", {})
            if modbus_info:
                function_name = modbus_info.get("function_name", "Unknown")
                function_code = modbus_info.get("function_code")
                
                embed["fields"].append({
                    "name": "Function",
                    "value": f"`{function_name}`" + (f" (Code: {function_code})" if function_code else ""),
                    "inline": True
                })
                
                if modbus_info.get("unit_id"):
                    embed["fields"].append({
                        "name": "Unit ID",
                        "value": f"`{modbus_info.get('unit_id')}`",
                        "inline": True
                    })
                
                if modbus_info.get("address"):
                    embed["fields"].append({
                        "name": "Register Address",
                        "value": f"`{modbus_info.get('address')}`",
                        "inline": True
                    })
                
                if modbus_info.get("value"):
                    embed["fields"].append({
                        "name": "Value Written",
                        "value": f"`{modbus_info.get('value')}`",
                        "inline": True
                    })
            
            # Add packet count if available
            packet_count = attack_info.get("packet_count", 0)
            if packet_count:
                embed["fields"].append({
                    "name": "Packets",
                    "value": f"{int(packet_count):,}",
                    "inline": True
                })
        
        # Add timestamp if available
        if timestamp:
            try:
                dt = datetime.fromtimestamp(timestamp)
                embed["fields"].append({
                    "name": "Timestamp",
                    "value": dt.strftime("%Y-%m-%d %H:%M:%S"),
                    "inline": False
                })
            except:
                pass
        
        return embed
    
    def send_alert(self, attack_info: Dict):
        """
        Send Discord message via webhook for detected attack.
        
        Args:
            attack_info: Dictionary containing attack information
        """
        if not self.enabled:
            return
        
        try:
            embed = self._format_attack_embed(attack_info)
            
            # Discord webhook payload
            payload = {
                "embeds": [embed]
            }
            
            # Send message to Discord
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )
            
            response.raise_for_status()
            
            logger.info(f"Discord alert sent: {attack_info.get('attack_type')}")
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending Discord alert: {e}")
        except Exception as e:
            logger.error(f"Unexpected error sending Discord alert: {e}")
    
    def test_notification(self):
        """
        Send a test message to verify the system works.
        """
        test_attack = {
            "attack_type": "Test Alert",
            "severity": "MEDIUM",
            "src_ip": "127.0.0.1",
            "timestamp": __import__("time").time(),
            "packet_count": 100,
            "packet_rate": 50.5,
            "time_window": 5
        }
        
        self.send_alert(test_attack)

