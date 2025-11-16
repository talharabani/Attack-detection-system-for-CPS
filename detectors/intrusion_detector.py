"""
Intrusion Attempt Detector.
Detects suspicious commands and unauthorized access attempts.
"""

import re
import time
from typing import Dict, Callable, List, Optional
import logging

from utils.helper import load_config, is_valid_ip


logger = logging.getLogger(__name__)


class IntrusionDetector:
    """
    Detects intrusion attempts by analyzing suspicious commands and activities.
    """
    
    def __init__(self, alert_callback: Callable):
        """
        Initialize intrusion detector.
        
        Args:
            alert_callback: Function to call when attack is detected
        """
        self.alert_callback = alert_callback
        self.enabled = True
        
        # Track failed logins per IP
        self.failed_logins = {}  # {ip: count}
        
        # Load configuration
        try:
            config = load_config()
            intrusion_config = config.get("detection", {}).get("intrusion", {})
            self.enabled = intrusion_config.get("enabled", True)
            self.suspicious_commands = intrusion_config.get(
                "suspicious_commands",
                ["rm -rf", "chmod 777", "wget", "curl", "nc ", "netcat"]
            )
            self.failed_login_threshold = intrusion_config.get("failed_login_threshold", 3)
        except Exception as e:
            logger.warning(f"Could not load config: {e}")
            self.suspicious_commands = ["rm -rf", "chmod 777", "wget", "curl", "nc ", "netcat"]
            self.failed_login_threshold = 3
        
        # Compile regex patterns for suspicious commands
        self.command_patterns = [
            re.compile(re.escape(cmd), re.IGNORECASE)
            for cmd in self.suspicious_commands
        ]
        
        # Additional suspicious patterns
        self.suspicious_patterns = [
            re.compile(r'python\s+-c\s+["\']', re.IGNORECASE),
            re.compile(r'bash\s+-c\s+["\']', re.IGNORECASE),
            re.compile(r'eval\s*\(', re.IGNORECASE),
            re.compile(r'base64\s+-d', re.IGNORECASE),
            re.compile(r'powershell\s+-enc', re.IGNORECASE),
            re.compile(r'certutil\s+-decode', re.IGNORECASE),
        ]
        
        logger.info(f"Intrusion detector initialized with {len(self.suspicious_commands)} suspicious commands")
    
    def _extract_ip_from_log(self, log_line: str) -> Optional[str]:
        """
        Extract IP address from log line.
        
        Args:
            log_line: Log line text
            
        Returns:
            IP address string or None
        """
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        matches = re.findall(ip_pattern, log_line)
        
        for match in matches:
            if is_valid_ip(match):
                return match
        
        return None
    
    def _extract_username_from_log(self, log_line: str) -> Optional[str]:
        """
        Extract username from log line.
        
        Args:
            log_line: Log line text
            
        Returns:
            Username string or None
        """
        # Try various patterns
        patterns = [
            r'user[=:](\w+)',
            r'user (\w+)',
            r'for (\w+) from',
            r'(\w+)@'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, log_line, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _check_suspicious_command(self, log_line: str) -> Optional[str]:
        """
        Check if log line contains suspicious command.
        
        Args:
            log_line: Log line text
            
        Returns:
            Suspicious command found or None
        """
        # Check against suspicious command patterns
        for pattern in self.command_patterns:
            if pattern.search(log_line):
                return pattern.pattern
        
        # Check against additional suspicious patterns
        for pattern in self.suspicious_patterns:
            if pattern.search(log_line):
                return pattern.pattern
        
        return None
    
    def analyze_log_entry(self, log_line: str, log_source: str = "unknown"):
        """
        Analyze a log entry for intrusion patterns.
        
        Args:
            log_line: Log line text
            log_source: Source of the log
        """
        if not self.enabled:
            return
        
        try:
            # Check for suspicious commands
            suspicious_cmd = self._check_suspicious_command(log_line)
            
            if suspicious_cmd:
                src_ip = self._extract_ip_from_log(log_line)
                username = self._extract_username_from_log(log_line)
                
                # Generate attack alert
                attack_info = {
                    "attack_type": "Intrusion Attempt",
                    "subtype": "Suspicious Command",
                    "src_ip": src_ip or "unknown",
                    "username": username or "unknown",
                    "suspicious_command": suspicious_cmd,
                    "log_line": log_line[:500],  # Limit log line length
                    "timestamp": time.time(),
                    "log_source": log_source,
                    "severity": "HIGH"
                }
                
                logger.warning(
                    f"Intrusion attempt detected: suspicious command '{suspicious_cmd}' "
                    f"from IP {src_ip or 'unknown'}"
                )
                
                # Call alert callback
                self.alert_callback(attack_info)
            
            # Track failed logins for potential intrusion
            if self._is_failed_login(log_line):
                src_ip = self._extract_ip_from_log(log_line)
                
                if src_ip and is_valid_ip(src_ip):
                    # Increment failed login count
                    if src_ip not in self.failed_logins:
                        self.failed_logins[src_ip] = 0
                    
                    self.failed_logins[src_ip] += 1
                    
                    # Check if threshold exceeded
                    if self.failed_logins[src_ip] >= self.failed_login_threshold:
                        username = self._extract_username_from_log(log_line)
                        
                        attack_info = {
                            "attack_type": "Intrusion Attempt",
                            "subtype": "Multiple Failed Logins",
                            "src_ip": src_ip,
                            "username": username or "unknown",
                            "failed_login_count": self.failed_logins[src_ip],
                            "timestamp": time.time(),
                            "log_source": log_source,
                            "severity": "MEDIUM"
                        }
                        
                        logger.warning(
                            f"Intrusion attempt detected: {self.failed_logins[src_ip]} "
                            f"failed logins from {src_ip}"
                        )
                        
                        # Call alert callback
                        self.alert_callback(attack_info)
                        
                        # Reset counter to avoid repeated alerts
                        self.failed_logins[src_ip] = 0
        
        except Exception as e:
            logger.error(f"Error analyzing log entry for intrusion: {e}")
    
    def _is_failed_login(self, log_line: str) -> bool:
        """
        Check if log line indicates a failed login.
        
        Args:
            log_line: Log line text
            
        Returns:
            True if failed login, False otherwise
        """
        log_lower = log_line.lower()
        
        indicators = [
            "failed password",
            "authentication failure",
            "invalid user",
            "logon failure",
            "eventid.*4625",
            "eventid.*4776"
        ]
        
        for indicator in indicators:
            if re.search(indicator, log_lower):
                return True
        
        return False
    
    def analyze_process(self, process_info: Dict):
        """
        Analyze process information for suspicious activity.
        
        Args:
            process_info: Dictionary containing process information
        """
        if not self.enabled:
            return
        
        try:
            cmdline = process_info.get("cmdline", "")
            
            if not cmdline or cmdline == "N/A":
                return
            
            # Check for suspicious commands in process
            suspicious_cmd = self._check_suspicious_command(cmdline)
            
            if suspicious_cmd:
                attack_info = {
                    "attack_type": "Intrusion Attempt",
                    "subtype": "Suspicious Process",
                    "pid": process_info.get("pid"),
                    "process_name": process_info.get("name"),
                    "cmdline": cmdline,
                    "suspicious_command": suspicious_cmd,
                    "username": process_info.get("username", "unknown"),
                    "timestamp": time.time(),
                    "severity": "HIGH"
                }
                
                logger.warning(
                    f"Intrusion attempt detected: suspicious process '{process_info.get('name')}' "
                    f"(PID: {process_info.get('pid')})"
                )
                
                # Call alert callback
                self.alert_callback(attack_info)
        
        except Exception as e:
            logger.error(f"Error analyzing process for intrusion: {e}")
    
    def get_statistics(self) -> Dict:
        """
        Get detector statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            "monitored_ips": len(self.failed_logins),
            "failed_login_counts": dict(self.failed_logins),
            "suspicious_commands_count": len(self.suspicious_commands),
            "enabled": self.enabled
        }

