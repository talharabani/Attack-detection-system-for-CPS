"""
Brute Force Login Attack Detector.
Detects multiple failed login attempts from the same IP address.
"""

import re
import time
from collections import defaultdict
from typing import Dict, Callable, Optional
import logging

from utils.helper import load_config, is_valid_ip


logger = logging.getLogger(__name__)


class BruteForceDetector:
    """
    Detects brute force login attempts by analyzing authentication logs.
    """
    
    def __init__(self, alert_callback: Callable):
        """
        Initialize brute force detector.
        
        Args:
            alert_callback: Function to call when attack is detected
        """
        self.alert_callback = alert_callback
        self.enabled = True
        
        # Track failed login attempts: {ip: [(timestamp, username), ...]}
        self.failed_attempts = defaultdict(list)
        
        # Load configuration
        try:
            config = load_config()
            brute_config = config.get("detection", {}).get("brute_force", {})
            self.enabled = brute_config.get("enabled", True)
            self.failed_threshold = brute_config.get("failed_attempts_threshold", 5)
            self.time_window = brute_config.get("time_window_seconds", 300)
            self.ip_whitelist = set(brute_config.get("ip_whitelist", []))
        except Exception as e:
            logger.warning(f"Could not load config: {e}")
            self.failed_threshold = 5
            self.time_window = 300
            self.ip_whitelist = set()
        
        # Patterns for detecting failed logins
        self.linux_patterns = [
            r"Failed password for (\w+) from ([\d.]+)",
            r"authentication failure.*rhost=([\d.]+).*user=(\w+)",
            r"Invalid user (\w+) from ([\d.]+)",
            r"Connection closed by authenticating user (\w+) ([\d.]+)"
        ]
        
        self.windows_patterns = [
            r"EventID.*4625",  # Failed logon
            r"EventID.*4776"   # Credential validation failed
        ]
        
        logger.info(
            f"Brute force detector initialized: threshold={self.failed_threshold} "
            f"attempts in {self.time_window}s"
        )
    
    def _extract_ip_from_log(self, log_line: str) -> Optional[str]:
        """
        Extract IP address from log line.
        
        Args:
            log_line: Log line text
            
        Returns:
            IP address string or None
        """
        # Try to find IP address in log line
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
        # Try Linux patterns
        for pattern in self.linux_patterns:
            match = re.search(pattern, log_line, re.IGNORECASE)
            if match:
                # Pattern groups: username is usually first group
                if len(match.groups()) >= 1:
                    return match.group(1)
        
        # Try to find "user=" pattern
        user_match = re.search(r'user[=:](\w+)', log_line, re.IGNORECASE)
        if user_match:
            return user_match.group(1)
        
        return None
    
    def _is_failed_login(self, log_line: str) -> bool:
        """
        Check if log line indicates a failed login attempt.
        
        Args:
            log_line: Log line text
            
        Returns:
            True if failed login, False otherwise
        """
        log_lower = log_line.lower()
        
        # Linux indicators
        linux_indicators = [
            "failed password",
            "authentication failure",
            "invalid user",
            "connection closed by authenticating user",
            "pam_unix(sshd:auth): authentication failure"
        ]
        
        # Windows indicators
        windows_indicators = [
            "eventid.*4625",
            "eventid.*4776",
            "logon failure"
        ]
        
        all_indicators = linux_indicators + windows_indicators
        
        for indicator in all_indicators:
            if re.search(indicator, log_lower):
                return True
        
        return False
    
    def analyze_log_entry(self, log_line: str, log_source: str = "unknown"):
        """
        Analyze a log entry for brute force patterns.
        
        Args:
            log_line: Log line text
            log_source: Source of the log (e.g., "auth.log", "WindowsEventLog")
        """
        if not self.enabled:
            return
        
        try:
            # Check if this is a failed login
            if not self._is_failed_login(log_line):
                return
            
            # Extract IP and username
            src_ip = self._extract_ip_from_log(log_line)
            username = self._extract_username_from_log(log_line)
            
            if not src_ip or not is_valid_ip(src_ip):
                return
            
            # Skip whitelisted IPs
            if src_ip in self.ip_whitelist:
                return
            
            current_time = time.time()
            
            # Add failed attempt to history
            self.failed_attempts[src_ip].append((current_time, username or "unknown"))
            
            # Clean old attempts
            self._clean_old_attempts(current_time)
            
            # Check if threshold is exceeded
            attempt_count = len(self.failed_attempts[src_ip])
            
            if attempt_count >= self.failed_threshold:
                # Get unique usernames attempted
                usernames = set(
                    username for _, username in self.failed_attempts[src_ip]
                )
                
                # Calculate attempt rate
                if self.failed_attempts[src_ip]:
                    first_attempt_time = self.failed_attempts[src_ip][0][0]
                    time_span = current_time - first_attempt_time
                    attempt_rate = attempt_count / time_span if time_span > 0 else 0
                else:
                    attempt_rate = 0
                
                # Generate attack alert
                attack_info = {
                    "attack_type": "Brute Force Login",
                    "src_ip": src_ip,
                    "attempt_count": attempt_count,
                    "usernames_attempted": list(usernames),
                    "attempt_rate": attempt_rate,
                    "time_window": self.time_window,
                    "timestamp": current_time,
                    "log_source": log_source,
                    "severity": "HIGH"
                }
                
                logger.warning(
                    f"Brute force attack detected from {src_ip}: "
                    f"{attempt_count} failed attempts in {time_span:.2f}s"
                )
                
                # Call alert callback
                self.alert_callback(attack_info)
                
                # Clear history for this IP to avoid repeated alerts
                del self.failed_attempts[src_ip]
        
        except Exception as e:
            logger.error(f"Error analyzing log entry for brute force: {e}")
    
    def _clean_old_attempts(self, current_time: float):
        """
        Remove failed attempts outside the time window.
        
        Args:
            current_time: Current timestamp
        """
        cutoff_time = current_time - self.time_window
        
        for ip in list(self.failed_attempts.keys()):
            # Filter out old attempts
            self.failed_attempts[ip] = [
                (ts, username) for ts, username in self.failed_attempts[ip]
                if ts > cutoff_time
            ]
            
            # Remove empty entries
            if not self.failed_attempts[ip]:
                del self.failed_attempts[ip]
    
    def get_statistics(self) -> Dict:
        """
        Get detector statistics.
        
        Returns:
            Dictionary with statistics
        """
        current_time = time.time()
        self._clean_old_attempts(current_time)
        
        ip_stats = {}
        for ip, attempts in self.failed_attempts.items():
            if attempts:
                first_time = attempts[0][0]
                time_span = current_time - first_time
                attempt_rate = len(attempts) / time_span if time_span > 0 else 0
                usernames = set(username for _, username in attempts)
                ip_stats[ip] = {
                    "attempt_count": len(attempts),
                    "attempt_rate": attempt_rate,
                    "usernames_attempted": list(usernames)
                }
        
        return {
            "monitored_ips": len(self.failed_attempts),
            "ip_statistics": ip_stats,
            "enabled": self.enabled
        }

