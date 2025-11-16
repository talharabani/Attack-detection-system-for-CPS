"""
Port Scanning Attack Detector.
Detects Nmap-style port scanning attempts.
"""

import time
from collections import defaultdict
from typing import Dict, Callable, Set
import logging

from utils.helper import load_config, is_valid_ip


logger = logging.getLogger(__name__)


class PortScanDetector:
    """
    Detects port scanning attacks by monitoring connection attempts to multiple ports.
    """
    
    def __init__(self, alert_callback: Callable):
        """
        Initialize port scan detector.
        
        Args:
            alert_callback: Function to call when attack is detected
        """
        self.alert_callback = alert_callback
        self.enabled = True
        
        # Track ports scanned per IP: {ip: {ports: set, first_seen: timestamp, last_seen: timestamp}}
        self.scan_tracking = {}
        
        # Load configuration
        try:
            config = load_config()
            scan_config = config.get("detection", {}).get("port_scan", {})
            self.enabled = scan_config.get("enabled", True)
            self.port_threshold = scan_config.get("port_threshold", 20)
            self.time_window = scan_config.get("time_window_seconds", 30)
            self.ip_whitelist = set(scan_config.get("ip_whitelist", []))
        except Exception as e:
            logger.warning(f"Could not load config: {e}")
            self.port_threshold = 20
            self.time_window = 30
            self.ip_whitelist = set()
        
        logger.info(f"Port scan detector initialized: threshold={self.port_threshold} ports in {self.time_window}s")
    
    def _clean_old_scans(self, current_time: float):
        """
        Remove scan tracking data outside the time window.
        
        Args:
            current_time: Current timestamp
        """
        cutoff_time = current_time - self.time_window
        
        expired_ips = [
            ip for ip, data in self.scan_tracking.items()
            if data["last_seen"] < cutoff_time
        ]
        
        for ip in expired_ips:
            del self.scan_tracking[ip]
    
    def analyze_packet(self, packet_info: Dict):
        """
        Analyze a network packet for port scanning patterns.
        
        Args:
            packet_info: Dictionary containing packet information
        """
        if not self.enabled:
            return
        
        try:
            src_ip = packet_info.get("src_ip")
            dst_port = packet_info.get("dst_port")
            
            if not src_ip or not is_valid_ip(src_ip):
                return
            
            if dst_port is None:
                return
            
            # Skip whitelisted IPs
            if src_ip in self.ip_whitelist:
                return
            
            current_time = time.time()
            
            # Initialize tracking for this IP if not exists
            if src_ip not in self.scan_tracking:
                self.scan_tracking[src_ip] = {
                    "ports": set(),
                    "first_seen": current_time,
                    "last_seen": current_time
                }
            
            # Add port to tracking
            self.scan_tracking[src_ip]["ports"].add(dst_port)
            self.scan_tracking[src_ip]["last_seen"] = current_time
            
            # Clean old scans
            self._clean_old_scans(current_time)
            
            # Check if threshold is exceeded
            port_count = len(self.scan_tracking[src_ip]["ports"])
            
            if port_count >= self.port_threshold:
                # Calculate scan rate
                time_span = current_time - self.scan_tracking[src_ip]["first_seen"]
                scan_rate = port_count / time_span if time_span > 0 else 0
                
                # Get list of scanned ports (sorted)
                scanned_ports = sorted(list(self.scan_tracking[src_ip]["ports"]))
                
                # Generate attack alert
                attack_info = {
                    "attack_type": "Port Scanning",
                    "src_ip": src_ip,
                    "port_count": port_count,
                    "scanned_ports": scanned_ports[:50],  # Limit to first 50 ports
                    "scan_rate": scan_rate,
                    "time_window": self.time_window,
                    "timestamp": current_time,
                    "severity": "MEDIUM"
                }
                
                logger.warning(
                    f"Port scan detected from {src_ip}: {port_count} ports scanned "
                    f"in {time_span:.2f}s"
                )
                
                # Call alert callback
                self.alert_callback(attack_info)
                
                # Clear tracking for this IP to avoid repeated alerts
                del self.scan_tracking[src_ip]
        
        except Exception as e:
            logger.error(f"Error analyzing packet for port scan: {e}")
    
    def get_statistics(self) -> Dict:
        """
        Get detector statistics.
        
        Returns:
            Dictionary with statistics
        """
        current_time = time.time()
        self._clean_old_scans(current_time)
        
        ip_stats = {}
        for ip, data in self.scan_tracking.items():
            time_span = current_time - data["first_seen"]
            scan_rate = len(data["ports"]) / time_span if time_span > 0 else 0
            ip_stats[ip] = {
                "port_count": len(data["ports"]),
                "scan_rate": scan_rate,
                "ports": sorted(list(data["ports"]))[:10]  # Show first 10 ports
            }
        
        return {
            "monitored_ips": len(self.scan_tracking),
            "ip_statistics": ip_stats,
            "enabled": self.enabled
        }

