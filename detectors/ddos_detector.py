"""
DDoS (Distributed Denial of Service) and Flooding Attack Detector.
Detects high packet rates from the same IP address using dynamic baseline detection.
"""

import time
from collections import defaultdict, deque
from typing import Dict, Callable, List, Optional
import logging

from utils.helper import load_config, is_valid_ip, is_private_ip


logger = logging.getLogger(__name__)


class DDoSDetector:
    """
    Detects DDoS and flooding attacks by monitoring packet rates from IP addresses.
    Uses dynamic baseline detection to reduce false positives.
    """
    
    def __init__(self, alert_callback: Callable):
        """
        Initialize DDoS detector.
        
        Args:
            alert_callback: Function to call when attack is detected
        """
        self.alert_callback = alert_callback
        self.enabled = True
        
        # Packet tracking with sliding window: {ip: deque([(timestamp, packet_info), ...])}
        self.packet_history = defaultdict(lambda: deque(maxlen=10000))  # Limit memory usage
        
        # Baseline tracking for dynamic threshold
        self.baseline_packets = deque(maxlen=100000)  # Store packets for baseline calculation
        self.baseline_start_time = None
        self.baseline_period = 30  # 30 seconds
        self.baseline_calculated = False
        self.baseline_pps = 0.0  # Packets per second baseline
        self.dynamic_threshold_multiplier = 10
        
        # Static threshold (fallback) - Lower for better ping flood detection
        self.packet_threshold = 100  # Lowered from 500 for better detection
        self.time_window = 5  # 5 seconds
        
        # ICMP-specific threshold (VERY sensitive for ping floods)
        self.icmp_threshold = 10  # ICMP packets in time window (VERY LOW for immediate detection)
        self.icmp_time_window = 3  # 3 seconds (shorter window for faster detection)
        
        # Filtering options
        self.min_packet_size = 64  # bytes
        self.ignore_localhost = False  # Changed to False to detect attacks from other machines
        self.ignore_dns = True
        
        # Debug mode
        self.debug_mode = False
        
        # Statistics tracking per IP
        self.ip_statistics = defaultdict(lambda: {
            "packet_count": 0,
            "last_log_time": 0,
            "log_interval": 10  # Log stats every 10 seconds
        })
        
        # Load configuration
        self._load_config()
        
        logger.info(
            f"DDoS detector initialized: static_threshold={self.packet_threshold} packets "
            f"in {self.time_window}s, baseline_period={self.baseline_period}s, "
            f"dynamic_multiplier={self.dynamic_threshold_multiplier}x"
        )
    
    def _load_config(self):
        """Load configuration from config.json"""
        try:
            config = load_config()
            ddos_config = config.get("detection", {}).get("ddos", {})
            self.enabled = ddos_config.get("enabled", True)
            self.packet_threshold = ddos_config.get("packet_threshold", 100)
            self.time_window = ddos_config.get("time_window_seconds", 5)
            self.icmp_threshold = ddos_config.get("icmp_threshold", 10)
            self.icmp_time_window = ddos_config.get("icmp_time_window_seconds", 3)
            self.baseline_period = ddos_config.get("baseline_period_seconds", 30)
            self.dynamic_threshold_multiplier = ddos_config.get("dynamic_threshold_multiplier", 10)
            self.min_packet_size = ddos_config.get("min_packet_size_bytes", 64)
            self.ignore_localhost = ddos_config.get("ignore_localhost", False)
            self.ignore_dns = ddos_config.get("ignore_dns_traffic", True)
            self.ip_whitelist = set(ddos_config.get("ip_whitelist", []))
            
            # Load debug mode
            self.debug_mode = config.get("general", {}).get("debug", False)
        except Exception as e:
            logger.warning(f"Could not load config: {e}")
    
    def _should_filter_packet(self, packet_info: Dict) -> bool:
        """
        Check if packet should be filtered (ignored).
        
        Args:
            packet_info: Dictionary containing packet information
            
        Returns:
            True if packet should be filtered, False otherwise
        """
        src_ip = packet_info.get("src_ip", "")
        protocol = packet_info.get("protocol", 0)
        
        # Filter localhost (but allow if testing from same machine)
        if self.ignore_localhost and (src_ip == "127.0.0.1" or src_ip == "::1"):
            # Don't filter ICMP from localhost - might be testing
            if protocol != 1:  # ICMP protocol = 1
                return True
        
        # DON'T filter ICMP packets by size - they're important for ping flood detection
        # ICMP packets are typically 64 bytes, but we want to detect them
        if protocol != 1:  # Only filter size for non-ICMP
            packet_size = packet_info.get("size", 0)
            if packet_size < self.min_packet_size:
                return True
        
        # Filter DNS traffic (port 53) - but not ICMP
        if self.ignore_dns and protocol != 1:
            dst_port = packet_info.get("dst_port")
            src_port = packet_info.get("src_port")
            
            # UDP or TCP port 53 (DNS)
            if protocol in [6, 17] and (dst_port == 53 or src_port == 53):
                return True
        
        return False
    
    def _calculate_baseline(self, current_time: float) -> bool:
        """
        Calculate baseline packets per second from first 30 seconds.
        
        Args:
            current_time: Current timestamp
            
        Returns:
            True if baseline was calculated, False if still in baseline period
        """
        if self.baseline_calculated:
            return True
        
        if self.baseline_start_time is None:
            self.baseline_start_time = current_time
            return False
        
        elapsed = current_time - self.baseline_start_time
        
        if elapsed < self.baseline_period:
            return False
        
        # Calculate baseline PPS
        if self.baseline_packets:
            total_packets = len(self.baseline_packets)
            self.baseline_pps = total_packets / elapsed
            
            logger.info(
                f"Baseline calculated: {self.baseline_pps:.2f} PPS "
                f"(from {total_packets} packets over {elapsed:.2f}s)"
            )
            
            self.baseline_calculated = True
            return True
        
        return False
    
    def _get_dynamic_threshold(self) -> float:
        """
        Get dynamic threshold based on baseline.
        
        Returns:
            Dynamic threshold in packets per second
        """
        if self.baseline_calculated and self.baseline_pps > 0:
            return self.baseline_pps * self.dynamic_threshold_multiplier
        return float('inf')  # No baseline yet, use static threshold only
    
    def _clean_old_packets(self, current_time: float):
        """
        Remove packets outside the time window using sliding window.
        
        Args:
            current_time: Current timestamp
        """
        cutoff_time = current_time - self.time_window
        
        for ip in list(self.packet_history.keys()):
            # Remove old packets from deque (sliding window)
            while self.packet_history[ip] and self.packet_history[ip][0][0] < cutoff_time:
                self.packet_history[ip].popleft()
            
            # Remove empty entries
            if not self.packet_history[ip]:
                del self.packet_history[ip]
    
    def _get_packets_in_window(self, ip: str, current_time: float) -> List:
        """
        Get packets within the time window for an IP.
        
        Args:
            ip: IP address
            current_time: Current timestamp
            
        Returns:
            List of packets within time window
        """
        cutoff_time = current_time - self.time_window
        return [
            (ts, pkt) for ts, pkt in self.packet_history[ip]
            if ts > cutoff_time
        ]
    
    def _log_packet_stats(self, src_ip: str, packet_rate: float, threshold: float, current_time: float):
        """
        Log packet statistics for an IP (if debug mode or periodic logging).
        
        Args:
            src_ip: Source IP address
            packet_rate: Current packet rate (PPS)
            threshold: Current threshold (PPS)
            current_time: Current timestamp
        """
        stats = self.ip_statistics[src_ip]
        
        # Check if we should log (debug mode or periodic)
        should_log = False
        if self.debug_mode:
            should_log = True
        elif current_time - stats["last_log_time"] >= stats["log_interval"]:
            should_log = True
        
        if should_log:
            logger.info(
                f"IP {src_ip} PPS: {packet_rate:.2f}, "
                f"Threshold: {threshold:.2f}, "
                f"Status: {'ALERT' if packet_rate > threshold else 'NORMAL'}"
            )
            stats["last_log_time"] = current_time
    
    def analyze_packet(self, packet_info: Dict):
        """
        Analyze a network packet for DDoS patterns.
        Uses dynamic baseline detection and sliding window counting.
        
        Args:
            packet_info: Dictionary containing packet information
        """
        if not self.enabled:
            return
        
        try:
            current_time = time.time()
            
            # Check if this is an ICMP packet FIRST (before filtering)
            protocol = packet_info.get("protocol", 0)
            is_icmp = (protocol == 1)
            icmp_type = packet_info.get("icmp_type")
            is_ping = (is_icmp and icmp_type == 8)
            
            # DEBUG: Log ALL ICMP ping packets immediately (ALWAYS, not just debug mode)
            if is_ping:
                src_ip_debug = packet_info.get("src_ip", "unknown")
                logger.info(f"[ICMP] PING packet from {src_ip_debug} (type={icmp_type})")
                if self.debug_mode:
                    logger.debug(f"[ICMP-DEBUG] PING packet details: {packet_info}")
            
            # Calculate baseline if needed
            self._calculate_baseline(current_time)
            
            # Store packet for baseline calculation (if still in baseline period)
            if not self.baseline_calculated:
                self.baseline_packets.append((current_time, packet_info))
            
            # Filter packets (but NEVER filter ICMP ping packets - they're critical for detection)
            if not is_ping:
                if self._should_filter_packet(packet_info):
                    return
            
            src_ip = packet_info.get("src_ip")
            
            if not src_ip or not is_valid_ip(src_ip):
                return
            
            # Skip whitelisted IPs
            if src_ip in self.ip_whitelist:
                return
            
            # Add packet to history (sliding window)
            self.packet_history[src_ip].append((current_time, packet_info))
            
            # Clean old packets
            self._clean_old_packets(current_time)
            
            # Get packets in current window
            packets_in_window = self._get_packets_in_window(src_ip, current_time)
            packet_count = len(packets_in_window)
            
            if packet_count == 0:
                return
            
            # Calculate packet rate (PPS)
            if packets_in_window:
                first_packet_time = packets_in_window[0][0]
                time_span = current_time - first_packet_time
                packet_rate = packet_count / time_span if time_span > 0 else 0
            else:
                packet_rate = 0
            
            # Count ICMP ping packets in ICMP-specific window (3 seconds, not 5)
            icmp_window_cutoff = current_time - self.icmp_time_window
            icmp_window_packets = [
                (ts, pkt) for ts, pkt in self.packet_history[src_ip]
                if ts > icmp_window_cutoff
                and pkt.get("protocol") == 1 
                and pkt.get("icmp_type") == 8
            ]
            icmp_ping_count = len(icmp_window_packets)
            
            # DEBUG: Log ICMP packets for troubleshooting (ALWAYS log, not just debug mode)
            if icmp_ping_count > 0:
                if icmp_ping_count >= self.icmp_threshold * 0.5:  # Log when we're at 50% of threshold
                    logger.info(
                        f"[ICMP-COUNT] ICMP packets from {src_ip}: {icmp_ping_count} ICMP in {self.icmp_time_window}s "
                        f"(Threshold: {self.icmp_threshold})"
                    )
                elif self.debug_mode:
                    logger.debug(
                        f"[ICMP-COUNT] ICMP packets from {src_ip}: {icmp_ping_count} ICMP in {self.icmp_time_window}s "
                        f"(Threshold: {self.icmp_threshold})"
                    )
            
            # Check for ICMP ping flood FIRST (VERY sensitive threshold)
            # NO BASELINE NEEDED FOR ICMP - detect immediately
            is_ping_flood = False
            if icmp_ping_count >= self.icmp_threshold:
                    is_ping_flood = True
                    logger.warning(
                        f"[ALERT] PING FLOOD DETECTED from {src_ip}: {icmp_ping_count} ICMP packets "
                        f"in {self.icmp_time_window}s (Threshold: {self.icmp_threshold})"
                    )
            
            # Determine threshold to use
            dynamic_threshold_pps = self._get_dynamic_threshold()
            static_threshold_pps = self.packet_threshold / self.time_window
            
            # For ICMP, use lower threshold
            if icmp_ping_count > 0:
                # Use ICMP-specific threshold (more sensitive)
                icmp_threshold_pps = self.icmp_threshold / self.icmp_time_window
                threshold_pps = min(icmp_threshold_pps, static_threshold_pps)
            else:
                # Use the lower threshold (more sensitive)
                threshold_pps = min(dynamic_threshold_pps, static_threshold_pps) if dynamic_threshold_pps != float('inf') else static_threshold_pps
            
            threshold_packets = threshold_pps * self.time_window
            
            # Log statistics (debug mode or periodic)
            self._log_packet_stats(src_ip, packet_rate, threshold_pps, current_time)
            
            # Check if threshold is exceeded OR ping flood detected
            # For ICMP, trigger immediately if threshold met (no baseline wait)
            should_alert = False
            
            if is_ping_flood:
                # IMMEDIATE ALERT for ping flood - don't wait for baseline
                should_alert = True
            elif not self.baseline_calculated:
                # During baseline period, only alert on ICMP floods
                # Don't alert on general traffic until baseline is calculated
                if icmp_ping_count == 0:
                    return
                should_alert = is_ping_flood
            elif packet_count >= threshold_packets or packet_rate > threshold_pps:
                # General threshold exceeded
                should_alert = True
            else:
                # No attack detected
                return
            
            if should_alert:
                # Generate attack alert with specific type
                if is_ping_flood:
                    attack_type = "Ping Flood Attack (ICMP)"
                    attack_subtype = "ICMP Echo Request Flood"
                    severity = "HIGH"
                else:
                    attack_type = "DDoS/Flooding"
                    attack_subtype = "General Packet Flood"
                    severity = "HIGH"
                
                attack_info = {
                    "attack_type": attack_type,
                    "attack_subtype": attack_subtype,
                    "src_ip": src_ip,
                    "packet_count": packet_count,
                    "icmp_ping_count": icmp_ping_count if is_ping_flood else 0,
                    "packet_rate": packet_rate,
                    "packet_rate_pps": packet_rate,
                    "threshold_pps": threshold_pps,
                    "baseline_pps": self.baseline_pps if self.baseline_calculated else 0,
                    "time_window": self.icmp_time_window if is_ping_flood else self.time_window,
                    "timestamp": current_time,
                    "severity": severity,
                    "protocol": "ICMP" if is_ping_flood else "Mixed"
                }
                
                # Logging already done above for ping floods, only log non-ping attacks here
                if not is_ping_flood:
                    logger.warning(
                        f"DDoS attack detected from {src_ip}: {packet_count} packets "
                        f"({packet_rate:.2f} PPS) in {time_span:.2f}s "
                        f"(Threshold: {threshold_pps:.2f} PPS)"
                    )
                
                # Call alert callback
                self.alert_callback(attack_info)
                
                # Clear history for this IP to avoid repeated alerts
                if src_ip in self.packet_history:
                    del self.packet_history[src_ip]
        
        except Exception as e:
            logger.error(f"Error analyzing packet for DDoS: {e}")
    
    def get_statistics(self) -> Dict:
        """
        Get detector statistics.
        
        Returns:
            Dictionary with statistics
        """
        current_time = time.time()
        self._clean_old_packets(current_time)
        
        ip_stats = {}
        for ip, packets in self.packet_history.items():
            if packets:
                packets_in_window = self._get_packets_in_window(ip, current_time)
                if packets_in_window:
                    first_time = packets_in_window[0][0]
                    time_span = current_time - first_time
                    packet_rate = len(packets_in_window) / time_span if time_span > 0 else 0
                    ip_stats[ip] = {
                        "packet_count": len(packets_in_window),
                        "packet_rate_pps": packet_rate
                    }
        
        dynamic_threshold = self._get_dynamic_threshold()
        
        return {
            "monitored_ips": len(self.packet_history),
            "ip_statistics": ip_stats,
            "enabled": self.enabled,
            "baseline_calculated": self.baseline_calculated,
            "baseline_pps": self.baseline_pps,
            "dynamic_threshold_pps": dynamic_threshold if dynamic_threshold != float('inf') else None,
            "static_threshold_pps": self.packet_threshold / self.time_window
        }
