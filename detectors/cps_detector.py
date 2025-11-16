"""
Cyber-Physical System (CPS) Attack Detector.
Detects attacks on industrial control systems and SCADA networks.
"""

import time
from collections import defaultdict, deque
from typing import Dict, Callable, List, Optional
import logging

from utils.helper import load_config, is_valid_ip
from monitor.industrial_protocol_monitor import IndustrialProtocolMonitor


logger = logging.getLogger(__name__)


class CPSDetector:
    """
    Detects attacks on Cyber-Physical Systems and industrial control systems.
    Monitors Modbus, DNP3, OPC-UA, and other industrial protocols.
    """
    
    def __init__(self, alert_callback: Callable):
        """
        Initialize CPS detector.
        
        Args:
            alert_callback: Function to call when attack is detected
        """
        self.alert_callback = alert_callback
        self.enabled = True
        
        # Protocol monitor
        self.protocol_monitor = IndustrialProtocolMonitor(self._handle_protocol_traffic)
        
        # Track protocol traffic per IP
        self.protocol_traffic = defaultdict(lambda: {
            "modbus": deque(maxlen=1000),
            "dnp3": deque(maxlen=1000),
            "opcua": deque(maxlen=1000),
            "iec61850": deque(maxlen=1000),
            "bacnet": deque(maxlen=1000)
        })
        
        # Track command history for replay detection
        self.command_history = defaultdict(lambda: deque(maxlen=100))
        
        # Track unauthorized access attempts
        self.unauthorized_access = defaultdict(int)
        
        # Track timing patterns for anomaly detection
        self.timing_patterns = defaultdict(lambda: deque(maxlen=50))
        
        # Load configuration
        try:
            config = load_config()
            cps_config = config.get("detection", {}).get("cps", {})
            self.enabled = cps_config.get("enabled", True)
            self.unauthorized_threshold = cps_config.get("unauthorized_threshold", 3)
            self.replay_window = cps_config.get("replay_window_seconds", 60)
            self.timing_anomaly_threshold = cps_config.get("timing_anomaly_threshold", 2.0)
            self.allowed_ips = set(cps_config.get("allowed_ips", []))
            self.plc_addresses = set(cps_config.get("plc_addresses", []))
        except Exception as e:
            logger.warning(f"Could not load config: {e}")
            self.unauthorized_threshold = 3
            self.replay_window = 60
            self.timing_anomaly_threshold = 2.0
            self.allowed_ips = set()
            self.plc_addresses = set()
        
        logger.info("CPS detector initialized for industrial protocol monitoring")
    
    def _handle_protocol_traffic(self, protocol_info: Dict):
        """
        Handle detected industrial protocol traffic.
        
        Args:
            protocol_info: Dictionary with protocol information
        """
        self.analyze_protocol_traffic(protocol_info)
    
    def _detect_unauthorized_plc_access(self, protocol_info: Dict) -> bool:
        """
        Detect unauthorized access to PLCs.
        
        Args:
            protocol_info: Protocol traffic information
            
        Returns:
            True if unauthorized access detected
        """
        src_ip = protocol_info.get("src_ip")
        dst_ip = protocol_info.get("dst_ip")
        
        # Check if destination is a known PLC
        if self.plc_addresses and dst_ip not in self.plc_addresses:
            # Not a known PLC, but might be legitimate discovery
            return False
        
        # Check if source IP is in allowed list
        if self.allowed_ips and src_ip not in self.allowed_ips:
            self.unauthorized_access[src_ip] += 1
            
            if self.unauthorized_access[src_ip] >= self.unauthorized_threshold:
                return True
        
        return False
    
    def _detect_command_replay(self, protocol_info: Dict) -> bool:
        """
        Detect command replay attacks.
        
        Args:
            protocol_info: Protocol traffic information
            
        Returns:
            True if replay attack detected
        """
        # Create command signature
        command_sig = self._create_command_signature(protocol_info)
        
        if not command_sig:
            return False
        
        src_ip = protocol_info.get("src_ip")
        current_time = time.time()
        
        # Check if similar command was sent recently
        for cmd_time, sig in self.command_history[src_ip]:
            if sig == command_sig:
                time_diff = current_time - cmd_time
                if 0 < time_diff < self.replay_window:
                    # Same command repeated within replay window
                    return True
        
        # Add to history
        self.command_history[src_ip].append((current_time, command_sig))
        
        return False
    
    def _create_command_signature(self, protocol_info: Dict) -> Optional[str]:
        """
        Create a signature for a command to detect replays.
        
        Args:
            protocol_info: Protocol traffic information
            
        Returns:
            Command signature string or None
        """
        protocol = protocol_info.get("protocol")
        
        if protocol == "modbus":
            return f"modbus_{protocol_info.get('unit_id')}_{protocol_info.get('function_code')}_{protocol_info.get('address')}"
        elif protocol == "dnp3":
            return f"dnp3_{protocol_info.get('source')}_{protocol_info.get('destination')}_{protocol_info.get('control')}"
        
        return None
    
    def _detect_timing_anomaly(self, protocol_info: Dict) -> bool:
        """
        Detect timing anomalies in control system communications.
        
        Args:
            protocol_info: Protocol traffic information
            
        Returns:
            True if timing anomaly detected
        """
        src_ip = protocol_info.get("src_ip")
        current_time = time.time()
        
        # Track timing between commands
        if self.timing_patterns[src_ip]:
            last_time = self.timing_patterns[src_ip][-1]
            time_diff = current_time - last_time
            
            # Calculate average timing
            if len(self.timing_patterns[src_ip]) > 1:
                timings = [self.timing_patterns[src_ip][i+1] - self.timing_patterns[src_ip][i] 
                          for i in range(len(self.timing_patterns[src_ip]) - 1)]
                avg_timing = sum(timings) / len(timings) if timings else 0
                
                # Check if current timing is significantly different
                if avg_timing > 0:
                    ratio = abs(time_diff - avg_timing) / avg_timing
                    if ratio > self.timing_anomaly_threshold:
                        return True
        
        self.timing_patterns[src_ip].append(current_time)
        
        return False
    
    def _detect_protocol_violation(self, protocol_info: Dict) -> bool:
        """
        Detect protocol violations.
        
        Args:
            protocol_info: Protocol traffic information
            
        Returns:
            True if protocol violation detected
        """
        protocol = protocol_info.get("protocol")
        
        if protocol == "modbus":
            function_code = protocol_info.get("function_code")
            # Check for invalid function codes
            valid_codes = [1, 2, 3, 4, 5, 6, 15, 16, 17, 20, 21, 22, 23, 24, 43]
            if function_code and function_code not in valid_codes:
                return True
        
        # Add more protocol-specific checks here
        
        return False
    
    def _detect_unusual_read_write_pattern(self, protocol_info: Dict) -> bool:
        """
        Detect unusual read/write patterns.
        
        Args:
            protocol_info: Protocol traffic information
            
        Returns:
            True if unusual pattern detected
        """
        protocol = protocol_info.get("protocol")
        src_ip = protocol_info.get("src_ip")
        
        if protocol == "modbus":
            is_write = protocol_info.get("is_write", False)
            is_read = protocol_info.get("is_read", False)
            
            # Track write operations
            if is_write:
                write_count = sum(1 for pkt in self.protocol_traffic[src_ip]["modbus"] 
                                if pkt.get("is_write"))
                
                # Alert if too many write operations
                if write_count > 10:  # Threshold for write operations
                    return True
        
        return False
    
    def analyze_protocol_traffic(self, protocol_info: Dict):
        """
        Analyze industrial protocol traffic for attacks.
        
        Args:
            protocol_info: Dictionary containing protocol traffic information
        """
        if not self.enabled:
            return
        
        try:
            protocol = protocol_info.get("protocol")
            src_ip = protocol_info.get("src_ip")
            
            if not protocol or not src_ip:
                return
            
            # Store protocol traffic
            if protocol in self.protocol_traffic[src_ip]:
                self.protocol_traffic[src_ip][protocol].append(protocol_info)
            
            # Detect various attack types
            attack_detected = False
            attack_type = None
            attack_details = {}
            
            # 1. Unauthorized PLC access
            if self._detect_unauthorized_plc_access(protocol_info):
                attack_detected = True
                attack_type = "Unauthorized PLC Access"
                attack_details = {
                    "src_ip": src_ip,
                    "protocol": protocol,
                    "unauthorized_attempts": self.unauthorized_access[src_ip]
                }
            
            # 2. Command replay attack
            elif self._detect_command_replay(protocol_info):
                attack_detected = True
                attack_type = "Command Replay Attack"
                attack_details = {
                    "src_ip": src_ip,
                    "protocol": protocol,
                    "command_signature": self._create_command_signature(protocol_info)
                }
            
            # 3. Protocol violation
            elif self._detect_protocol_violation(protocol_info):
                attack_detected = True
                attack_type = "Protocol Violation"
                attack_details = {
                    "src_ip": src_ip,
                    "protocol": protocol,
                    "violation_type": "Invalid function code or structure"
                }
            
            # 4. Unusual read/write pattern
            elif self._detect_unusual_read_write_pattern(protocol_info):
                attack_detected = True
                attack_type = "Unusual Read/Write Pattern"
                attack_details = {
                    "src_ip": src_ip,
                    "protocol": protocol,
                    "pattern": "Excessive write operations"
                }
            
            # 5. Timing anomaly
            elif self._detect_timing_anomaly(protocol_info):
                attack_detected = True
                attack_type = "Timing Anomaly"
                attack_details = {
                    "src_ip": src_ip,
                    "protocol": protocol,
                    "anomaly_type": "Unusual command timing"
                }
            
            if attack_detected:
                attack_info = {
                    "attack_type": "CPS Attack",
                    "attack_subtype": attack_type,
                    "src_ip": src_ip,
                    "protocol": protocol,
                    "timestamp": time.time(),
                    "severity": "HIGH",
                    "details": attack_details
                }
                
                logger.warning(
                    f"CPS attack detected: {attack_type} from {src_ip} "
                    f"using {protocol} protocol"
                )
                
                self.alert_callback(attack_info)
        
        except Exception as e:
            logger.error(f"Error analyzing CPS protocol traffic: {e}")
    
    def analyze_packet(self, packet_info: Dict):
        """
        Analyze network packet for CPS protocol traffic.
        
        Args:
            packet_info: Dictionary containing packet information
        """
        # Use protocol monitor to detect industrial protocols
        protocol_info = self.protocol_monitor.analyze_packet(packet_info)
        
        if protocol_info:
            self.analyze_protocol_traffic(protocol_info)
    
    def get_statistics(self) -> Dict:
        """
        Get detector statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            "enabled": self.enabled,
            "monitored_protocols": list(self.protocol_monitor.enabled_protocols),
            "tracked_ips": len(self.protocol_traffic),
            "unauthorized_attempts": dict(self.unauthorized_access)
        }

