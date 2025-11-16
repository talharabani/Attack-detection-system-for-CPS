"""
Modbus TCP/IP Attack Detector.
Specifically detects Modbus protocol attacks and command injection.
"""

import struct
import time
from collections import defaultdict, deque
from typing import Dict, Callable, Optional
import logging

from utils.helper import load_config, is_valid_ip


logger = logging.getLogger(__name__)


class ModbusDetector:
    """
    Detects Modbus-specific attacks including command injection and unauthorized access.
    """
    
    # Valid Modbus function codes
    VALID_FUNCTION_CODES = {
        1: "Read Coils",
        2: "Read Discrete Inputs",
        3: "Read Holding Registers",
        4: "Read Input Registers",
        5: "Write Single Coil",
        6: "Write Single Register",
        15: "Write Multiple Coils",
        16: "Write Multiple Registers",
        17: "Report Server ID",
        20: "Read File Record",
        21: "Write File Record",
        22: "Mask Write Register",
        23: "Read/Write Multiple Registers",
        24: "Read FIFO Queue",
        43: "Encapsulated Interface Transport"
    }
    
    # Dangerous write function codes
    WRITE_FUNCTIONS = [5, 6, 15, 16, 21, 22, 23]
    
    def __init__(self, alert_callback: Callable):
        """
        Initialize Modbus detector.
        
        Args:
            alert_callback: Function to call when attack is detected
        """
        self.alert_callback = alert_callback
        self.enabled = True
        
        # Track Modbus commands per IP
        self.modbus_commands = defaultdict(lambda: deque(maxlen=1000))
        
        # Track write operations (more dangerous)
        self.write_operations = defaultdict(int)
        
        # Track invalid function codes
        self.invalid_commands = defaultdict(int)
        
        # Load configuration
        try:
            config = load_config()
            modbus_config = config.get("detection", {}).get("modbus", {})
            self.enabled = modbus_config.get("enabled", True)
            self.write_threshold = modbus_config.get("write_threshold", 5)
            self.allowed_ips = set(modbus_config.get("allowed_ips", []))
            self.plc_addresses = set(modbus_config.get("plc_addresses", []))
        except Exception as e:
            logger.warning(f"Could not load config: {e}")
            self.write_threshold = 5
            self.allowed_ips = set()
            self.plc_addresses = set()
        
        logger.info("Modbus detector initialized")
    
    def parse_modbus_packet(self, packet_info: Dict) -> Optional[Dict]:
        """
        Parse Modbus TCP/IP packet.
        
        Args:
            packet_info: Dictionary containing packet information with raw_data
            
        Returns:
            Parsed Modbus information or None
        """
        # Check if this is Modbus port
        dst_port = packet_info.get("dst_port")
        if dst_port != 502:  # Modbus TCP port
            return None
        
        raw_data = packet_info.get("raw_data")
        if not raw_data or len(raw_data) < 8:
            return None
        
        try:
            # Parse Modbus TCP header
            transaction_id = struct.unpack('>H', raw_data[0:2])[0]
            protocol_id = struct.unpack('>H', raw_data[2:4])[0]
            length = struct.unpack('>H', raw_data[4:6])[0]
            unit_id = raw_data[6]
            function_code = raw_data[7]
            
            # Validate protocol ID (should be 0 for Modbus)
            if protocol_id != 0:
                return None
            
            function_name = self.VALID_FUNCTION_CODES.get(function_code, f"Unknown ({function_code})")
            is_write = function_code in self.WRITE_FUNCTIONS
            is_read = function_code in [1, 2, 3, 4]
            
            # Extract address if available
            address = None
            value = None
            if len(raw_data) >= 10:
                address = struct.unpack('>H', raw_data[8:10])[0]
                if len(raw_data) >= 12 and is_write:
                    value = struct.unpack('>H', raw_data[10:12])[0]
            
            return {
                "protocol": "modbus",
                "transaction_id": transaction_id,
                "unit_id": unit_id,
                "function_code": function_code,
                "function_name": function_name,
                "is_write": is_write,
                "is_read": is_read,
                "address": address,
                "value": value,
                "src_ip": packet_info.get("src_ip"),
                "dst_ip": packet_info.get("dst_ip"),
                "src_port": packet_info.get("src_port"),
                "dst_port": dst_port,
                "timestamp": time.time(),
                "raw_data": raw_data
            }
        
        except Exception as e:
            logger.debug(f"Error parsing Modbus packet: {e}")
            return None
    
    def _detect_command_injection(self, modbus_info: Dict) -> bool:
        """
        Detect Modbus command injection attacks.
        
        Args:
            modbus_info: Parsed Modbus information
            
        Returns:
            True if command injection detected
        """
        function_code = modbus_info.get("function_code")
        
        # Check for invalid function codes
        if function_code not in self.VALID_FUNCTION_CODES:
            self.invalid_commands[modbus_info.get("src_ip")] += 1
            return True
        
        # Check for malformed packets
        raw_data = modbus_info.get("raw_data", b"")
        if len(raw_data) < 8:
            return True
        
        return False
    
    def _detect_unauthorized_write(self, modbus_info: Dict) -> bool:
        """
        Detect unauthorized write operations.
        
        Args:
            modbus_info: Parsed Modbus information
            
        Returns:
            True if unauthorized write detected
        """
        if not modbus_info.get("is_write"):
            return False
        
        src_ip = modbus_info.get("src_ip")
        
        # Check if IP is allowed
        if self.allowed_ips and src_ip not in self.allowed_ips:
            self.write_operations[src_ip] += 1
            
            if self.write_operations[src_ip] >= self.write_threshold:
                return True
        
        return False
    
    def analyze_packet(self, packet_info: Dict):
        """
        Analyze packet for Modbus attacks.
        
        Args:
            packet_info: Dictionary containing packet information
        """
        if not self.enabled:
            return
        
        try:
            # Parse Modbus packet
            modbus_info = self.parse_modbus_packet(packet_info)
            
            if not modbus_info:
                return
            
            src_ip = modbus_info.get("src_ip")
            
            # Store command
            self.modbus_commands[src_ip].append(modbus_info)
            
            # Detect attacks
            attack_detected = False
            attack_type = None
            attack_details = {}
            
            # 1. Command injection
            if self._detect_command_injection(modbus_info):
                attack_detected = True
                attack_type = "Modbus Command Injection"
                attack_details = {
                    "function_code": modbus_info.get("function_code"),
                    "invalid_commands": self.invalid_commands[src_ip]
                }
            
            # 2. Unauthorized write
            elif self._detect_unauthorized_write(modbus_info):
                attack_detected = True
                attack_type = "Unauthorized Modbus Write"
                attack_details = {
                    "write_count": self.write_operations[src_ip],
                    "function_code": modbus_info.get("function_code"),
                    "address": modbus_info.get("address")
                }
            
            if attack_detected:
                attack_info = {
                    "attack_type": "CPS Attack",
                    "attack_subtype": attack_type,
                    "src_ip": src_ip,
                    "protocol": "modbus",
                    "timestamp": time.time(),
                    "severity": "CRITICAL",
                    "details": attack_details,
                    "modbus_info": {
                        "function_code": modbus_info.get("function_code"),
                        "function_name": modbus_info.get("function_name"),
                        "unit_id": modbus_info.get("unit_id"),
                        "address": modbus_info.get("address")
                    }
                }
                
                logger.warning(
                    f"Modbus attack detected: {attack_type} from {src_ip} "
                    f"(Function: {modbus_info.get('function_name')})"
                )
                
                self.alert_callback(attack_info)
        
        except Exception as e:
            logger.error(f"Error analyzing Modbus packet: {e}")

