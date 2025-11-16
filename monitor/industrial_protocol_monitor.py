"""
Industrial Protocol Monitor for CPS Attack Detection.
Monitors Modbus, DNP3, IEC 61850, OPC-UA, and BACnet protocols.
"""

import struct
import time
from typing import Dict, Optional, Callable, List
import logging

try:
    from scapy.all import IP, TCP, UDP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from utils.helper import load_config


logger = logging.getLogger(__name__)


class IndustrialProtocolMonitor:
    """
    Monitors and parses industrial control system protocols.
    Detects protocol-specific traffic and extracts command information.
    """
    
    # Protocol port mappings
    PROTOCOL_PORTS = {
        "modbus": [502],  # Modbus TCP
        "dnp3": [20000],  # DNP3
        "iec61850": [102],  # IEC 61850 MMS
        "opcua": [4840, 4841],  # OPC-UA
        "bacnet": [47808],  # BACnet/IP
    }
    
    def __init__(self, protocol_callback: Callable):
        """
        Initialize industrial protocol monitor.
        
        Args:
            protocol_callback: Function to call when protocol traffic is detected
        """
        self.protocol_callback = protocol_callback
        
        # Load configuration
        try:
            config = load_config()
            cps_config = config.get("detection", {}).get("cps", {})
            self.enabled_protocols = cps_config.get("enabled_protocols", ["modbus", "dnp3", "opcua"])
        except Exception as e:
            logger.warning(f"Could not load config: {e}")
            self.enabled_protocols = ["modbus", "dnp3", "opcua"]
        
        logger.info(f"Industrial protocol monitor initialized for: {', '.join(self.enabled_protocols)}")
    
    def _is_industrial_protocol_port(self, port: int) -> Optional[str]:
        """
        Check if port is used by industrial protocols.
        
        Args:
            port: Port number
            
        Returns:
            Protocol name if found, None otherwise
        """
        for protocol, ports in self.PROTOCOL_PORTS.items():
            if protocol in self.enabled_protocols and port in ports:
                return protocol
        return None
    
    def _parse_modbus(self, data: bytes, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> Optional[Dict]:
        """
        Parse Modbus TCP/IP protocol.
        
        Args:
            data: Packet payload
            src_ip: Source IP
            dst_ip: Destination IP
            src_port: Source port
            dst_port: Destination port
            
        Returns:
            Dictionary with parsed Modbus information or None
        """
        if len(data) < 8:  # Modbus TCP header is 6 bytes + function code
            return None
        
        try:
            # Modbus TCP header: Transaction ID (2), Protocol ID (2), Length (2), Unit ID (1), Function Code (1)
            if len(data) >= 8:
                transaction_id = struct.unpack('>H', data[0:2])[0]
                protocol_id = struct.unpack('>H', data[2:4])[0]
                length = struct.unpack('>H', data[4:6])[0]
                unit_id = data[6]
                function_code = data[7]
                
                # Modbus function codes
                function_names = {
                    1: "Read Coils",
                    2: "Read Discrete Inputs",
                    3: "Read Holding Registers",
                    4: "Read Input Registers",
                    5: "Write Single Coil",
                    6: "Write Single Register",
                    15: "Write Multiple Coils",
                    16: "Write Multiple Registers"
                }
                
                function_name = function_names.get(function_code, f"Unknown ({function_code})")
                
                # Determine if this is a read or write operation
                is_write = function_code in [5, 6, 15, 16]
                is_read = function_code in [1, 2, 3, 4]
                
                # Extract address if available
                address = None
                if len(data) >= 10:
                    address = struct.unpack('>H', data[8:10])[0]
                
                return {
                    "protocol": "modbus",
                    "transaction_id": transaction_id,
                    "unit_id": unit_id,
                    "function_code": function_code,
                    "function_name": function_name,
                    "is_write": is_write,
                    "is_read": is_read,
                    "address": address,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "timestamp": time.time(),
                    "data_length": len(data)
                }
        except Exception as e:
            logger.debug(f"Error parsing Modbus: {e}")
            return None
    
    def _parse_dnp3(self, data: bytes, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> Optional[Dict]:
        """
        Parse DNP3 protocol.
        
        Args:
            data: Packet payload
            src_ip: Source IP
            dst_ip: Destination IP
            src_port: Source port
            dst_port: Destination port
            
        Returns:
            Dictionary with parsed DNP3 information or None
        """
        if len(data) < 10:  # DNP3 header minimum
            return None
        
        try:
            # DNP3 header structure
            start1, start2 = data[0], data[1]
            if start1 != 0x05 or start2 != 0x64:
                return None  # Not DNP3
            
            length = data[2]
            control = data[3]
            destination = struct.unpack('>H', data[4:6])[0]
            source = struct.unpack('>H', data[6:8])[0]
            
            # Determine if this is a command
            is_command = (control & 0x0F) in [0x0C, 0x0D]  # Direct Operate, Select and Operate
            
            return {
                "protocol": "dnp3",
                "control": control,
                "destination": destination,
                "source": source,
                "is_command": is_command,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "timestamp": time.time(),
                "data_length": len(data)
            }
        except Exception as e:
            logger.debug(f"Error parsing DNP3: {e}")
            return None
    
    def _parse_opcua(self, data: bytes, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> Optional[Dict]:
        """
        Parse OPC-UA protocol (simplified).
        
        Args:
            data: Packet payload
            src_ip: Source IP
            dst_ip: Destination IP
            src_port: Source port
            dst_port: Destination port
            
        Returns:
            Dictionary with parsed OPC-UA information or None
        """
        if len(data) < 8:
            return None
        
        try:
            # OPC-UA uses binary encoding, simplified detection
            # Look for common OPC-UA message types
            message_type = data[0:3] if len(data) >= 3 else b''
            
            # Check for OPC-UA SecureChannel or Session messages
            is_opcua = False
            message_kind = "Unknown"
            
            # Simplified detection based on structure
            if len(data) > 8:
                # OPC-UA messages often start with message type indicators
                if b'HEL' in data[:10] or b'ACK' in data[:10] or b'ERR' in data[:10]:
                    is_opcua = True
                    message_kind = "Handshake"
                elif len(data) > 20:  # Likely OPC-UA data message
                    is_opcua = True
                    message_kind = "Data"
            
            if is_opcua:
                return {
                    "protocol": "opcua",
                    "message_kind": message_kind,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "timestamp": time.time(),
                    "data_length": len(data)
                }
        except Exception as e:
            logger.debug(f"Error parsing OPC-UA: {e}")
            return None
    
    def analyze_packet(self, packet_info: Dict) -> Optional[Dict]:
        """
        Analyze packet for industrial protocol traffic.
        
        Args:
            packet_info: Dictionary containing packet information
            
        Returns:
            Parsed protocol information or None
        """
        try:
            protocol = packet_info.get("protocol", 0)
            src_port = packet_info.get("src_port")
            dst_port = packet_info.get("dst_port")
            src_ip = packet_info.get("src_ip")
            dst_ip = packet_info.get("dst_ip")
            
            # Check if this is TCP or UDP
            if protocol not in [6, 17]:  # Not TCP or UDP
                return None
            
            # Determine which port indicates the protocol
            protocol_name = None
            if dst_port:
                protocol_name = self._is_industrial_protocol_port(dst_port)
            if not protocol_name and src_port:
                protocol_name = self._is_industrial_protocol_port(src_port)
            
            if not protocol_name:
                return None
            
            # For now, we need the raw packet data
            # In a real implementation, you'd extract this from Scapy packet
            # For this system, we'll return protocol detection info
            # The actual parsing would happen in the detector with full packet access
            
            return {
                "protocol": protocol_name,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "detected_port": dst_port or src_port,
                "timestamp": time.time()
            }
        
        except Exception as e:
            logger.debug(f"Error analyzing packet for industrial protocol: {e}")
            return None
    
    def parse_protocol_data(self, protocol: str, data: bytes, src_ip: str, dst_ip: str, 
                           src_port: int, dst_port: int) -> Optional[Dict]:
        """
        Parse protocol-specific data.
        
        Args:
            protocol: Protocol name
            data: Raw packet data
            src_ip: Source IP
            dst_ip: Destination IP
            src_port: Source port
            dst_port: Destination port
            
        Returns:
            Parsed protocol information or None
        """
        if protocol == "modbus":
            return self._parse_modbus(data, src_ip, dst_ip, src_port, dst_port)
        elif protocol == "dnp3":
            return self._parse_dnp3(data, src_ip, dst_ip, src_port, dst_port)
        elif protocol == "opcua":
            return self._parse_opcua(data, src_ip, dst_ip, src_port, dst_port)
        
        return None

