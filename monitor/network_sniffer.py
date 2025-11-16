"""
Network packet sniffer using Scapy.
Captures network packets in real-time for attack detection.
"""

import threading
import time
from collections import defaultdict, Counter
from typing import Callable, Optional, Dict, List
import logging

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available. Network monitoring will be disabled.")

from utils.helper import load_config


logger = logging.getLogger(__name__)


class NetworkSniffer:
    """
    Real-time network packet sniffer.
    Captures packets and provides callbacks for packet analysis.
    """
    
    def __init__(self, packet_callback: Callable, interface: Optional[str] = None):
        """
        Initialize network sniffer.
        
        Args:
            packet_callback: Function to call when packet is captured
            interface: Network interface to sniff on (None = auto-detect)
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for network monitoring. Install with: pip install scapy")
        
        self.packet_callback = packet_callback
        self.interface = interface
        self.running = False
        self.sniffer_thread = None
        self.packet_count = 0
        self.start_time = None
        
        # Packet statistics by protocol and source
        self.packet_stats = defaultdict(lambda: {"count": 0, "last_seen": 0})
        self.protocol_stats = defaultdict(int)
        
        # Load configuration
        try:
            config = load_config()
            if interface is None:
                self.interface = config.get("network", {}).get("interface")
        except Exception as e:
            logger.warning(f"Could not load config: {e}")
    
    def _packet_handler(self, packet):
        """
        Handle captured packet.
        
        Args:
            packet: Scapy packet object
        """
        try:
            self.packet_count += 1
            
            # Log every 100 packets to show sniffer is working
            if self.packet_count % 100 == 0:
                # Show packet statistics
                protocol_summary = ", ".join([f"{proto}:{count}" for proto, count in sorted(self.protocol_stats.items())])
                logger.info(f"[SNIFFER] Captured {self.packet_count} packets so far... Protocols: {protocol_summary}")
                
                # Show top 5 source IPs every 500 packets
                if self.packet_count % 500 == 0:
                    top_ips = sorted(
                        self.packet_stats.items(),
                        key=lambda x: x[1]["count"],
                        reverse=True
                    )[:5]
                    if top_ips:
                        ip_summary = ", ".join([f"{ip}({stats['count']})" for ip, stats in top_ips])
                        logger.info(f"[SNIFFER] Top source IPs: {ip_summary}")
            
            # Extract packet information
            packet_info = self._extract_packet_info(packet)
            
            if packet_info:
                protocol = packet_info.get("protocol", 0)
                src_ip = packet_info.get("src_ip", "unknown")
                
                # Track protocol statistics
                protocol_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol, f"PROTO-{protocol}")
                self.protocol_stats[protocol_name] += 1
                
                # Track packet statistics by source IP
                self.packet_stats[src_ip]["count"] += 1
                self.packet_stats[src_ip]["last_seen"] = time.time()
                
                # Ensure ICMP packets have size set (they might not have Raw layer)
                if protocol == 1 and packet_info.get("size", 0) == 0:
                    # ICMP packets are typically 64 bytes (including IP header)
                    packet_info["size"] = len(packet) if hasattr(packet, '__len__') else 64
                
                # Log ICMP packets immediately (ALWAYS, not just every 100)
                if protocol == 1:
                    icmp_type = packet_info.get("icmp_type", "unknown")
                    dst_ip = packet_info.get("dst_ip", "unknown")
                    logger.info(f"[ICMP] Packet captured: type={icmp_type}, from={src_ip} -> {dst_ip}")
                
                # Call the callback with packet information
                self.packet_callback(packet_info)
            else:
                # Log if packet extraction failed
                if self.packet_count % 500 == 0:
                    logger.debug(f"Packet #{self.packet_count} extraction returned None")
        
        except Exception as e:
            logger.error(f"Error processing packet: {e}", exc_info=True)
    
    def _extract_packet_info(self, packet) -> Optional[Dict]:
        """
        Extract relevant information from packet.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Dictionary with packet information or None
        """
        try:
            # Check if packet has IP layer
            if not packet.haslayer(IP):
                return None
            
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.proto
            
            packet_info = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "timestamp": time.time(),
                "size": len(packet)
            }
            
            # Extract port information if TCP/UDP
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_info["src_port"] = tcp_layer.sport
                packet_info["dst_port"] = tcp_layer.dport
                packet_info["flags"] = tcp_layer.flags
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_info["src_port"] = udp_layer.sport
                packet_info["dst_port"] = udp_layer.dport
            
            # Extract ICMP information
            if packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                packet_info["icmp_type"] = icmp_layer.type
            
            # Extract raw payload for industrial protocol analysis
            if packet.haslayer(Raw):
                raw_layer = packet[Raw]
                packet_info["raw_data"] = bytes(raw_layer.load)
            else:
                packet_info["raw_data"] = None
            
            return packet_info
        
        except Exception as e:
            logger.debug(f"Error extracting packet info: {e}")
            return None
    
    def _sniff_loop(self):
        """
        Main sniffing loop running in separate thread.
        """
        try:
            logger.info(f"Starting packet capture on interface: {self.interface or 'default'}")
            logger.info("Capturing ALL packets including ICMP...")
            logger.info("[WAITING] Waiting for packets... (send pings from another machine to test)")
            
            # Start sniffing - capture ALL packets including ICMP
            # Remove filter to capture everything, then filter in code
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                stop_filter=lambda x: not self.running,
                store=False,  # Don't store packets in memory
                filter=None  # Capture ALL packets (no filter)
            )
        
        except Exception as e:
            logger.error(f"[ERROR] Error in sniffing loop: {e}")
            logger.error("[ERROR] Make sure you're running as Administrator!")
            logger.error("[ERROR] On Windows: Install Npcap from https://npcap.com/")
            logger.error("[ERROR] On Linux: Run with 'sudo' and install libpcap-dev")
            import traceback
            logger.error(traceback.format_exc())
            self.running = False
    
    def start(self):
        """Start the network sniffer in a separate thread."""
        if self.running:
            logger.warning("Sniffer is already running")
            return
        
        self.running = True
        self.start_time = time.time()
        self.sniffer_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniffer_thread.start()
        logger.info("Network sniffer started")
    
    def stop(self):
        """Stop the network sniffer."""
        if not self.running:
            return
        
        self.running = False
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=5)
        
        elapsed = time.time() - self.start_time if self.start_time else 0
        logger.info(f"Network sniffer stopped. Captured {self.packet_count} packets in {elapsed:.2f} seconds")
    
    def get_statistics(self) -> Dict:
        """
        Get sniffer statistics.
        
        Returns:
            Dictionary with statistics
        """
        elapsed = time.time() - self.start_time if self.start_time else 0
        
        # Get top 10 source IPs by packet count
        top_ips = sorted(
            self.packet_stats.items(),
            key=lambda x: x[1]["count"],
            reverse=True
        )[:10]
        
        top_ips_dict = {ip: stats for ip, stats in top_ips}
        
        return {
            "packet_count": self.packet_count,
            "elapsed_time": elapsed,
            "packets_per_second": self.packet_count / elapsed if elapsed > 0 else 0,
            "running": self.running,
            "protocol_stats": dict(self.protocol_stats),
            "top_source_ips": top_ips_dict
        }
    
    @staticmethod
    def list_interfaces() -> List[str]:
        """
        List available network interfaces.
        
        Returns:
            List of interface names
        """
        if not SCAPY_AVAILABLE:
            return []
        
        try:
            return get_if_list()
        except Exception as e:
            logger.error(f"Error listing interfaces: {e}")
            return []

