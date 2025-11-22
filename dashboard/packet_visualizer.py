"""
Real-Time Packet Visualization Module.
Captures packets and provides data for live visualization.
"""

import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import logging

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available. Real-time visualization will be disabled.")

logger = logging.getLogger(__name__)


class PacketVisualizer:
    """
    Real-time packet capture and visualization data provider.
    Captures packets and maintains statistics for visualization.
    """
    
    def __init__(self, interface: Optional[str] = None, max_history: int = 300):
        """
        Initialize packet visualizer.
        
        Args:
            interface: Network interface to capture on (None = auto-detect)
            max_history: Maximum number of data points to keep in history
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for packet visualization.")
        
        self.interface = interface
        self.max_history = max_history
        self.running = False
        self.capture_thread = None
        
        # Real-time data structures
        self.pps_history = deque(maxlen=max_history)  # [(timestamp, pps), ...]
        self.packet_times = deque(maxlen=1000)  # Recent packet timestamps for PPS calculation
        
        # Network heatmap data: (src_ip, dst_ip) -> packet_count
        self.heatmap_data = defaultdict(int)
        self.heatmap_timestamps = deque(maxlen=max_history)
        
        # Top talkers: ip -> {packets, bytes, last_seen}
        self.top_talkers = defaultdict(lambda: {"packets": 0, "bytes": 0, "last_seen": None})
        
        # Protocol breakdown
        self.protocol_counts = defaultdict(int)
        
        # Time window for calculations (seconds)
        self.time_window = 1.0
        self.last_cleanup = time.time()
        
        # Statistics
        self.total_packets = 0
        self.start_time = None
        
        # Packet details for display (like terminal output)
        self.packet_log = deque(maxlen=500)  # Store last 500 packets with details
        
    def _packet_handler(self, packet):
        """Handle captured packet."""
        try:
            current_time = time.time()
            self.total_packets += 1
            
            # Add to packet times for PPS calculation
            self.packet_times.append(current_time)
            
            # Extract packet information
            packet_info = {
                "timestamp": datetime.now(),
                "src_ip": None,
                "dst_ip": None,
                "protocol": "Unknown",
                "src_port": None,
                "dst_port": None,
                "length": len(packet),
                "flags": None,
                "summary": str(packet.summary())
            }
            
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                packet_info["src_ip"] = src_ip
                packet_info["dst_ip"] = dst_ip
                
                # Update heatmap
                self.heatmap_data[(src_ip, dst_ip)] += 1
                
                # Update top talkers (source IP)
                if src_ip not in self.top_talkers:
                    self.top_talkers[src_ip]["last_seen"] = current_time
                self.top_talkers[src_ip]["packets"] += 1
                self.top_talkers[src_ip]["bytes"] += len(packet)
                self.top_talkers[src_ip]["last_seen"] = current_time
                
                # Protocol detection
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    packet_info["protocol"] = "TCP"
                    packet_info["src_port"] = tcp_layer.sport
                    packet_info["dst_port"] = tcp_layer.dport
                    packet_info["flags"] = tcp_layer.flags
                    self.protocol_counts["TCP"] += 1
                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    packet_info["protocol"] = "UDP"
                    packet_info["src_port"] = udp_layer.sport
                    packet_info["dst_port"] = udp_layer.dport
                    self.protocol_counts["UDP"] += 1
                elif packet.haslayer(ICMP):
                    packet_info["protocol"] = "ICMP"
                    self.protocol_counts["ICMP"] += 1
                else:
                    self.protocol_counts["Other"] += 1
                    packet_info["protocol"] = "Other"
            
            # Store packet info for display
            self.packet_log.append(packet_info)
            
            # Calculate PPS periodically (every 10 packets or every second)
            if len(self.packet_times) % 10 == 0 or len(self.pps_history) == 0:
                # Calculate PPS over last time window
                window_start = current_time - self.time_window
                recent_packets = [t for t in self.packet_times if t >= window_start]
                
                if len(recent_packets) > 0:
                    time_span = max(current_time - recent_packets[0], 0.1)  # Minimum 0.1s
                    pps = len(recent_packets) / time_span
                    self.pps_history.append((datetime.now(), pps))
            
            # Cleanup old data periodically
            if current_time - self.last_cleanup > 5.0:
                self._cleanup_old_data(current_time)
                self.last_cleanup = current_time
                
        except Exception as e:
            logger.debug(f"Error processing packet: {e}")
    
    def _cleanup_old_data(self, current_time: float):
        """Clean up old data to prevent memory issues."""
        # Clean old top talkers (not seen in last 5 minutes)
        cutoff_time = current_time - 300
        to_remove = [
            ip for ip, data in self.top_talkers.items()
            if data["last_seen"] and data["last_seen"] < cutoff_time
        ]
        for ip in to_remove:
            del self.top_talkers[ip]
        
        # Limit heatmap data size
        if len(self.heatmap_data) > 1000:
            # Keep only top 500 connections
            sorted_heatmap = sorted(
                self.heatmap_data.items(),
                key=lambda x: x[1],
                reverse=True
            )[:500]
            self.heatmap_data = defaultdict(int, sorted_heatmap)
    
    def _capture_loop(self):
        """Main packet capture loop running in separate thread."""
        try:
            logger.info(f"Starting real-time packet capture on interface: {self.interface or 'default'}")
            self.start_time = time.time()
            
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                stop_filter=lambda x: not self.running,
                store=False,
                filter=None  # Capture all packets
            )
        except Exception as e:
            logger.error(f"Error in packet capture loop: {e}")
            self.running = False
    
    def start(self):
        """Start packet capture."""
        if self.running:
            logger.warning("Packet visualizer is already running")
            return
        
        self.running = True
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
        logger.info("Packet visualizer started")
    
    def stop(self):
        """Stop packet capture."""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        logger.info("Packet visualizer stopped")
    
    def get_pps_data(self, minutes: int = 5) -> List[Dict]:
        """
        Get PPS (Packets Per Second) data for visualization.
        
        Args:
            minutes: Number of minutes of history to return
            
        Returns:
            List of dicts with 'timestamp' and 'pps' keys
        """
        if not self.pps_history:
            return []
        
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        data = [
            {"timestamp": ts, "pps": pps}
            for ts, pps in self.pps_history
            if ts >= cutoff_time
        ]
        return data
    
    def get_current_pps(self) -> float:
        """Get current PPS value."""
        if not self.packet_times:
            return 0.0
        
        current_time = time.time()
        window_start = current_time - self.time_window
        recent_packets = [t for t in self.packet_times if t >= window_start]
        
        if len(recent_packets) == 0:
            return 0.0
        
        time_span = current_time - recent_packets[0]
        if time_span <= 0:
            return 0.0
        
        return len(recent_packets) / time_span
    
    def get_network_heatmap(self, top_n: int = 50) -> List[Dict]:
        """
        Get network heatmap data (source-destination IP pairs).
        
        Args:
            top_n: Number of top connections to return
            
        Returns:
            List of dicts with 'source', 'destination', 'packets' keys
        """
        if not self.heatmap_data:
            return []
        
        sorted_connections = sorted(
            self.heatmap_data.items(),
            key=lambda x: x[1],
            reverse=True
        )[:top_n]
        
        return [
            {
                "source": src,
                "destination": dst,
                "packets": count
            }
            for (src, dst), count in sorted_connections
        ]
    
    def get_top_talkers(self, top_n: int = 20) -> List[Dict]:
        """
        Get top talkers (IPs with most traffic).
        
        Args:
            top_n: Number of top talkers to return
            
        Returns:
            List of dicts with 'ip', 'packets', 'bytes', 'pps' keys
        """
        if not self.top_talkers:
            return []
        
        # Calculate PPS for each IP (simplified - using recent packets)
        current_time = time.time()
        window_start = current_time - self.time_window
        
        # For now, use packet count as proxy for activity
        sorted_talkers = sorted(
            self.top_talkers.items(),
            key=lambda x: x[1]["packets"],
            reverse=True
        )[:top_n]
        
        result = []
        for ip, data in sorted_talkers:
            result.append({
                "ip": ip,
                "packets": data["packets"],
                "bytes": data["bytes"],
                "last_seen": data["last_seen"],
                "pps_estimate": data["packets"] / max(1, (current_time - (data["last_seen"] or current_time)))
            })
        
        return result
    
    def get_protocol_breakdown(self) -> Dict[str, int]:
        """Get protocol breakdown statistics."""
        return dict(self.protocol_counts)
    
    def get_statistics(self) -> Dict:
        """Get overall statistics."""
        uptime = time.time() - (self.start_time or time.time())
        current_pps = self.get_current_pps()
        
        return {
            "total_packets": self.total_packets,
            "current_pps": current_pps,
            "uptime_seconds": uptime,
            "unique_ips": len(self.top_talkers),
            "unique_connections": len(self.heatmap_data),
            "protocols": dict(self.protocol_counts)
        }
    
    def get_packet_log(self, limit: int = 100) -> List[Dict]:
        """
        Get recent packet log for display (like terminal output).
        
        Args:
            limit: Maximum number of packets to return
            
        Returns:
            List of packet info dicts
        """
        return list(self.packet_log)[-limit:]
    
    def reset(self):
        """Reset all statistics."""
        self.pps_history.clear()
        self.packet_times.clear()
        self.heatmap_data.clear()
        self.top_talkers.clear()
        self.protocol_counts.clear()
        self.packet_log.clear()
        self.total_packets = 0
        self.start_time = None

