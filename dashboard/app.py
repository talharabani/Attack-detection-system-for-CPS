"""
Real-Time Web Dashboard for Attack Detection System.
Modern, eye-catching UI with glassmorphism design and smooth animations.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import time
import json
import os
import re
import hashlib
from pathlib import Path
import sys
import psutil
import html

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from utils.helper import load_config
from utils.attack_logger import AttackLogger

# Import PDF report generator
try:
    from utils.pdf_report_generator import PDFReportGenerator
    PDF_REPORT_AVAILABLE = True
except ImportError:
    PDFReportGenerator = None
    PDF_REPORT_AVAILABLE = False

# Import export utilities
try:
    from dashboard.export_utils import export_to_csv, export_to_json, export_to_elasticsearch_format, export_to_grafana_format
except ImportError:
    # Fallback if export_utils not found
    def export_to_csv(attacks): return ""
    def export_to_json(attacks): return "[]"
    def export_to_elasticsearch_format(attacks): return []
    def export_to_grafana_format(attacks): return []

# Import packet visualizer
try:
    from dashboard.packet_visualizer import PacketVisualizer, SCAPY_AVAILABLE
except ImportError:
    SCAPY_AVAILABLE = False
    PacketVisualizer = None

# Page configuration
st.set_page_config(
    page_title="🛡️ RealTime Attack Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Beautiful Modern CSS with Warm Earthy Color Scheme
st.markdown("""
<style>
    /* Import Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');
    
    /* Color Palette - Dark Theme */
    :root {
        --bg-primary: #121212;
        --bg-secondary: #1a1a1a;
        --text-primary: #E0E0E0;
        --text-secondary: #B0B0B0;
        --border-color: #444444;
        --accent-color: #888888;
        --color-primary: #888888;
        --color-secondary: #444444;
        --color-text: #E0E0E0;
        --color-text-light: #B0B0B0;
    }
    
    /* Global Styles */
    * {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    /* Main App Background - Dark Theme */
    .stApp {
        background: #121212;
        color: var(--text-primary);
        min-height: 100vh;
    }
    
    @keyframes gradientShift {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }
    
    /* Hide Streamlit default elements */
    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
    header { visibility: hidden; }
    
    /* Modern Header - Dark Theme */
    .main-header {
        font-size: 3.5rem;
        font-weight: 900;
        color: var(--text-primary);
        text-align: center;
        padding: 2rem 1rem;
        margin-bottom: 2rem;
        text-shadow: 0 0 20px rgba(136, 136, 136, 0.3);
        animation: pulse 2s ease-in-out infinite;
        letter-spacing: -0.02em;
    }
    
    @keyframes pulse {
        0%, 100% { transform: scale(1); }
        50% { transform: scale(1.02); }
    }
    
    /* Glassmorphism Cards - Dark Theme */
    .glass-card {
        background: rgba(26, 26, 26, 0.9);
        backdrop-filter: blur(20px);
        -webkit-backdrop-filter: blur(20px);
        border: 1px solid var(--border-color);
        border-radius: 20px;
        padding: 2rem;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.5);
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        color: var(--text-primary);
    }
    
    .glass-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 12px 48px 0 rgba(0, 0, 0, 0.7);
        border-color: var(--accent-color);
    }
    
    /* Attack Card Styling - Dark Theme */
    .attack-card {
        background: rgba(26, 26, 26, 0.95);
        backdrop-filter: blur(20px);
        border: 1px solid var(--border-color);
        border-left: 6px solid;
        border-radius: 16px;
        padding: 1.5rem;
        margin: 1rem 0;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
        transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        position: relative;
        overflow: hidden;
        color: var(--text-primary);
    }
    
    .attack-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 3px;
        background: linear-gradient(90deg, transparent, currentColor, transparent);
        opacity: 0;
        transition: opacity 0.3s;
    }
    
    .attack-card:hover {
        transform: translateX(8px) translateY(-4px);
        box-shadow: 0 16px 48px rgba(212, 163, 115, 0.35);
        border-left-width: 8px;
    }
    
    .attack-card:hover::before {
        opacity: 1;
    }
    
    /* Metric Cards - Dark Theme */
    .metric-card {
        background: rgba(26, 26, 26, 0.9);
        backdrop-filter: blur(20px);
        border: 1px solid var(--border-color);
        border-radius: 16px;
        padding: 1.5rem;
        text-align: center;
        transition: all 0.3s ease;
        position: relative;
        overflow: hidden;
        color: var(--text-primary);
    }
    
    .metric-card::before {
        content: '';
        position: absolute;
        top: -50%;
        left: -50%;
        width: 200%;
        height: 200%;
        background: radial-gradient(circle, rgba(136, 136, 136, 0.1) 0%, transparent 70%);
        opacity: 0;
        transition: opacity 0.3s;
    }
    
    .metric-card:hover {
        transform: scale(1.05);
        border-color: var(--accent-color);
    }
    
    .metric-card:hover::before {
        opacity: 1;
    }
    
    .metric-value {
        font-size: 2.5rem;
        font-weight: 800;
        color: var(--text-primary);
        margin: 0.5rem 0;
    }
    
    .metric-label {
        font-size: 0.9rem;
        color: var(--text-secondary);
        text-transform: uppercase;
        letter-spacing: 0.1em;
        font-weight: 600;
    }
    
    /* Buttons - Dark Theme */
    .stButton > button {
        background: var(--accent-color);
        color: var(--text-primary);
        border: 1px solid var(--border-color);
        border-radius: 12px;
        padding: 0.75rem 2rem;
        font-weight: 600;
        font-size: 1rem;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
        width: 100%;
        position: relative;
        overflow: hidden;
    }
    
    .stButton > button::before {
        content: '';
        position: absolute;
        top: 50%;
        left: 50%;
        width: 0;
        height: 0;
        border-radius: 50%;
        background: rgba(255, 255, 255, 0.1);
        transform: translate(-50%, -50%);
        transition: width 0.6s, height 0.6s;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 30px rgba(0, 0, 0, 0.7);
        background: #999999;
        border-color: var(--accent-color);
    }
    
    .stButton > button:hover::before {
        width: 300px;
        height: 300px;
    }
    
    /* Sidebar - Dark Theme */
    [data-testid="stSidebar"] {
        background: rgba(26, 26, 26, 0.95);
        backdrop-filter: blur(20px);
        border-right: 1px solid var(--border-color);
    }
    
    /* Selectbox and Input - Dark Styling */
    .stSelectbox > div > div {
        background: rgba(26, 26, 26, 0.9);
        border: 1px solid var(--border-color);
        border-radius: 12px;
        color: var(--text-primary);
    }
    
    .stTextInput > div > div > input {
        background: rgba(26, 26, 26, 0.9);
        border: 1px solid var(--border-color);
        border-radius: 12px;
        color: var(--text-primary);
    }
    
    /* Progress Bars - Dark Theme */
    .stProgress > div > div > div {
        background: var(--accent-color);
        border-radius: 10px;
    }
    
    /* Severity Badges - Beautiful Color Coding */
    .severity-badge {
        display: inline-block;
        padding: 0.4rem 1rem;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        color: white;
    }
    
    .severity-critical {
        background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
        animation: glow 2s ease-in-out infinite;
    }
    
    .severity-high {
        background: linear-gradient(135deg, #e67e22 0%, #d35400 100%);
    }
    
    .severity-medium {
        background: linear-gradient(135deg, #888888 0%, #666666 100%);
    }
    
    .severity-low {
        background: linear-gradient(135deg, #666666 0%, #555555 100%);
        color: var(--text-primary);
    }
    
    @keyframes glow {
        0%, 100% { box-shadow: 0 4px 15px rgba(231, 76, 60, 0.5); }
        50% { box-shadow: 0 4px 25px rgba(231, 76, 60, 0.8); }
    }
    
    /* Real-time Indicator - Warm Green */
    .live-indicator {
        display: inline-block;
        width: 12px;
        height: 12px;
        background: #27ae60;
        border-radius: 50%;
        margin-right: 8px;
        animation: pulse-dot 2s ease-in-out infinite;
        box-shadow: 0 0 10px rgba(39, 174, 96, 0.8);
    }
    
    @keyframes pulse-dot {
        0%, 100% { transform: scale(1); opacity: 1; }
        50% { transform: scale(1.2); opacity: 0.7; }
    }
    
    /* Section Headers - Beautiful Typography */
    h1, h2, h3 {
        color: var(--color-text);
        font-weight: 700;
        letter-spacing: -0.02em;
    }
    
    h2 {
        font-size: 1.8rem;
        margin-bottom: 1.5rem;
        color: var(--text-primary);
    }
    
    /* Scrollbar - Dark Design */
    ::-webkit-scrollbar {
        width: 10px;
    }
    
    ::-webkit-scrollbar-track {
        background: rgba(26, 26, 26, 0.8);
        border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb {
        background: var(--accent-color);
        border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: #999999;
    }
    
    /* Notification Banner - Dark Theme */
    .notification-banner {
        background: rgba(26, 26, 26, 0.9);
        border: 1px solid var(--border-color);
        border-radius: 12px;
        padding: 1rem;
        margin: 1rem 0;
        animation: slideIn 0.5s ease-out;
        color: var(--text-primary);
    }
    
    @keyframes slideIn {
        from {
            transform: translateY(-20px);
            opacity: 0;
        }
        to {
            transform: translateY(0);
            opacity: 1;
        }
    }
    
    /* Info Boxes - Dark Theme */
    .stInfo {
        background: rgba(26, 26, 26, 0.9);
        border-left: 4px solid var(--accent-color);
        border-radius: 8px;
        color: var(--text-primary);
    }
    
    .stSuccess {
        background: rgba(26, 26, 26, 0.9);
        border-left: 4px solid #27ae60;
        border-radius: 8px;
        color: var(--text-primary);
    }
    
    .stError {
        background: rgba(26, 26, 26, 0.9);
        border-left: 4px solid #e74c3c;
        border-radius: 8px;
        color: var(--text-primary);
    }
    
    .stWarning {
        background: rgba(26, 26, 26, 0.9);
        border-left: 4px solid var(--accent-color);
        border-radius: 8px;
        color: var(--text-primary);
    }
    
    /* Chart Containers - Dark Background */
    .js-plotly-plot {
        background: rgba(26, 26, 26, 0.8);
        border-radius: 16px;
        padding: 1rem;
        border: 1px solid var(--border-color);
    }
    
    /* Text Colors for Better Readability */
    p, span, div, label {
        color: var(--text-primary);
    }
    
    /* Markdown Text */
    .stMarkdown {
        color: var(--text-primary);
    }
    
    /* Dataframe Styling */
    .dataframe {
        background: rgba(26, 26, 26, 0.9);
        border: 1px solid var(--border-color);
        color: var(--text-primary);
    }
    
    /* Packet Log Terminal Style */
    .packet-log {
        background: #1e1e1e;
        color: #d4d4d4;
        font-family: 'Courier New', monospace;
        font-size: 0.85rem;
        padding: 1rem;
        border-radius: 8px;
        max-height: 500px;
        overflow-y: auto;
        border: 1px solid var(--border-color);
    }
    
    .packet-entry {
        padding: 0.3rem 0;
        border-bottom: 1px solid var(--border-color);
    }
    
    .packet-entry:hover {
        background: rgba(136, 136, 136, 0.1);
    }
    
    .packet-time {
        color: var(--accent-color);
    }
    
    .packet-protocol {
        color: var(--text-primary);
        font-weight: bold;
    }
    
    .packet-ip {
        color: var(--text-secondary);
    }
    
    /* Responsive Design */
    @media (max-width: 768px) {
        .main-header {
            font-size: 2rem;
        }
        .metric-value {
            font-size: 2rem;
        }
    }
</style>
""", unsafe_allow_html=True)


class DashboardData:
    """Manages dashboard data and metrics."""
    
    def __init__(self):
        self.attack_history = []
        self.blocked_ips = set()
        self.last_attack_count = 0
        # Initialize attack logger to read from database
        try:
            self.attack_logger = AttackLogger()
        except Exception as e:
            st.error(f"Error initializing attack logger: {e}")
            self.attack_logger = None
        self.load_attack_history()
        self.load_blocked_ips()
        self.last_attack_count = len(self.attack_history)
    
    
    def load_attack_history(self):
        """Load attack history from attack database."""
        try:
            if not self.attack_logger:
                return
            
            # Get all attacks from database
            db_attacks = self.attack_logger.get_all_attacks()
            
            # Convert database format to dashboard format
            self.attack_history = []
            for attack in db_attacks:
                # Parse timestamp
                try:
                    if isinstance(attack.get("timestamp"), str):
                        timestamp = datetime.fromisoformat(attack["timestamp"])
                    else:
                        timestamp = datetime.now()
                except:
                    timestamp = datetime.now()
                
                # Get details
                details = attack.get("details", {})
                
                # Build attack entry
                attack_entry = {
                    "timestamp": timestamp,
                    "attack_type": attack.get("attack_type", "Unknown Attack"),
                    "attack_subtype": details.get("attack_subtype", ""),
                    "src_ip": attack.get("src_ip", "Unknown"),
                    "severity": attack.get("severity", "MEDIUM"),
                    "packet_count": details.get("packet_count"),
                    "packet_rate": details.get("packet_rate"),
                    "packet_rate_pps": details.get("packet_rate"),
                    "protocol": details.get("protocol", "Unknown"),
                    "shodan_data": details.get("shodan_data")
                }
                
                self.attack_history.append(attack_entry)
            
            # Sort by timestamp (newest first)
            self.attack_history.sort(key=lambda x: x["timestamp"], reverse=True)
            
            # Limit to 1000 most recent
            if len(self.attack_history) > 1000:
                self.attack_history = self.attack_history[:1000]
        
        except Exception as e:
            st.error(f"Error loading attack history: {e}")
    
    def load_blocked_ips(self):
        """Load blocked IPs from active defense."""
        try:
            # Blocked IPs are tracked separately or can be inferred from attack patterns
            # For now, we'll track IPs that have multiple high-severity attacks
            for attack in self.attack_history:
                if attack.get("severity") in ["CRITICAL", "HIGH"]:
                    src_ip = attack.get("src_ip")
                    if src_ip and src_ip != "Unknown":
                        # Count attacks from this IP
                        ip_attack_count = sum(1 for a in self.attack_history 
                                            if a.get("src_ip") == src_ip and 
                                            a.get("severity") in ["CRITICAL", "HIGH"])
                        if ip_attack_count >= 3:  # Block IPs with 3+ high severity attacks
                            self.blocked_ips.add(src_ip)
        except Exception as e:
            pass
    
    def get_recent_attacks(self, limit=4):
        """Get recent attacks."""
        return self.attack_history[-limit:] if self.attack_history else []
    
    def get_all_attacks(self):
        """Get all attacks."""
        return self.attack_history
    
    def get_attack_stats(self):
        """Get attack statistics."""
        if not self.attack_history:
            return {
                "total_attacks": 0,
                "today_attacks": 0,
                "high_severity": 0,
                "critical_severity": 0,
                "blocked_ips": len(self.blocked_ips),
                "attack_types": {}
            }
        
        today = datetime.now().date()
        today_attacks = sum(1 for a in self.attack_history if a["timestamp"].date() == today)
        high_severity = sum(1 for a in self.attack_history if a["severity"] == "HIGH")
        critical_severity = sum(1 for a in self.attack_history if a["severity"] == "CRITICAL")
        
        attack_types = {}
        for attack in self.attack_history:
            atype = attack.get("attack_type", "Unknown")
            attack_types[atype] = attack_types.get(atype, 0) + 1
        
        return {
            "total_attacks": len(self.attack_history),
            "today_attacks": today_attacks,
            "high_severity": high_severity,
            "critical_severity": critical_severity,
            "blocked_ips": len(self.blocked_ips),
            "attack_types": attack_types
        }
    
    def get_traffic_data(self, minutes=30):
        """Get traffic data for visualization."""
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=minutes)
        
        traffic_points = []
        current_time = start_time
        
        while current_time <= end_time:
            base_packets = 50
            attacks_in_minute = sum(1 for a in self.attack_history
                                  if start_time <= a["timestamp"] <= current_time)
            packets = base_packets + (attacks_in_minute * 100)
            
            traffic_points.append({
                "Time": current_time,
                "Packets/sec": packets,
                "Attacks": attacks_in_minute
            })
            
            current_time += timedelta(minutes=1)
        
        return traffic_points
    
    def get_pps_data(self, minutes=30):
        """Get PPS (Packets Per Second) data for real-time graph."""
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=minutes)
        
        # Group attacks by time window (every 10 seconds)
        pps_data = []
        current_time = start_time
        
        while current_time <= end_time:
            window_end = current_time + timedelta(seconds=10)
            
            # Get attacks in this window
            attacks_in_window = [
                a for a in self.attack_history
                if current_time <= a["timestamp"] <= window_end
            ]
            
            # Calculate total PPS from attacks
            total_pps = sum(
                a.get("packet_rate_pps", a.get("packet_rate", 0))
                for a in attacks_in_window
                if isinstance(a.get("packet_rate_pps", a.get("packet_rate", 0)), (int, float))
            )
            
            # Add base traffic
            base_pps = 50
            total_pps = max(total_pps, base_pps)
            
            pps_data.append({
                "Time": current_time,
                "PPS": total_pps,
                "Attack Count": len(attacks_in_window)
            })
            
            current_time = window_end
        
        return pps_data
    
    def get_per_ip_traffic(self, minutes=30):
        """Get per-IP traffic data."""
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=minutes)
        
        # Get attacks in time window
        recent_attacks = [
            a for a in self.attack_history
            if start_time <= a["timestamp"] <= end_time
        ]
        
        # Group by IP
        ip_traffic = {}
        for attack in recent_attacks:
            ip = attack.get("src_ip", "Unknown")
            if ip not in ip_traffic:
                ip_traffic[ip] = {
                    "packet_count": 0,
                    "packet_rate": 0,
                    "attack_count": 0,
                    "last_seen": attack["timestamp"]
                }
            
            ip_traffic[ip]["packet_count"] += attack.get("packet_count", 0) or 0
            ip_traffic[ip]["packet_rate"] += attack.get("packet_rate_pps", attack.get("packet_rate", 0)) or 0
            ip_traffic[ip]["attack_count"] += 1
            if attack["timestamp"] > ip_traffic[ip]["last_seen"]:
                ip_traffic[ip]["last_seen"] = attack["timestamp"]
        
        # Convert to list for display
        return [
            {
                "IP": ip,
                "Total Packets": data["packet_count"],
                "Avg PPS": data["packet_rate"] / max(data["attack_count"], 1),
                "Attack Count": data["attack_count"],
                "Last Seen": data["last_seen"]
            }
            for ip, data in sorted(ip_traffic.items(), key=lambda x: x[1]["packet_count"], reverse=True)
        ]
    
    def get_protocol_breakdown(self):
        """Get protocol breakdown statistics."""
        protocol_counts = {}
        protocol_packets = {}
        
        for attack in self.attack_history:
            protocol = attack.get("protocol", "Unknown")
            packet_count = attack.get("packet_count", 0) or 0
            
            if protocol not in protocol_counts:
                protocol_counts[protocol] = 0
                protocol_packets[protocol] = 0
            
            protocol_counts[protocol] += 1
            protocol_packets[protocol] += packet_count
        
        return {
            "counts": protocol_counts,
            "packets": protocol_packets
        }
    
    def get_attacker_profile(self, ip: str) -> Dict:
        """Get comprehensive attacker profile for an IP."""
        # Get all attacks from this IP
        ip_attacks = [a for a in self.attack_history if a.get("src_ip") == ip]
        
        if not ip_attacks:
            return None
        
        # Get Shodan data from most recent attack
        shodan_data = None
        for attack in reversed(ip_attacks):
            if attack.get("shodan_data"):
                shodan_data = attack.get("shodan_data")
                break
        
        # Calculate statistics
        total_attacks = len(ip_attacks)
        attack_types = {}
        severities = {}
        total_packets = 0
        max_pps = 0
        first_seen = min(a["timestamp"] for a in ip_attacks)
        last_seen = max(a["timestamp"] for a in ip_attacks)
        
        for attack in ip_attacks:
            atype = attack.get("attack_type", "Unknown")
            severity = attack.get("severity", "MEDIUM")
            packet_count = attack.get("packet_count", 0) or 0
            pps = attack.get("packet_rate_pps", attack.get("packet_rate", 0)) or 0
            
            attack_types[atype] = attack_types.get(atype, 0) + 1
            severities[severity] = severities.get(severity, 0) + 1
            total_packets += packet_count
            max_pps = max(max_pps, pps)
        
        # Extract Shodan info
        ip_info = shodan_data.get("ip_info", {}) if shodan_data else {}
        location = ip_info.get("location", {}) if ip_info else {}
        
        # Determine why flagged
        why_flagged = []
        if total_attacks > 5:
            why_flagged.append(f"Multiple attacks ({total_attacks} total)")
        if max_pps > 500:
            why_flagged.append(f"High packet rate ({max_pps:.0f} PPS)")
        if "CRITICAL" in severities or "HIGH" in severities:
            why_flagged.append("High severity attacks detected")
        if ip_info.get("vulnerabilities"):
            why_flagged.append(f"Known vulnerabilities ({len(ip_info.get('vulnerabilities', []))} CVEs)")
        if shodan_data and shodan_data.get("threat_level") in ["HIGH", "CRITICAL"]:
            why_flagged.append(f"Shodan threat level: {shodan_data.get('threat_level')}")
        
        return {
            "ip": ip,
            "total_attacks": total_attacks,
            "attack_types": attack_types,
            "severities": severities,
            "total_packets": total_packets,
            "max_pps": max_pps,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "shodan_data": shodan_data,
            "country": location.get("country", "Unknown") if location else "Unknown",
            "city": location.get("city", "Unknown") if location else "Unknown",
            "isp": ip_info.get("isp", "Unknown") if ip_info else "Unknown",
            "organization": ip_info.get("org", "Unknown") if ip_info else "Unknown",
            "asn": ip_info.get("asn", "Unknown") if ip_info else "Unknown",
            "open_ports": ip_info.get("open_ports", []) if ip_info else [],
            "vulnerabilities": ip_info.get("vulnerabilities", []) if ip_info else [],
            "honeypot_score": shodan_data.get("honeypot", {}).get("honeypot_score") if shodan_data and shodan_data.get("honeypot") else None,
            "threat_level": shodan_data.get("threat_level", "UNKNOWN") if shodan_data else "UNKNOWN",
            "why_flagged": why_flagged,
            "reputation_score": self._calculate_reputation_score(ip_attacks, shodan_data)
        }
    
    def _calculate_reputation_score(self, attacks: List[Dict], shodan_data: Optional[Dict]) -> int:
        """Calculate reputation score (0-100, lower is worse)."""
        score = 100
        
        # Deduct for number of attacks
        score -= min(len(attacks) * 5, 30)
        
        # Deduct for high severity
        for attack in attacks:
            severity = attack.get("severity", "LOW")
            if severity == "CRITICAL":
                score -= 20
            elif severity == "HIGH":
                score -= 10
            elif severity == "MEDIUM":
                score -= 5
        
        # Deduct for Shodan threat level
        if shodan_data:
            threat_level = shodan_data.get("threat_level", "UNKNOWN")
            if threat_level == "CRITICAL":
                score -= 25
            elif threat_level == "HIGH":
                score -= 15
            elif threat_level == "MEDIUM":
                score -= 10
            
            # Deduct for vulnerabilities
            vulns = shodan_data.get("ip_info", {}).get("vulnerabilities", [])
            score -= min(len(vulns) * 2, 15)
        
        return max(0, min(100, score))


# Initialize dashboard data
try:
    if 'dashboard_data' not in st.session_state:
        st.session_state.dashboard_data = DashboardData()
    
    dashboard_data = st.session_state.dashboard_data
except Exception as e:
    st.error(f"❌ **Failed to initialize dashboard data:** {str(e)}")
    st.exception(e)
    # Create a minimal dashboard_data to prevent further errors
    class MinimalDashboardData:
        def __init__(self):
            self.attack_history = []
            self.blocked_ips = set()
            self.last_attack_count = 0
        def load_attack_history(self): pass
        def load_blocked_ips(self): pass
        def get_all_attacks(self): return []
        def get_attack_stats(self):
            return {"total_attacks": 0, "today_attacks": 0, "high_severity": 0, 
                   "critical_severity": 0, "blocked_ips": 0, "attack_types": {}}
        def get_traffic_data(self, minutes=30): return []
        def get_pps_data(self, minutes=30): return []
        def get_per_ip_traffic(self, minutes=30): return []
        def get_protocol_breakdown(self): return {"counts": {}, "packets": {}}
        def get_attacker_profile(self, ip): return None
    
    dashboard_data = MinimalDashboardData()


def render_attack_card(attack, index=None):
    """Render a beautiful modern attack card using Streamlit components."""
    attack_type = attack.get("attack_type", "Unknown Attack")
    src_ip = attack.get("src_ip", "Unknown")
    severity = attack.get("severity", "MEDIUM")
    timestamp = attack["timestamp"]
    
    packet_count = attack.get("packet_count")
    packet_rate = attack.get("packet_rate", attack.get("packet_rate_pps"))
    protocol = attack.get("protocol", "Unknown")
    attack_subtype = attack.get("attack_subtype", "")
    shodan_data = attack.get("shodan_data")
    
    attack_type_names = {
        "DDoS/Flooding": "🌊 DDoS / Flooding Attack",
        "Ping Flood Attack": "📡 Ping Flood Attack",
        "Port Scanning": "🔍 Port Scanning Attack",
        "Brute Force Login": "🔐 Brute Force Login",
        "Intrusion Attempt": "🚨 Intrusion Attempt",
        "CPS Attack": "🏭 CPS Attack"
    }
    display_attack_type = attack_type_names.get(attack_type, f"⚠️ {attack_type}")
    
    if isinstance(packet_rate, (int, float)) and packet_rate != "N/A":
        if packet_rate < 1:
            packet_rate_str = f"{packet_rate:.2f} pkt/s"
        elif packet_rate < 100:
            packet_rate_str = f"{packet_rate:.1f} pkt/s"
        else:
            packet_rate_str = f"{int(packet_rate)} pkt/s"
    else:
        packet_rate_str = None
    
    if isinstance(packet_count, (int, float)) and packet_count is not None:
        packet_count_str = f"{int(packet_count):,}"
    else:
        packet_count_str = None
    
    severity_colors = {
        "CRITICAL": "#e74c3c",
        "HIGH": "#e67e22",
        "MEDIUM": "#888888",
        "LOW": "#B0B0B0"
    }
    severity_icons = {
        "CRITICAL": "🚨",
        "HIGH": "🔴",
        "MEDIUM": "🟠",
        "LOW": "🟡"
    }
    sev_color = severity_colors.get(severity, "#888888")
    sev_icon = severity_icons.get(severity, "⚪")
    
    time_ago = datetime.now() - timestamp
    if time_ago.total_seconds() < 60:
        time_str = f"{int(time_ago.total_seconds())}s ago"
    elif time_ago.total_seconds() < 3600:
        time_str = f"{int(time_ago.total_seconds() / 60)}m ago"
    else:
        time_str = f"{int(time_ago.total_seconds() / 3600)}h ago"
    
    # Escape HTML special characters in user data
    def escape_html(text):
        if text is None:
            return ""
        text = str(text)
        text = text.replace("&", "&amp;")
        text = text.replace("<", "&lt;")
        text = text.replace(">", "&gt;")
        text = text.replace('"', "&quot;")
        text = text.replace("'", "&#x27;")
        return text
    
    # Escape all user-provided data
    escaped_attack_type = escape_html(display_attack_type)
    escaped_subtype = escape_html(attack_subtype)
    escaped_src_ip = escape_html(src_ip)
    escaped_protocol = escape_html(protocol)
    escaped_packet_count = escape_html(packet_count_str) if packet_count_str else ""
    escaped_packet_rate = escape_html(packet_rate_str) if packet_rate_str else ""
    escaped_timestamp = escape_html(timestamp.strftime('%B %d, %Y at %I:%M:%S %p'))
    escaped_time_str = escape_html(time_str)
    
    # Build HTML with escaped values - using dark theme colors
    attack_subtype_html = f'<div style="color: #B0B0B0; font-size: 0.9rem; margin-bottom: 0.5rem;">{escaped_subtype}</div>' if attack_subtype else ''
    packet_count_html = f'<div><div style="color: #B0B0B0; font-size: 0.85rem; margin-bottom: 0.3rem;">Packets</div><div style="font-size: 1.1rem; font-weight: 600; color: #E0E0E0;">{escaped_packet_count}</div></div>' if packet_count_str else ''
    packet_rate_html = f'<div><div style="color: #B0B0B0; font-size: 0.85rem; margin-bottom: 0.3rem;">Rate</div><div style="font-size: 1.1rem; font-weight: 600; color: #E0E0E0;">{escaped_packet_rate}</div></div>' if packet_rate_str else ''
    
    # Build HTML content as a single string - use format() for better control
    html_template = """<div class="attack-card" style="border-left-color: {color};">
<div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem;">
<div>
<div style="font-size: 1.3rem; font-weight: 700; margin-bottom: 0.5rem; color: #E0E0E0;">{icon} {attack_type}</div>
{subtype}
<div style="color: #B0B0B0; font-size: 0.85rem;">{timestamp} • {time_ago}</div>
</div>
<span class="severity-badge severity-{severity_lower}" style="background: linear-gradient(135deg, {color} 0%, {color}dd 100%); padding: 0.4rem 1rem; border-radius: 20px; font-weight: 700; font-size: 0.85rem; text-transform: uppercase; color: white;">{severity}</span>
</div>
<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-top: 1.5rem;">
<div><div style="color: #B0B0B0; font-size: 0.85rem; margin-bottom: 0.3rem;">Source IP</div><div style="font-family: 'Courier New', monospace; font-size: 1.1rem; font-weight: 600; color: #888888;">{src_ip}</div></div>
<div><div style="color: #B0B0B0; font-size: 0.85rem; margin-bottom: 0.3rem;">Protocol</div><div style="font-size: 1.1rem; font-weight: 600; color: #E0E0E0;">{protocol}</div></div>
{packet_count}
{packet_rate}
</div>
</div>"""
    
    # Format the template
    html_content = html_template.format(
        color=sev_color,
        icon=sev_icon,
        attack_type=escaped_attack_type,
        subtype=attack_subtype_html,
        timestamp=escaped_timestamp,
        time_ago=escaped_time_str,
        severity_lower=severity.lower(),
        severity=severity,
        src_ip=escaped_src_ip,
        protocol=escaped_protocol,
        packet_count=packet_count_html,
        packet_rate=packet_rate_html
    )
    
    # Render the HTML
    st.markdown(html_content, unsafe_allow_html=True)
    
    # Display Shodan threat intelligence if available
    if shodan_data:
        ip_info = shodan_data.get("ip_info", {})
        threat_level = shodan_data.get("threat_level", "UNKNOWN")
        
        # Shodan section with expander
        with st.expander(f"🔍 Shodan Threat Intelligence - Threat Level: {threat_level}", expanded=False):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**📍 Location & Organization**")
                if ip_info.get("org") and ip_info.get("org") != "Unknown":
                    st.write(f"**Organization:** {ip_info.get('org')}")
                if ip_info.get("isp") and ip_info.get("isp") != "Unknown":
                    st.write(f"**ISP:** {ip_info.get('isp')}")
                location = ip_info.get("location", {})
                if location.get("country") and location.get("country") != "Unknown":
                    loc_str = location.get("country", "")
                    if location.get("city") and location.get("city") != "Unknown":
                        loc_str += f", {location.get('city')}"
                    st.write(f"**Location:** {loc_str}")
                if ip_info.get("hostnames"):
                    st.write(f"**Hostnames:** {', '.join(ip_info.get('hostnames', [])[:3])}")
            
            with col2:
                st.markdown("**🔌 Network Information**")
                open_ports = ip_info.get("open_ports", [])
                if open_ports:
                    ports_display = ", ".join(map(str, open_ports[:10]))
                    if len(open_ports) > 10:
                        ports_display += f" (+{len(open_ports) - 10} more)"
                    st.write(f"**Open Ports:** {ports_display}")
                    st.write(f"**Total Ports:** {len(open_ports)}")
                
                if ip_info.get("os") and ip_info.get("os") != "Unknown":
                    st.write(f"**OS:** {ip_info.get('os')}")
                if ip_info.get("device_type") and ip_info.get("device_type") != "Unknown":
                    st.write(f"**Device Type:** {ip_info.get('device_type')}")
            
            # Vulnerabilities
            vulnerabilities = ip_info.get("vulnerabilities", [])
            if vulnerabilities:
                st.markdown("**🚨 Vulnerabilities**")
                cves_display = ", ".join(vulnerabilities[:10])
                if len(vulnerabilities) > 10:
                    cves_display += f" (+{len(vulnerabilities) - 10} more)"
                st.warning(f"**{len(vulnerabilities)} CVEs Found:** {cves_display}")
            
            # Tags
            tags = ip_info.get("tags", [])
            if tags:
                st.markdown("**🏷️ Tags**")
                tags_display = " ".join([f"`{tag}`" for tag in tags[:10]])
                st.markdown(tags_display)
            
            # Honeypot Score
            honeypot = shodan_data.get("honeypot")
            if honeypot and honeypot.get("honeypot_score") is not None:
                score = honeypot.get("honeypot_score", 0)
                if score < 0.3:
                    st.success(f"**Honeypot Score:** {score:.2f} - Likely Real Threat")
                elif score < 0.7:
                    st.warning(f"**Honeypot Score:** {score:.2f} - Possible Honeypot")
                else:
                    st.info(f"**Honeypot Score:** {score:.2f} - Likely Honeypot")
            
            # Exploits
            exploits = shodan_data.get("exploits", [])
            if exploits:
                st.markdown(f"**💥 Available Exploits: {len(exploits)} found**")
                for i, exploit in enumerate(exploits[:5], 1):
                    exploit_id = exploit.get("id", "Unknown")
                    exploit_desc = exploit.get("description", "No description")[:100]
                    st.markdown(f"{i}. **{exploit_id}**: {exploit_desc}...")
                if len(exploits) > 5:
                    st.caption(f"... and {len(exploits) - 5} more exploits")
            
            # Services
            services = ip_info.get("services", [])
            if services:
                st.markdown("**🌐 Services**")
                for service in services[:5]:
                    port = service.get("port", "?")
                    product = service.get("product", "Unknown")
                    version = service.get("version", "")
                    st.caption(f"Port {port}: {product} {version}".strip())
                if len(services) > 5:
                    st.caption(f"... and {len(services) - 5} more services")


def check_password():
    """Check if user is authenticated."""
    # Check if password is set in config
    try:
        config = load_config()
        dashboard_config = config.get("dashboard", {})
        password = dashboard_config.get("password")
        
        # If no password is set, allow access (for first-time setup)
        if not password:
            return True
        
        # Check session state for authentication
        if "authenticated" in st.session_state and st.session_state.authenticated:
            return True
        
        # Show password input
        st.markdown("""
        <div style="text-align: center; padding: 4rem 2rem;">
            <h1>🔒 Dashboard Access</h1>
            <p style="color: var(--text-secondary);">Please enter the dashboard password to continue</p>
        </div>
        """, unsafe_allow_html=True)
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            entered_password = st.text_input("Password", type="password", key="password_input")
            if st.button("Login", use_container_width=True, key="login_btn"):
                if entered_password == password:
                    st.session_state.authenticated = True
                    st.rerun()
                else:
                    st.error("❌ Incorrect password")
        
        return False
    except Exception as e:
        # If config loading fails, allow access (fallback)
        return True


def main():
    """Main dashboard application."""
    
    # Check authentication
    if not check_password():
        return
    
    # Modern Header
    st.markdown(
        '<div class="main-header">🛡️ RealTime Attack Detection Dashboard</div>',
        unsafe_allow_html=True
    )
    
    # Live Indicator
    col_status, col_time = st.columns([1, 4])
    with col_status:
        st.markdown(
            '<div style="text-align: center;"><span class="live-indicator"></span><strong style="color: #27ae60;">LIVE</strong></div>',
            unsafe_allow_html=True
        )
    with col_time:
        st.markdown(
            f'<div style="text-align: right; color: #B0B0B0; font-size: 0.9rem;">{datetime.now().strftime("%B %d, %Y • %I:%M:%S %p")}</div>',
            unsafe_allow_html=True
        )
    
    # Navigation Tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📊 Dashboard", 
        "📈 Real-Time Graphs", 
        "👤 Attacker Profiles", 
        "💾 Export",
        "📡 Live Packet Visualization"
    ])
    
    # Sidebar
    with st.sidebar:
        st.markdown("### ⚙️ Settings")
        
        auto_refresh = st.checkbox("🔄 Auto Refresh", value=True, key="auto_refresh")
        refresh_interval = st.slider("⏱️ Refresh Interval (seconds)", 1, 10, 3, key="refresh_interval")
        
        if st.button("🔄 Refresh Now", use_container_width=True):
            dashboard_data.load_attack_history()
            dashboard_data.load_blocked_ips()
            dashboard_data.last_attack_count = len(dashboard_data.get_all_attacks())
            st.rerun()
        
        st.divider()
        st.markdown("### 📊 View Options")
        show_traffic = st.checkbox("🌐 Network Traffic", value=True, key="show_traffic")
        show_connections = st.checkbox("🔌 Active Connections", value=True, key="show_connections")
        show_attacks = st.checkbox("📈 Attack Timeline", value=True, key="show_attacks")
        show_metrics = st.checkbox("💻 System Metrics", value=True, key="show_metrics")
        show_attack_types = st.checkbox("🎯 Attack Types", value=True, key="show_attack_types")
        
        st.divider()
        st.markdown("### ℹ️ System Info")
        try:
            config = load_config()
            st.info(f"📄 Log: {config.get('general', {}).get('log_file', 'attack_detection.log')}")
        except:
            pass
    
    # Load fresh data (always reload to get latest attacks)
    dashboard_data.load_attack_history()
    dashboard_data.load_blocked_ips()
    stats = dashboard_data.get_attack_stats()
    
    # Check for new attacks and auto-refresh if enabled
    current_attack_count = len(dashboard_data.get_all_attacks())
    if current_attack_count > dashboard_data.last_attack_count:
        new_attacks = current_attack_count - dashboard_data.last_attack_count
        st.markdown(
            f'<div class="notification-banner">🆕 <strong>{new_attacks} new attack(s) detected!</strong> Dashboard updated automatically.</div>',
            unsafe_allow_html=True
        )
        dashboard_data.last_attack_count = current_attack_count
        # Auto-refresh if enabled to show new attacks immediately
        if auto_refresh:
            time.sleep(0.5)  # Small delay to ensure data is saved
            st.rerun()
    
    # TAB 1: Main Dashboard
    with tab1:
        render_main_dashboard(dashboard_data, stats, show_traffic, show_connections, show_attacks, show_metrics, show_attack_types)
    
    # TAB 2: Real-Time Graphs
    with tab2:
        render_realtime_graphs(dashboard_data)
    
    # TAB 3: Attacker Profiles
    with tab3:
        render_attacker_profiles(dashboard_data)
    
    # TAB 4: Export
    with tab4:
        render_export_section(dashboard_data)
    
    # TAB 5: Live Packet Visualization
    with tab5:
        render_live_packet_visualization()
    
    # Auto-refresh - only refresh if enabled and not blocking page load
    if auto_refresh:
        # Show refresh indicator
        st.caption(f"🔄 Auto-refresh enabled ({refresh_interval}s interval) - Use 'Refresh Now' button to update")
        # Don't auto-refresh automatically - let user control it
        # Auto-refresh can cause continuous reloading issues


def render_main_dashboard(dashboard_data, stats, show_traffic, show_connections, show_attacks, show_metrics, show_attack_types):
    """Render main dashboard tab."""
    # Modern Metrics Cards
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Total Attacks</div>
                <div class="metric-value">{stats["total_attacks"]}</div>
                <div style="color: #B0B0B0; font-size: 0.8rem;">+{stats["today_attacks"]} today</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    
    with col2:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Today</div>
                <div class="metric-value">{stats["today_attacks"]}</div>
                <div style="color: #B0B0B0; font-size: 0.8rem;">attacks</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    
    with col3:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Critical</div>
                <div class="metric-value" style="color: #e74c3c;">{stats["critical_severity"]}</div>
                <div style="color: #B0B0B0; font-size: 0.8rem;">severity</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    
    with col4:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">High Severity</div>
                <div class="metric-value" style="color: #e67e22;">{stats["high_severity"]}</div>
                <div style="color: #B0B0B0; font-size: 0.8rem;">attacks</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    
    with col5:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Blocked IPs</div>
                <div class="metric-value" style="color: #27ae60;">{stats["blocked_ips"]}</div>
                <div style="color: rgba(255,255,255,0.5); font-size: 0.8rem;">blocked</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Main Content
    col_left, col_right = st.columns([1.5, 1])
    
    with col_left:
        # Attack Timeline
        if show_attacks and dashboard_data.attack_history:
            st.markdown("### 📈 Attack Timeline")
            timeline_data = []
            for attack in dashboard_data.attack_history[-100:]:
                timeline_data.append({
                    "Time": attack["timestamp"],
                    "Attack Type": attack.get("attack_type", "Unknown"),
                    "Severity": attack.get("severity", "MEDIUM"),
                    "IP": attack.get("src_ip", "Unknown")
                })
            
            if timeline_data:
                df_timeline = pd.DataFrame(timeline_data)
                color_map = {"CRITICAL": "#e74c3c", "HIGH": "#e67e22", "MEDIUM": "#888888", "LOW": "#B0B0B0"}
                
                fig_timeline = go.Figure()
                for severity in df_timeline["Severity"].unique():
                    df_sev = df_timeline[df_timeline["Severity"] == severity]
                    fig_timeline.add_trace(go.Scatter(
                        x=df_sev["Time"],
                        y=[severity] * len(df_sev),
                        mode='markers',
                        name=severity,
                        marker=dict(size=15, color=color_map.get(severity, "#888888"), line=dict(width=2, color='#E0E0E0')),
                        hovertemplate='<b>%{text}</b><br>Time: %{x}<br>Severity: %{y}<extra></extra>',
                        text=[f"{row['Attack Type']} from {row['IP']}" for _, row in df_sev.iterrows()]
                    ))
                
                fig_timeline.update_layout(
                    title="",
                    xaxis_title="Time",
                    yaxis_title="Severity",
                    height=400,
                    plot_bgcolor='rgba(26, 26, 26, 0.9)',
                    paper_bgcolor='rgba(18, 18, 18, 0.9)',
                    font=dict(color='#E0E0E0', size=12),
                    legend=dict(bgcolor='rgba(26, 26, 26, 0.9)', bordercolor='#444444'),
                    margin=dict(l=0, r=0, t=0, b=0)
                )
                st.plotly_chart(fig_timeline, use_container_width=True)
        
        # Attack Types Chart
        if show_attack_types and stats["attack_types"]:
            st.markdown("### 🎯 Attack Types Distribution")
            attack_types_df = pd.DataFrame([
                {"Attack Type": k, "Count": v}
                for k, v in stats["attack_types"].items()
            ])
            
            fig_types = px.pie(
                attack_types_df,
                values="Count",
                names="Attack Type",
                hole=0.4,
                color_discrete_sequence=['#888888', '#B0B0B0', '#E0E0E0', '#444444', '#e67e22', '#e74c3c', '#27ae60']
            )
            fig_types.update_layout(
                plot_bgcolor='rgba(26, 26, 26, 0.9)',
                paper_bgcolor='rgba(18, 18, 18, 0.9)',
                font=dict(color='#E0E0E0', size=12),
                margin=dict(l=0, r=0, t=0, b=0),
                showlegend=True
            )
            st.plotly_chart(fig_types, use_container_width=True)
        
        # Network Traffic
        if show_traffic:
            st.markdown("### 🌐 Network Traffic")
            traffic_data = dashboard_data.get_traffic_data(30)
            if traffic_data:
                df_traffic = pd.DataFrame(traffic_data)
                fig_traffic = go.Figure()
                fig_traffic.add_trace(go.Scatter(
                    x=df_traffic["Time"],
                    y=df_traffic["Packets/sec"],
                    name="Packets/sec",
                    line=dict(color='#888888', width=3),
                    fill='tonexty',
                    fillcolor='rgba(136, 136, 136, 0.2)'
                ))
                
                attack_times = [t["Time"] for t in traffic_data if t["Attacks"] > 0]
                attack_packets = [t["Packets/sec"] for t in traffic_data if t["Attacks"] > 0]
                
                if attack_times:
                    fig_traffic.add_trace(go.Scatter(
                        x=attack_times,
                        y=attack_packets,
                        mode='markers',
                        name="Attacks",
                        marker=dict(size=18, color='#e74c3c', symbol='x', line=dict(width=2, color='#E0E0E0'))
                    ))
                
                fig_traffic.update_layout(
                    height=350,
                    plot_bgcolor='rgba(26, 26, 26, 0.9)',
                    paper_bgcolor='rgba(18, 18, 18, 0.9)',
                    font=dict(color='#E0E0E0', size=12),
                    legend=dict(bgcolor='rgba(26, 26, 26, 0.9)'),
                    margin=dict(l=0, r=0, t=0, b=0)
                )
                st.plotly_chart(fig_traffic, use_container_width=True)
    
    with col_right:
        st.markdown("### 🚨 Recent Attacks")
        
        # Filters
        col_filter1, col_filter2 = st.columns(2)
        with col_filter1:
            severity_filter = st.selectbox(
                "Severity",
                ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
                key="severity_filter"
            )
        with col_filter2:
            sort_order = st.selectbox(
                "Sort",
                ["Newest", "Oldest", "Severity"],
                key="sort_order"
            )
        
        # Get and filter attacks
        all_attacks = dashboard_data.get_all_attacks()
        
        if severity_filter != "All":
            all_attacks = [a for a in all_attacks if a.get("severity") == severity_filter]
        
        if sort_order == "Newest":
            all_attacks = sorted(all_attacks, key=lambda x: x["timestamp"], reverse=True)
        elif sort_order == "Oldest":
            all_attacks = sorted(all_attacks, key=lambda x: x["timestamp"])
        elif sort_order == "Severity":
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            all_attacks = sorted(all_attacks, key=lambda x: severity_order.get(x.get("severity", "LOW"), 4))
        
        recent_attacks = all_attacks[:5] if all_attacks else []
        
        if recent_attacks:
            st.markdown(
                f'<div style="color: #B0B0B0; margin-bottom: 1rem; font-size: 0.9rem;">📊 Showing {len(recent_attacks)} of {len(dashboard_data.get_all_attacks())} total</div>',
                unsafe_allow_html=True
            )
            
            for attack in recent_attacks:
                render_attack_card(attack)
            
            if len(all_attacks) > 5:
                if st.button("📋 View All Attacks", use_container_width=True, key="view_all_btn"):
                    st.session_state.show_all_attacks = not st.session_state.get("show_all_attacks", False)
                
                if st.session_state.get("show_all_attacks", False):
                    st.markdown("---")
                    search_term = st.text_input("🔍 Search", key="attack_search")
                    
                    if search_term:
                        filtered_attacks = [
                            a for a in all_attacks
                            if search_term.lower() in str(a.get("src_ip", "")).lower() or
                               search_term.lower() in str(a.get("attack_type", "")).lower()
                        ]
                    else:
                        filtered_attacks = all_attacks
                    
                    for attack in filtered_attacks:
                        render_attack_card(attack)
        else:
            st.info("✅ No attacks detected. System is secure.")
        
        # System Metrics
        if show_metrics:
            st.markdown("### 💻 System Metrics")
            try:
                cpu_percent = psutil.cpu_percent(interval=0.5)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/' if os.name != 'nt' else 'C:\\')
                
                st.markdown(f"**CPU:** {cpu_percent}%")
                st.progress(cpu_percent / 100)
                
                st.markdown(f"**Memory:** {memory.percent}%")
                st.progress(memory.percent / 100)
                
                st.markdown(f"**Disk:** {disk.percent}%")
                st.progress(disk.percent / 100)
            except Exception as e:
                st.error(f"Error: {e}")
    
    # Active Connections
    if show_connections:
        st.markdown("### 🔌 Active Connections")
        try:
            connections = psutil.net_connections(kind='inet')
            conn_data = []
            for conn in connections[:20]:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    conn_data.append({
                        "Local": f"{conn.laddr.ip}:{conn.laddr.port}",
                        "Remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                        "Status": conn.status,
                        "PID": conn.pid or "N/A"
                    })
            
            if conn_data:
                df_connections = pd.DataFrame(conn_data)
                st.dataframe(df_connections, use_container_width=True, hide_index=True, height=300)
            else:
                st.info("No active connections")
        except Exception as e:
            st.error(f"Error: {e}")
    
    # Footer
    st.markdown(
        f"""
        <div style="text-align: center; color: #B0B0B0; padding: 2rem; margin-top: 3rem;">
            🛡️ RealTime Attack Detection System | Last Updated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        </div>
        """,
        unsafe_allow_html=True
    )


def render_realtime_graphs(dashboard_data):
    """Render real-time graphs tab."""
    st.markdown("## 📈 Real-Time Graphs & Analytics")
    
    # Check if packet visualizer is available and running
    use_live_data = False
    if SCAPY_AVAILABLE and PacketVisualizer and "packet_visualizer" in st.session_state:
        visualizer = st.session_state.packet_visualizer
        if visualizer.running:
            use_live_data = True
    
    # PPS Graph
    st.markdown("### 📊 Packets Per Second (PPS) Graph")
    if use_live_data:
        # Use live packet data
        pps_data = visualizer.get_pps_data(minutes=30)
        if pps_data:
            df_pps = pd.DataFrame(pps_data)
            fig_pps = go.Figure()
            fig_pps.add_trace(go.Scatter(
                x=df_pps["timestamp"],
                y=df_pps["pps"],
                name="PPS (Live)",
                line=dict(color='#888888', width=3),
                fill='tozeroy',
                fillcolor='rgba(136, 136, 136, 0.2)',
                mode='lines'
            ))
            fig_pps.update_layout(
                height=400,
                plot_bgcolor='rgba(26, 26, 26, 0.9)',
                paper_bgcolor='rgba(18, 18, 18, 0.9)',
                font=dict(color='#E0E0E0', size=12),
                legend=dict(bgcolor='rgba(26, 26, 26, 0.9)'),
                margin=dict(l=0, r=0, t=0, b=0),
                xaxis_title="Time",
                yaxis_title="Packets Per Second"
            )
            st.plotly_chart(fig_pps, use_container_width=True)
        else:
            st.info("No live PPS data yet. Start packet capture in Live Packet Visualization tab.")
    else:
        # Use attack data
        pps_data = dashboard_data.get_pps_data(30)
        if pps_data:
            df_pps = pd.DataFrame(pps_data)
            fig_pps = go.Figure()
            fig_pps.add_trace(go.Scatter(
                x=df_pps["Time"],
                y=df_pps["PPS"],
                name="PPS",
                line=dict(color='#888888', width=3),
                fill='tozeroy',
                fillcolor='rgba(136, 136, 136, 0.2)'
            ))
            if "Attack Count" in df_pps.columns:
                fig_pps.add_trace(go.Scatter(
                    x=df_pps["Time"],
                    y=df_pps["Attack Count"] * 100,
                    name="Attack Activity",
                    line=dict(color='#e74c3c', width=2, dash='dash')
                ))
            fig_pps.update_layout(
                height=400,
                plot_bgcolor='rgba(26, 26, 26, 0.9)',
                paper_bgcolor='rgba(18, 18, 18, 0.9)',
                font=dict(color='#E0E0E0', size=12),
                legend=dict(bgcolor='rgba(26, 26, 26, 0.9)'),
                margin=dict(l=0, r=0, t=0, b=0),
                xaxis_title="Time",
                yaxis_title="Packets Per Second"
            )
            st.plotly_chart(fig_pps, use_container_width=True)
        else:
            st.info("No PPS data available. Start packet capture for live data.")
    
    # Per-IP Traffic Graph
    st.markdown("### 🌐 Per-IP Traffic Analysis")
    if use_live_data:
        # Use live packet data
        top_talkers = visualizer.get_top_talkers(top_n=20)
        if top_talkers:
            df_ip = pd.DataFrame(top_talkers)
            fig_ip = go.Figure()
            fig_ip.add_trace(go.Bar(
                x=df_ip["ip"],
                y=df_ip["packets"],
                name="Total Packets",
                marker_color='#888888',
                text=df_ip["packets"],
                textposition='outside'
            ))
            fig_ip.update_layout(
                height=400,
                plot_bgcolor='rgba(26, 26, 26, 0.9)',
                paper_bgcolor='rgba(18, 18, 18, 0.9)',
                font=dict(color='#E0E0E0', size=12),
                xaxis_title="Source IP",
                yaxis_title="Total Packets",
                margin=dict(l=0, r=0, t=0, b=0)
            )
            st.plotly_chart(fig_ip, use_container_width=True)
            
            # IP Traffic Table
            st.markdown("#### 📋 Top Talkers")
            display_df = df_ip[["ip", "packets", "bytes"]].copy()
            display_df.columns = ["IP Address", "Packets", "Bytes"]
            display_df["Bytes"] = display_df["Bytes"].apply(lambda x: f"{x:,}")
            st.dataframe(display_df, use_container_width=True, hide_index=True)
        else:
            st.info("No per-IP traffic data yet. Start capture to see live data.")
    else:
        # Use attack data
        ip_traffic = dashboard_data.get_per_ip_traffic(30)
        if ip_traffic:
            df_ip = pd.DataFrame(ip_traffic)
            fig_ip = go.Figure()
            fig_ip.add_trace(go.Bar(
                x=df_ip["IP"],
                y=df_ip["Total Packets"],
                name="Total Packets",
                marker_color='#888888'
            ))
            fig_ip.update_layout(
                height=400,
                plot_bgcolor='rgba(26, 26, 26, 0.9)',
                paper_bgcolor='rgba(18, 18, 18, 0.9)',
                font=dict(color='#E0E0E0', size=12),
                xaxis_title="Source IP",
                yaxis_title="Total Packets",
                margin=dict(l=0, r=0, t=0, b=0)
            )
            st.plotly_chart(fig_ip, use_container_width=True)
            
            # IP Traffic Table
            st.markdown("#### 📋 Top Attacking IPs")
            st.dataframe(df_ip.head(20), use_container_width=True, hide_index=True)
        else:
            st.info("No per-IP traffic data available")
    
    # Protocol Breakdown
    st.markdown("### 🔌 Protocol Breakdown")
    if use_live_data:
        # Use live packet data
        protocol_data = visualizer.get_protocol_breakdown()
        if protocol_data:
            col1, col2 = st.columns(2)
            
            with col1:
                fig_protocol_count = px.pie(
                    values=list(protocol_data.values()),
                    names=list(protocol_data.keys()),
                    title="Packets by Protocol (Live)",
                    color_discrete_sequence=['#888888', '#B0B0B0', '#E0E0E0', '#444444', '#e67e22']
                )
                fig_protocol_count.update_layout(
                    plot_bgcolor='rgba(26, 26, 26, 0.9)',
                    paper_bgcolor='rgba(18, 18, 18, 0.9)',
                    font=dict(color='#E0E0E0', size=12),
                    margin=dict(l=0, r=0, t=30, b=0)
                )
                st.plotly_chart(fig_protocol_count, use_container_width=True)
            
            with col2:
                fig_protocol_packets = go.Figure()
                fig_protocol_packets.add_trace(go.Bar(
                    x=list(protocol_data.keys()),
                    y=list(protocol_data.values()),
                    marker_color='#888888',
                    text=list(protocol_data.values()),
                    textposition='outside'
                ))
                fig_protocol_packets.update_layout(
                    height=400,
                    plot_bgcolor='rgba(26, 26, 26, 0.9)',
                    paper_bgcolor='rgba(18, 18, 18, 0.9)',
                    font=dict(color='#E0E0E0', size=12),
                    xaxis_title="Protocol",
                    yaxis_title="Total Packets",
                    margin=dict(l=0, r=0, t=30, b=0),
                    showlegend=False
                )
                st.plotly_chart(fig_protocol_packets, use_container_width=True)
        else:
            st.info("No protocol data yet. Start capture to see live data.")
    else:
        # Use attack data
        protocol_data = dashboard_data.get_protocol_breakdown()
        if protocol_data["counts"]:
            col1, col2 = st.columns(2)
            
            with col1:
                # Protocol Count Chart
                fig_protocol_count = px.pie(
                    values=list(protocol_data["counts"].values()),
                    names=list(protocol_data["counts"].keys()),
                    title="Attacks by Protocol",
                    color_discrete_sequence=['#888888', '#B0B0B0', '#E0E0E0', '#444444', '#e67e22']
                )
                fig_protocol_count.update_layout(
                    plot_bgcolor='rgba(26, 26, 26, 0.9)',
                    paper_bgcolor='rgba(18, 18, 18, 0.9)',
                    font=dict(color='#E0E0E0', size=12),
                    margin=dict(l=0, r=0, t=30, b=0)
                )
                st.plotly_chart(fig_protocol_count, use_container_width=True)
            
            with col2:
                # Protocol Packets Chart
                if protocol_data["packets"]:
                    fig_protocol_packets = px.bar(
                        x=list(protocol_data["packets"].keys()),
                        y=list(protocol_data["packets"].values()),
                        title="Packets by Protocol",
                        color=list(protocol_data["packets"].values()),
                        color_continuous_scale='viridis'
                    )
                    fig_protocol_packets.update_layout(
                        plot_bgcolor='rgba(26, 26, 26, 0.9)',
                        paper_bgcolor='rgba(18, 18, 18, 0.9)',
                        font=dict(color='#E0E0E0', size=12),
                        xaxis_title="Protocol",
                        yaxis_title="Total Packets",
                        margin=dict(l=0, r=0, t=30, b=0),
                        showlegend=False
                    )
                    st.plotly_chart(fig_protocol_packets, use_container_width=True)
        else:
            st.info("No protocol data available")
    
    # Attack Timeline (Enhanced)
    st.markdown("### ⏱️ Attack Timeline")
    if dashboard_data.attack_history:
        timeline_data = []
        for attack in dashboard_data.attack_history[-200:]:
            timeline_data.append({
                "Time": attack["timestamp"],
                "Attack Type": attack.get("attack_type", "Unknown"),
                "Severity": attack.get("severity", "MEDIUM"),
                "IP": attack.get("src_ip", "Unknown"),
                "PPS": attack.get("packet_rate_pps", attack.get("packet_rate", 0)) or 0
            })
        
        if timeline_data:
            df_timeline = pd.DataFrame(timeline_data)
            color_map = {"CRITICAL": "#e74c3c", "HIGH": "#e67e22", "MEDIUM": "#888888", "LOW": "#B0B0B0"}
            
            fig_timeline = go.Figure()
            for severity in df_timeline["Severity"].unique():
                df_sev = df_timeline[df_timeline["Severity"] == severity]
                fig_timeline.add_trace(go.Scatter(
                    x=df_sev["Time"],
                    y=df_sev["PPS"],
                    mode='markers',
                    name=severity,
                    marker=dict(
                        size=15,
                        color=color_map.get(severity, "#888888"),
                        line=dict(width=2, color='#E0E0E0')
                    ),
                    hovertemplate='<b>%{text}</b><br>Time: %{x}<br>PPS: %{y}<br>Severity: ' + severity + '<extra></extra>',
                    text=[f"{row['Attack Type']} from {row['IP']}" for _, row in df_sev.iterrows()]
                ))
            
            fig_timeline.update_layout(
                height=500,
                plot_bgcolor='rgba(26, 26, 26, 0.9)',
                paper_bgcolor='rgba(18, 18, 18, 0.9)',
                font=dict(color='#E0E0E0', size=12),
                legend=dict(bgcolor='rgba(26, 26, 26, 0.9)', bordercolor='#444444'),
                margin=dict(l=0, r=0, t=0, b=0),
                xaxis_title="Time",
                yaxis_title="Packets Per Second (PPS)"
            )
            st.plotly_chart(fig_timeline, use_container_width=True)


def render_attacker_profiles(dashboard_data):
    """Render attacker profiles tab."""
    st.markdown("## 👤 Attacker Profiles")
    
    # Get unique attacker IPs
    all_attacks = dashboard_data.get_all_attacks()
    unique_ips = list(set(a.get("src_ip", "Unknown") for a in all_attacks if a.get("src_ip") and a.get("src_ip") != "Unknown"))
    
    if not unique_ips:
        st.info("No attacker IPs found")
        return
    
    # IP Selector
    selected_ip = st.selectbox("🔍 Select Attacker IP", unique_ips, key="attacker_ip_selector")
    
    if selected_ip:
        profile = dashboard_data.get_attacker_profile(selected_ip)
        
        if profile:
            # Header
            col1, col2 = st.columns([2, 1])
            with col1:
                st.markdown(f"### 🎯 Attacker Profile: `{profile['ip']}`")
            with col2:
                reputation = profile.get("reputation_score", 50)
                if reputation < 30:
                    st.error(f"**Reputation Score: {reputation}/100** ⚠️ HIGH RISK")
                elif reputation < 60:
                    st.warning(f"**Reputation Score: {reputation}/100** ⚠️ MEDIUM RISK")
                else:
                    st.success(f"**Reputation Score: {reputation}/100** ✅ LOW RISK")
            
            # Key Metrics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Attacks", profile["total_attacks"])
            with col2:
                st.metric("Total Packets", f"{profile['total_packets']:,}")
            with col3:
                st.metric("Max PPS", f"{profile['max_pps']:.0f}")
            with col4:
                st.metric("Threat Level", profile.get("threat_level", "UNKNOWN"))
            
            # Why Flagged
            st.markdown("### 🚨 Why This IP Was Flagged")
            why_flagged = profile.get("why_flagged", [])
            if why_flagged:
                for reason in why_flagged:
                    st.warning(f"⚠️ {reason}")
            else:
                st.info("No specific flags identified")
            
            # Location & Network Info
            st.markdown("### 📍 Location & Network Information")
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"**Country:** {profile.get('country', 'Unknown')}")
                st.markdown(f"**City:** {profile.get('city', 'Unknown')}")
                st.markdown(f"**ISP:** {profile.get('isp', 'Unknown')}")
                st.markdown(f"**Organization:** {profile.get('organization', 'Unknown')}")
            with col2:
                st.markdown(f"**ASN:** {profile.get('asn', 'Unknown')}")
                st.markdown(f"**First Seen:** {profile['first_seen'].strftime('%Y-%m-%d %H:%M:%S')}")
                st.markdown(f"**Last Seen:** {profile['last_seen'].strftime('%Y-%m-%d %H:%M:%S')}")
                open_ports = profile.get("open_ports", [])
                if open_ports:
                    st.markdown(f"**Open Ports:** {len(open_ports)} ({', '.join(map(str, open_ports[:10]))})")
            
            # Attack Statistics
            st.markdown("### 📊 Attack Statistics")
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**Attack Types:**")
                for atype, count in profile.get("attack_types", {}).items():
                    st.write(f"- {atype}: {count}")
            with col2:
                st.markdown("**Severity Distribution:**")
                for severity, count in profile.get("severities", {}).items():
                    st.write(f"- {severity}: {count}")
            
            # Vulnerabilities
            vulnerabilities = profile.get("vulnerabilities", [])
            if vulnerabilities:
                st.markdown("### 🚨 Known Vulnerabilities")
                st.warning(f"**{len(vulnerabilities)} CVEs Found:** {', '.join(vulnerabilities[:10])}")
            
            # Honeypot Score
            honeypot_score = profile.get("honeypot_score")
            if honeypot_score is not None:
                st.markdown("### 🍯 Honeypot Analysis")
                if honeypot_score < 0.3:
                    st.success(f"Honeypot Score: {honeypot_score:.2f} - Likely Real Threat")
                elif honeypot_score < 0.7:
                    st.warning(f"Honeypot Score: {honeypot_score:.2f} - Possible Honeypot")
                else:
                    st.info(f"Honeypot Score: {honeypot_score:.2f} - Likely Honeypot")
            
            # Complete Attack History from this IP
            st.markdown("### 📋 Complete Attack History from This IP")
            ip_attacks = [a for a in all_attacks if a.get("src_ip") == selected_ip]
            ip_attacks = sorted(ip_attacks, key=lambda x: x["timestamp"], reverse=True)
            
            st.info(f"📊 **{len(ip_attacks)} total attacks** from this IP")
            
            # Detailed Attack Table
            if ip_attacks:
                attack_data = []
                for idx, attack in enumerate(ip_attacks, 1):
                    attack_data.append({
                        "#": idx,
                        "Timestamp": attack["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if isinstance(attack["timestamp"], datetime) else str(attack["timestamp"]),
                        "Attack Type": attack.get("attack_type", "Unknown"),
                        "Subtype": attack.get("attack_subtype", "N/A"),
                        "Severity": attack.get("severity", "MEDIUM"),
                        "Protocol": attack.get("protocol", "Unknown"),
                        "Packet Count": f"{attack.get('packet_count', 0):,}" if attack.get('packet_count') else "N/A",
                        "Packet Rate (PPS)": f"{attack.get('packet_rate', attack.get('packet_rate_pps', 0)):.2f}" if attack.get('packet_rate') or attack.get('packet_rate_pps') else "N/A",
                        "Time Window (s)": f"{attack.get('time_window', 'N/A')}" if attack.get('time_window') else "N/A",
                        "Scanned Ports": f"{len(attack.get('scanned_ports', []))} ports" if attack.get('scanned_ports') else "N/A",
                        "Port Count": attack.get("port_count", "N/A") if attack.get("port_count") else "N/A"
                    })
                
                df_attacks = pd.DataFrame(attack_data)
                st.dataframe(df_attacks, use_container_width=True, hide_index=True, height=400)
                
                # Expandable detailed view for each attack
                st.markdown("#### 🔍 Detailed Attack Information")
                for idx, attack in enumerate(ip_attacks[:20], 1):  # Show first 20 in detail
                    with st.expander(f"Attack #{idx}: {attack.get('attack_type', 'Unknown')} - {attack['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if isinstance(attack['timestamp'], datetime) else attack['timestamp']}"):
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.markdown("**Basic Information**")
                            st.write(f"**Attack Type:** {attack.get('attack_type', 'Unknown')}")
                            st.write(f"**Attack Subtype:** {attack.get('attack_subtype', 'N/A')}")
                            st.write(f"**Severity:** {attack.get('severity', 'MEDIUM')}")
                            st.write(f"**Protocol:** {attack.get('protocol', 'Unknown')}")
                            st.write(f"**Timestamp:** {attack['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if isinstance(attack['timestamp'], datetime) else attack['timestamp']}")
                            
                            if attack.get('time_window'):
                                st.write(f"**Time Window:** {attack['time_window']} seconds")
                            if attack.get('port_count'):
                                st.write(f"**Port Count:** {attack['port_count']}")
                            if attack.get('scan_rate'):
                                st.write(f"**Scan Rate:** {attack['scan_rate']:.2f} ports/sec")
                        
                        with col2:
                            st.markdown("**Traffic Statistics**")
                            if attack.get('packet_count'):
                                st.write(f"**Packet Count:** {attack['packet_count']:,}")
                            if attack.get('packet_rate') or attack.get('packet_rate_pps'):
                                rate = attack.get('packet_rate') or attack.get('packet_rate_pps', 0)
                                st.write(f"**Packet Rate:** {rate:.2f} PPS")
                            if attack.get('threshold_pps'):
                                st.write(f"**Threshold:** {attack['threshold_pps']:.2f} PPS")
                            if attack.get('baseline_pps'):
                                st.write(f"**Baseline PPS:** {attack['baseline_pps']:.2f}")
                            
                            if attack.get('scanned_ports'):
                                ports = attack['scanned_ports']
                                if len(ports) <= 20:
                                    st.write(f"**Scanned Ports:** {', '.join(map(str, ports))}")
                                else:
                                    st.write(f"**Scanned Ports:** {', '.join(map(str, ports[:20]))} ... (+{len(ports)-20} more)")
                                    with st.expander("View All Ports"):
                                        st.write(', '.join(map(str, ports)))
                        
                        # Shodan Intelligence
                        if attack.get('shodan_data'):
                            st.markdown("**🔍 Shodan Threat Intelligence**")
                            shodan = attack['shodan_data']
                            ip_info = shodan.get('ip_info', {})
                            st.write(f"**Threat Level:** {shodan.get('threat_level', 'UNKNOWN')}")
                            if ip_info.get('org'):
                                st.write(f"**Organization:** {ip_info['org']}")
                            if ip_info.get('isp'):
                                st.write(f"**ISP:** {ip_info['isp']}")
                            if ip_info.get('location'):
                                loc = ip_info['location']
                                st.write(f"**Location:** {loc.get('city', '')}, {loc.get('country', '')}")
                        
                        # Full attack data (JSON view)
                        with st.expander("📄 View Raw Attack Data (JSON)"):
                            st.json(attack)
                
                # Also show attack cards for visual view
                st.markdown("#### 🎨 Visual Attack Cards")
                for attack in ip_attacks[:10]:  # Show first 10 as cards
                    render_attack_card(attack)


def render_export_section(dashboard_data):
    """Render export section."""
    st.markdown("## 💾 Export Attack Logs")
    
    all_attacks = dashboard_data.get_all_attacks()
    
    if not all_attacks:
        st.info("No attacks to export")
        return
    
    st.info(f"📊 **{len(all_attacks)} attacks** available for export")
    
    # Export Options
    st.markdown("### 📤 Export Format")
    
    # PDF Report Section (New)
    if PDF_REPORT_AVAILABLE:
        st.markdown("#### 📄 PDF Report Generator")
        st.caption("Generate comprehensive PDF reports with statistics, charts, and detailed analysis")
        
        col_pdf1, col_pdf2, col_pdf3 = st.columns(3)
        with col_pdf1:
            report_type = st.selectbox(
                "Report Type",
                ["Comprehensive", "Summary", "Detailed"],
                key="pdf_report_type"
            )
        with col_pdf2:
            pdf_time_range = st.selectbox(
                "Time Range",
                ["All", "Last 24 Hours", "Last 7 Days", "Last 30 Days", "Custom"],
                key="pdf_time_range"
            )
        with col_pdf3:
            custom_title = st.text_input("Custom Title (Optional)", key="pdf_custom_title")
        
        # Custom date range
        start_date = None
        end_date = None
        if pdf_time_range == "Custom":
            col_date1, col_date2 = st.columns(2)
            with col_date1:
                start_date = st.date_input("Start Date", key="pdf_start_date")
            with col_date2:
                end_date = st.date_input("End Date", key="pdf_end_date")
        elif pdf_time_range != "All":
            now = datetime.now()
            if pdf_time_range == "Last 24 Hours":
                start_date = now - timedelta(hours=24)
            elif pdf_time_range == "Last 7 Days":
                start_date = now - timedelta(days=7)
            elif pdf_time_range == "Last 30 Days":
                start_date = now - timedelta(days=30)
            start_date = start_date if start_date else None
        
        # Filter attacks
        filtered_attacks = all_attacks
        if start_date:
            if isinstance(start_date, datetime):
                start_dt = start_date
            else:
                start_dt = datetime.combine(start_date, datetime.min.time())
            filtered_attacks = [
                a for a in all_attacks
                if (a["timestamp"] if isinstance(a["timestamp"], datetime) else datetime.fromisoformat(a["timestamp"])) >= start_dt
            ]
        if end_date:
            if isinstance(end_date, datetime):
                end_dt = end_date
            else:
                end_dt = datetime.combine(end_date, datetime.max.time())
            filtered_attacks = [
                a for a in filtered_attacks
                if (a["timestamp"] if isinstance(a["timestamp"], datetime) else datetime.fromisoformat(a["timestamp"])) <= end_dt
            ]
        
        if st.button("📄 Generate PDF Report", use_container_width=True, key="generate_pdf"):
            try:
                with st.spinner("Generating PDF report... This may take a moment."):
                    generator = PDFReportGenerator()
                    pdf_path = generator.generate_report(
                        attacks=filtered_attacks,
                        report_type=report_type.lower(),
                        start_date=start_date,
                        end_date=end_date,
                        title=custom_title if custom_title else None
                    )
                    
                    # Read PDF file
                    with open(pdf_path, "rb") as pdf_file:
                        pdf_bytes = pdf_file.read()
                    
                    st.success(f"✅ PDF report generated successfully!")
                    st.download_button(
                        label="⬇️ Download PDF Report",
                        data=pdf_bytes,
                        file_name=Path(pdf_path).name,
                        mime="application/pdf",
                        key="download_pdf"
                    )
                    st.info(f"📄 Report saved to: `{pdf_path}`")
            except Exception as e:
                st.error(f"❌ Error generating PDF report: {e}")
                st.exception(e)
        
        st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # CSV Export
        st.markdown("#### 📄 CSV Export")
        csv_data = export_to_csv(all_attacks)
        st.download_button(
            label="⬇️ Download CSV",
            data=csv_data,
            file_name=f"attack_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            key="export_csv"
        )
        
        # JSON Export
        st.markdown("#### 📋 JSON Export")
        json_data = export_to_json(all_attacks)
        st.download_button(
            label="⬇️ Download JSON",
            data=json_data,
            file_name=f"attack_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            key="export_json"
        )
    
    with col2:
        # ElasticSearch Export
        st.markdown("#### 🔍 ElasticSearch Export")
        es_data = export_to_elasticsearch_format(all_attacks)
        es_json = json.dumps(es_data, indent=2, ensure_ascii=False, default=str)
        st.download_button(
            label="⬇️ Download ElasticSearch Bulk",
            data=es_json,
            file_name=f"attack_logs_elasticsearch_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            key="export_es"
        )
        st.caption("Use this with: `curl -X POST 'localhost:9200/_bulk' -H 'Content-Type: application/json' --data-binary @file.json`")
        
        # Grafana Export
        st.markdown("#### 📊 Grafana Export")
        grafana_data = export_to_grafana_format(all_attacks)
        grafana_json = json.dumps(grafana_data, indent=2, ensure_ascii=False)
        st.download_button(
            label="⬇️ Download Grafana Time Series",
            data=grafana_json,
            file_name=f"attack_logs_grafana_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            key="export_grafana"
        )
        st.caption("Import this JSON into Grafana as a time series data source")
    
    # Export Configuration
    st.markdown("### ⚙️ Export Configuration")
    with st.expander("🔧 Advanced Export Settings"):
        index_name = st.text_input("ElasticSearch Index Name", value="attack-detection", key="es_index")
        time_range = st.selectbox("Time Range", ["All", "Last 24 Hours", "Last 7 Days", "Last 30 Days"], key="export_time_range")
        
        # Filter attacks by time range
        if time_range != "All":
            now = datetime.now()
            if time_range == "Last 24 Hours":
                cutoff = now - timedelta(hours=24)
            elif time_range == "Last 7 Days":
                cutoff = now - timedelta(days=7)
            else:
                cutoff = now - timedelta(days=30)
            
            filtered_attacks = [a for a in all_attacks if a["timestamp"] >= cutoff]
            st.info(f"📊 {len(filtered_attacks)} attacks in selected time range")
        else:
            filtered_attacks = all_attacks
        
        if st.button("🔄 Regenerate Exports", key="regenerate_exports"):
            st.rerun()


def render_live_packet_visualization():
    """Render live packet visualization tab."""
    st.markdown("## 📡 Live Packet Visualization")
    
    if not SCAPY_AVAILABLE or PacketVisualizer is None:
        st.error("⚠️ Scapy is not available. Please install it with: `pip install scapy`")
        st.info("Real-time packet visualization requires Scapy for packet capture.")
        return
    
    # Initialize packet visualizer in session state
    if "packet_visualizer" not in st.session_state:
        try:
            config = load_config()
            interface = config.get("network", {}).get("interface")
            st.session_state.packet_visualizer = PacketVisualizer(interface=interface)
        except Exception as e:
            st.error(f"Failed to initialize packet visualizer: {e}")
            return
    
    visualizer = st.session_state.packet_visualizer
    
    # Control panel
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        if st.button("▶️ Start Capture" if not visualizer.running else "⏸️ Stop Capture", 
                     use_container_width=True, key="toggle_capture"):
            if visualizer.running:
                visualizer.stop()
                st.success("Packet capture stopped")
            else:
                try:
                    visualizer.start()
                    st.success("Packet capture started")
                except Exception as e:
                    st.error(f"Failed to start capture: {e}")
            st.rerun()
    
    with col2:
        if st.button("🔄 Reset Stats", use_container_width=True, key="reset_stats"):
            visualizer.reset()
            st.success("Statistics reset")
            st.rerun()
    
    with col3:
        if st.button("📊 Refresh Data", use_container_width=True, key="refresh_viz"):
            st.rerun()
    
    with col4:
        auto_refresh_viz = st.checkbox("🔄 Auto Refresh", value=True, key="auto_refresh_viz")
        if auto_refresh_viz and visualizer.running:
            st.caption("⏱️ Auto-refresh: 2s")
    
    # Status indicator
    if visualizer.running:
        st.success("🟢 **Live Capture Active** - Capturing packets in real-time")
    else:
        st.warning("🔴 **Capture Stopped** - Click 'Start Capture' to begin")
    
    # Statistics
    stats = visualizer.get_statistics()
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total Packets", f"{stats['total_packets']:,}")
    with col2:
        st.metric("Current PPS", f"{stats['current_pps']:.1f}")
    with col3:
        st.metric("Unique IPs", stats['unique_ips'])
    with col4:
        st.metric("Connections", stats['unique_connections'])
    with col5:
        uptime_min = stats['uptime_seconds'] / 60
        st.metric("Uptime", f"{uptime_min:.1f} min")
    
    st.markdown("---")
    
    # Live PPS Chart with auto-update placeholder
    st.markdown("### 📊 Live PPS (Packets Per Second) Chart")
    pps_chart_placeholder = st.empty()
    
    pps_data = visualizer.get_pps_data(minutes=5)
    
    if pps_data:
        df_pps = pd.DataFrame(pps_data)
        fig_pps = go.Figure()
        fig_pps.add_trace(go.Scatter(
            x=df_pps["timestamp"],
            y=df_pps["pps"],
            name="PPS",
            line=dict(color='#888888', width=3),
            fill='tozeroy',
            fillcolor='rgba(136, 136, 136, 0.2)',
            mode='lines'
        ))
        fig_pps.update_layout(
            height=400,
            plot_bgcolor='rgba(26, 26, 26, 0.9)',
            paper_bgcolor='rgba(18, 18, 18, 0.9)',
            font=dict(color='#E0E0E0', size=12),
            xaxis_title="Time",
            yaxis_title="Packets Per Second (PPS)",
            margin=dict(l=0, r=0, t=0, b=0),
            hovermode='x unified'
        )
        pps_chart_placeholder.plotly_chart(fig_pps, use_container_width=True)
    else:
        pps_chart_placeholder.info("No PPS data yet. Start capture to see live data.")
    
    st.markdown("---")
    
    # Network Heatmap and Top Talkers side by side
    col_left, col_right = st.columns(2)
    
    with col_left:
        st.markdown("### 🔥 Network Heatmap")
        st.caption("Top source-destination IP connections")
        
        heatmap_data = visualizer.get_network_heatmap(top_n=30)
        if heatmap_data:
            # Create heatmap visualization
            df_heatmap = pd.DataFrame(heatmap_data)
            
            # Create a matrix for heatmap
            sources = df_heatmap["source"].unique()
            destinations = df_heatmap["destination"].unique()
            
            # Create heatmap using scatter plot with size encoding
            fig_heatmap = go.Figure()
            
            # Add connections as scatter points
            fig_heatmap.add_trace(go.Scatter(
                x=df_heatmap["source"],
                y=df_heatmap["destination"],
                mode='markers',
                marker=dict(
                    size=df_heatmap["packets"] / df_heatmap["packets"].max() * 50 + 10,
                    color=df_heatmap["packets"],
                    colorscale='YlOrRd',
                    showscale=True,
                    colorbar=dict(title="Packets")
                ),
                text=df_heatmap["packets"],
                hovertemplate='<b>%{x} → %{y}</b><br>Packets: %{text}<extra></extra>',
                name="Connections"
            ))
            
            fig_heatmap.update_layout(
                height=500,
                plot_bgcolor='rgba(26, 26, 26, 0.9)',
                paper_bgcolor='rgba(18, 18, 18, 0.9)',
                font=dict(color='#E0E0E0', size=10),
                xaxis_title="Source IP",
                yaxis_title="Destination IP",
                margin=dict(l=100, r=50, t=50, b=100),
                xaxis=dict(tickangle=-45),
                yaxis=dict(tickangle=0)
            )
            st.plotly_chart(fig_heatmap, use_container_width=True)
            
            # Also show as table
            with st.expander("📋 View Heatmap Data Table"):
                st.dataframe(df_heatmap, use_container_width=True, hide_index=True)
        else:
            st.info("No network connections data yet. Start capture to see heatmap.")
    
    with col_right:
        st.markdown("### 🎯 Top Talkers")
        st.caption("IPs with most network activity")
        
        top_talkers = visualizer.get_top_talkers(top_n=20)
        if top_talkers:
            df_talkers = pd.DataFrame(top_talkers)
            
            # Bar chart
            fig_talkers = go.Figure()
            fig_talkers.add_trace(go.Bar(
                x=df_talkers["ip"],
                y=df_talkers["packets"],
                name="Packets",
                marker_color='#888888',
                text=df_talkers["packets"],
                textposition='outside',
                hovertemplate='<b>%{x}</b><br>Packets: %{y:,}<br>Bytes: %{customdata:,}<extra></extra>',
                customdata=df_talkers["bytes"]
            ))
            
            fig_talkers.update_layout(
                height=500,
                plot_bgcolor='rgba(26, 26, 26, 0.9)',
                paper_bgcolor='rgba(18, 18, 18, 0.9)',
                font=dict(color='#E0E0E0', size=10),
                xaxis_title="IP Address",
                yaxis_title="Total Packets",
                margin=dict(l=0, r=0, t=50, b=100),
                xaxis=dict(tickangle=-45)
            )
            st.plotly_chart(fig_talkers, use_container_width=True)
            
            # Table view
            with st.expander("📋 View Top Talkers Table"):
                display_df = df_talkers[["ip", "packets", "bytes", "pps_estimate"]].copy()
                display_df.columns = ["IP Address", "Packets", "Bytes", "Est. PPS"]
                display_df["Bytes"] = display_df["Bytes"].apply(lambda x: f"{x:,}")
                display_df["Est. PPS"] = display_df["Est. PPS"].apply(lambda x: f"{x:.2f}")
                st.dataframe(display_df, use_container_width=True, hide_index=True)
        else:
            st.info("No top talkers data yet. Start capture to see statistics.")
    
    st.markdown("---")
    
    # Protocol Breakdown
    st.markdown("### 🔌 Protocol Breakdown")
    protocol_data = visualizer.get_protocol_breakdown()
    
    if protocol_data:
        col1, col2 = st.columns(2)
        
        with col1:
            # Pie chart
            fig_protocol = px.pie(
                values=list(protocol_data.values()),
                names=list(protocol_data.keys()),
                title="Packets by Protocol",
                color_discrete_sequence=['#888888', '#B0B0B0', '#E0E0E0', '#444444', '#e67e22']
            )
            fig_protocol.update_layout(
                plot_bgcolor='rgba(26, 26, 26, 0.9)',
                paper_bgcolor='rgba(18, 18, 18, 0.9)',
                font=dict(color='#E0E0E0', size=12),
                margin=dict(l=0, r=0, t=50, b=0)
            )
            st.plotly_chart(fig_protocol, use_container_width=True)
        
        with col2:
            # Bar chart
            fig_protocol_bar = go.Figure()
            fig_protocol_bar.add_trace(go.Bar(
                x=list(protocol_data.keys()),
                y=list(protocol_data.values()),
                marker_color='#888888',
                text=list(protocol_data.values()),
                textposition='outside'
            ))
            fig_protocol_bar.update_layout(
                height=400,
                plot_bgcolor='rgba(26, 26, 26, 0.9)',
                paper_bgcolor='rgba(18, 18, 18, 0.9)',
                font=dict(color='#E0E0E0', size=12),
                xaxis_title="Protocol",
                yaxis_title="Packet Count",
                margin=dict(l=0, r=0, t=50, b=0)
            )
            st.plotly_chart(fig_protocol_bar, use_container_width=True)
    else:
        st.info("No protocol data yet. Start capture to see breakdown.")
    
    st.markdown("---")
    
    # Real Packet Log Display (Terminal Style)
    st.markdown("### 📋 Real-Time Packet Log (Terminal View)")
    st.caption("Live packet capture display - shows packets as they are captured")
    
    packet_log = visualizer.get_packet_log(limit=100)
    if packet_log:
        # Create terminal-style display with proper HTML formatting
        log_html_parts = ['<div class="packet-log">']
        for packet in reversed(packet_log[-50:]):  # Show last 50 packets
            timestamp = packet["timestamp"].strftime("%H:%M:%S.%f")[:-3]
            protocol = packet.get("protocol", "Unknown")
            src_ip = packet.get("src_ip") or "?"
            dst_ip = packet.get("dst_ip") or "?"
            src_port = packet.get("src_port")
            dst_port = packet.get("dst_port")
            length = packet.get("length", 0)
            
            # Format like terminal output - handle None values properly
            if src_port is not None and dst_port is not None:
                connection = f"{src_ip}:{src_port} → {dst_ip}:{dst_port}"
            elif src_ip != "?" and dst_ip != "?":
                connection = f"{src_ip} → {dst_ip}"
            else:
                connection = "Unknown connection"
            
            # Escape HTML special characters properly
            timestamp_esc = html.escape(str(timestamp))
            protocol_esc = html.escape(str(protocol))
            connection_esc = html.escape(str(connection))
            
            log_html_parts.append(
                f'<div class="packet-entry">'
                f'<span class="packet-time">[{timestamp_esc}]</span> '
                f'<span class="packet-protocol">{protocol_esc}</span> '
                f'<span class="packet-ip">{connection_esc}</span> '
                f'<span style="color: #B0B0B0;">({length} bytes)</span>'
                f'</div>'
            )
        log_html_parts.append('</div>')
        log_html = ''.join(log_html_parts)
        st.markdown(log_html, unsafe_allow_html=True)
        
        # Show packet count
        st.caption(f"Showing last 50 of {len(packet_log)} captured packets")
    else:
        st.info("No packets captured yet. Start capture to see live packet stream.")
    
    # Auto-refresh when capture is running
    if auto_refresh_viz and visualizer.running:
        import time
        time.sleep(2)  # Wait 2 seconds
        st.rerun()  # Refresh the page to show new packets


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        st.error(f"❌ **Critical Error:** {str(e)}")
        st.exception(e)
        st.info("Please check the terminal for more details and ensure all dependencies are installed.")
