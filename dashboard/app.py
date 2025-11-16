"""
Real-Time Web Dashboard for Attack Detection System.
Modern, eye-catching UI with glassmorphism design and smooth animations.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import time
import json
import os
import re
import hashlib
from pathlib import Path
import sys
import psutil

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from utils.helper import load_config

# Page configuration
st.set_page_config(
    page_title="🛡️ RealTime Attack Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Modern Glassmorphism CSS with animations
st.markdown("""
<style>
    /* Import Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');
    
    /* Global Styles */
    * {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    /* Main App Background - Animated Gradient */
    .stApp {
        background: linear-gradient(-45deg, #0a0e27, #1a1a2e, #16213e, #0f3460);
        background-size: 400% 400%;
        animation: gradientShift 15s ease infinite;
        color: #ffffff;
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
    
    /* Modern Header with Glow Effect */
    .main-header {
        font-size: 3.5rem;
        font-weight: 900;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        text-align: center;
        padding: 2rem 1rem;
        margin-bottom: 2rem;
        text-shadow: 0 0 40px rgba(102, 126, 234, 0.5);
        animation: pulse 2s ease-in-out infinite;
        letter-spacing: -0.02em;
    }
    
    @keyframes pulse {
        0%, 100% { transform: scale(1); }
        50% { transform: scale(1.02); }
    }
    
    /* Glassmorphism Cards */
    .glass-card {
        background: rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(20px);
        -webkit-backdrop-filter: blur(20px);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 20px;
        padding: 2rem;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }
    
    .glass-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 12px 48px 0 rgba(0, 0, 0, 0.5);
        border-color: rgba(102, 126, 234, 0.3);
    }
    
    /* Attack Card Styling */
    .attack-card {
        background: linear-gradient(135deg, rgba(30, 28, 46, 0.95) 0%, rgba(45, 27, 61, 0.95) 100%);
        backdrop-filter: blur(20px);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-left: 6px solid;
        border-radius: 16px;
        padding: 1.5rem;
        margin: 1rem 0;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        position: relative;
        overflow: hidden;
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
        box-shadow: 0 16px 48px rgba(0, 0, 0, 0.5);
        border-left-width: 8px;
    }
    
    .attack-card:hover::before {
        opacity: 1;
    }
    
    /* Metric Cards */
    .metric-card {
        background: rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(20px);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 16px;
        padding: 1.5rem;
        text-align: center;
        transition: all 0.3s ease;
        position: relative;
        overflow: hidden;
    }
    
    .metric-card::before {
        content: '';
        position: absolute;
        top: -50%;
        left: -50%;
        width: 200%;
        height: 200%;
        background: radial-gradient(circle, rgba(102, 126, 234, 0.1) 0%, transparent 70%);
        opacity: 0;
        transition: opacity 0.3s;
    }
    
    .metric-card:hover {
        transform: scale(1.05);
        border-color: rgba(102, 126, 234, 0.5);
    }
    
    .metric-card:hover::before {
        opacity: 1;
    }
    
    .metric-value {
        font-size: 2.5rem;
        font-weight: 800;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0.5rem 0;
    }
    
    .metric-label {
        font-size: 0.9rem;
        color: rgba(255, 255, 255, 0.7);
        text-transform: uppercase;
        letter-spacing: 0.1em;
        font-weight: 600;
    }
    
    /* Buttons */
    .stButton > button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        border-radius: 12px;
        padding: 0.75rem 2rem;
        font-weight: 600;
        font-size: 1rem;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        box-shadow: 0 4px 20px rgba(102, 126, 234, 0.4);
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
        background: rgba(255, 255, 255, 0.3);
        transform: translate(-50%, -50%);
        transition: width 0.6s, height 0.6s;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 30px rgba(102, 126, 234, 0.6);
    }
    
    .stButton > button:hover::before {
        width: 300px;
        height: 300px;
    }
    
    /* Sidebar */
    [data-testid="stSidebar"] {
        background: rgba(10, 14, 39, 0.8);
        backdrop-filter: blur(20px);
        border-right: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    /* Selectbox and Input */
    .stSelectbox > div > div {
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 12px;
    }
    
    .stTextInput > div > div > input {
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        color: white;
    }
    
    /* Progress Bars */
    .stProgress > div > div > div {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        border-radius: 10px;
    }
    
    /* Severity Badges */
    .severity-badge {
        display: inline-block;
        padding: 0.4rem 1rem;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
    }
    
    .severity-critical {
        background: linear-gradient(135deg, #ff1744 0%, #d50000 100%);
        color: white;
        animation: glow 2s ease-in-out infinite;
    }
    
    .severity-high {
        background: linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 100%);
        color: white;
    }
    
    .severity-medium {
        background: linear-gradient(135deg, #ffa500 0%, #ff8c00 100%);
        color: white;
    }
    
    .severity-low {
        background: linear-gradient(135deg, #4ecdc4 0%, #44a08d 100%);
        color: white;
    }
    
    @keyframes glow {
        0%, 100% { box-shadow: 0 4px 15px rgba(255, 23, 68, 0.5); }
        50% { box-shadow: 0 4px 25px rgba(255, 23, 68, 0.8); }
    }
    
    /* Real-time Indicator */
    .live-indicator {
        display: inline-block;
        width: 12px;
        height: 12px;
        background: #4caf50;
        border-radius: 50%;
        margin-right: 8px;
        animation: pulse-dot 2s ease-in-out infinite;
        box-shadow: 0 0 10px rgba(76, 175, 80, 0.8);
    }
    
    @keyframes pulse-dot {
        0%, 100% { transform: scale(1); opacity: 1; }
        50% { transform: scale(1.2); opacity: 0.7; }
    }
    
    /* Section Headers */
    h1, h2, h3 {
        color: #ffffff;
        font-weight: 700;
        letter-spacing: -0.02em;
    }
    
    h2 {
        font-size: 1.8rem;
        margin-bottom: 1.5rem;
        background: linear-gradient(135deg, #ffffff 0%, rgba(255, 255, 255, 0.7) 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    
    /* Scrollbar */
    ::-webkit-scrollbar {
        width: 10px;
    }
    
    ::-webkit-scrollbar-track {
        background: rgba(255, 255, 255, 0.05);
        border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: linear-gradient(135deg, #764ba2 0%, #667eea 100%);
    }
    
    /* Notification Banner */
    .notification-banner {
        background: linear-gradient(135deg, rgba(76, 175, 80, 0.2) 0%, rgba(56, 142, 60, 0.2) 100%);
        border: 1px solid rgba(76, 175, 80, 0.3);
        border-radius: 12px;
        padding: 1rem;
        margin: 1rem 0;
        animation: slideIn 0.5s ease-out;
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
    
    /* Info Boxes */
    .stInfo {
        background: rgba(33, 150, 243, 0.1);
        border-left: 4px solid #2196f3;
        border-radius: 8px;
    }
    
    .stSuccess {
        background: rgba(76, 175, 80, 0.1);
        border-left: 4px solid #4caf50;
        border-radius: 8px;
    }
    
    .stError {
        background: rgba(244, 67, 54, 0.1);
        border-left: 4px solid #f44336;
        border-radius: 8px;
    }
    
    /* Chart Containers */
    .js-plotly-plot {
        background: rgba(255, 255, 255, 0.03);
        border-radius: 16px;
        padding: 1rem;
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    /* Responsive */
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
        self.parsed_lines = set()
        self.last_file_size = 0
        self.last_file_position = 0
        self.blocked_ips = set()
        self.last_attack_count = 0
        self.load_attack_history()
        self.load_blocked_ips()
        self.last_attack_count = len(self.attack_history)
    
    def get_line_hash(self, line: str) -> str:
        """Create hash for a line to track if it's been parsed."""
        return hashlib.md5(line.encode()).hexdigest()
    
    def load_attack_history(self):
        """Load attack history from log file - only new attacks."""
        try:
            config = load_config()
            log_file = config.get("general", {}).get("log_file", "attack_detection.log")
            log_path = project_root / log_file
            
            if not log_path.exists():
                return
            
            current_size = log_path.stat().st_size
            
            if current_size == self.last_file_size:
                return
            
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(self.last_file_position)
                new_lines = f.readlines()
                self.last_file_position = f.tell()
                self.last_file_size = current_size
                
                for line in new_lines:
                    line = line.strip()
                    if not line:
                        continue
                    
                    line_hash = self.get_line_hash(line)
                    if line_hash in self.parsed_lines:
                        continue
                    
                    # Enhanced attack detection patterns
                    if ("ATTACK #" in line or 
                        "PING FLOOD DETECTED" in line.upper() or
                        "attack detected" in line.lower() and ("WARNING" in line or "CRITICAL" in line) or
                        ("detected from" in line.lower() and ("WARNING" in line or "CRITICAL" in line or "🚨" in line))):
                        
                        timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                        if timestamp_match:
                            try:
                                timestamp = datetime.strptime(timestamp_match.group(1), '%Y-%m-%d %H:%M:%S')
                            except:
                                timestamp = datetime.now()
                        else:
                            timestamp = datetime.now()
                        
                        # Extract attack type
                        attack_type = "Unknown Attack"
                        if "DDoS" in line or "Flooding" in line:
                            attack_type = "DDoS/Flooding"
                        elif "Port Scan" in line or "port scan" in line.lower():
                            attack_type = "Port Scanning"
                        elif "Brute Force" in line or "brute force" in line.lower():
                            attack_type = "Brute Force Login"
                        elif "Intrusion" in line or "intrusion" in line.lower():
                            attack_type = "Intrusion Attempt"
                        elif "CPS Attack" in line or "Modbus" in line:
                            attack_type = "CPS Attack"
                        elif "Ping Flood" in line or "ping flood" in line.lower():
                            attack_type = "Ping Flood Attack"
                        
                        # Extract IP
                        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                        src_ip = ip_match.group(0) if ip_match else "Unknown"
                        
                        # Extract severity
                        severity = "MEDIUM"
                        if "CRITICAL" in line:
                            severity = "CRITICAL"
                        elif "HIGH" in line:
                            severity = "HIGH"
                        elif "LOW" in line:
                            severity = "LOW"
                        
                        # Extract details
                        packet_count = None
                        packet_rate = None
                        protocol = "Unknown"
                        attack_subtype = ""
                        
                        # Packet count
                        pkt_count_match = re.search(r'Packets:\s*(\d+)', line, re.IGNORECASE)
                        if pkt_count_match:
                            packet_count = int(pkt_count_match.group(1))
                        else:
                            pkt_count_match = re.search(r'(\d+)\s+packets?', line, re.IGNORECASE)
                            if pkt_count_match:
                                packet_count = int(pkt_count_match.group(1))
                        
                        # Packet rate
                        pps_match = re.search(r'Rate:\s*([\d.]+)\s*PPS', line, re.IGNORECASE)
                        if pps_match:
                            packet_rate = float(pps_match.group(1))
                        else:
                            pps_match = re.search(r'([\d.]+)\s*PPS', line, re.IGNORECASE)
                            if pps_match:
                                packet_rate = float(pps_match.group(1))
                        
                        # Protocol
                        protocol_match = re.search(r'Protocol:\s*(\w+)', line, re.IGNORECASE)
                        if protocol_match:
                            protocol = protocol_match.group(1)
                        elif "ICMP" in line or "ping" in line.lower():
                            protocol = "ICMP"
                        elif "TCP" in line:
                            protocol = "TCP"
                        elif "UDP" in line:
                            protocol = "UDP"
                        
                        # Subtype
                        subtype_match = re.search(r'Type:\s*([^|]+)', line, re.IGNORECASE)
                        if subtype_match:
                            attack_subtype = subtype_match.group(1).strip()
                        elif "Ping Flood" in line or "ping flood" in line.lower():
                            attack_subtype = "ICMP Echo Request Flood"
                        elif "DDoS" in line or "Flooding" in line:
                            attack_subtype = "General Packet Flood"
                        elif "Port Scan" in line:
                            attack_subtype = "Multiple Port Scanning"
                        
                        self.attack_history.append({
                            "timestamp": timestamp,
                            "message": line,
                            "attack_type": attack_type,
                            "attack_subtype": attack_subtype,
                            "src_ip": src_ip,
                            "severity": severity,
                            "packet_count": packet_count,
                            "packet_rate": packet_rate,
                            "packet_rate_pps": packet_rate,
                            "protocol": protocol
                        })
                        
                        self.parsed_lines.add(line_hash)
                
                if len(self.attack_history) > 1000:
                    removed = self.attack_history[:-1000]
                    for attack in removed:
                        line_hash = self.get_line_hash(attack["message"])
                        self.parsed_lines.discard(line_hash)
                    self.attack_history = self.attack_history[-1000:]
        
        except Exception as e:
            st.error(f"Error loading attack history: {e}")
    
    def load_blocked_ips(self):
        """Load blocked IPs from active defense."""
        try:
            for attack in self.attack_history:
                if "Blocked IP" in attack["message"] or "blocked" in attack["message"].lower():
                    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', attack["message"])
                    if ip_match:
                        self.blocked_ips.add(ip_match.group(0))
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


# Initialize dashboard data
if 'dashboard_data' not in st.session_state:
    st.session_state.dashboard_data = DashboardData()

dashboard_data = st.session_state.dashboard_data


def render_attack_card(attack, index=None):
    """Render a beautiful modern attack card."""
    attack_type = attack.get("attack_type", "Unknown Attack")
    src_ip = attack.get("src_ip", "Unknown")
    severity = attack.get("severity", "MEDIUM")
    timestamp = attack["timestamp"]
    
    packet_count = attack.get("packet_count")
    packet_rate = attack.get("packet_rate", attack.get("packet_rate_pps"))
    protocol = attack.get("protocol", "Unknown")
    attack_subtype = attack.get("attack_subtype", "")
    
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
        "CRITICAL": "#ff1744",
        "HIGH": "#ff6b6b",
        "MEDIUM": "#ffa500",
        "LOW": "#4ecdc4"
    }
    severity_icons = {
        "CRITICAL": "🚨",
        "HIGH": "🔴",
        "MEDIUM": "🟠",
        "LOW": "🟡"
    }
    sev_color = severity_colors.get(severity, "#667eea")
    sev_icon = severity_icons.get(severity, "⚪")
    
    time_ago = datetime.now() - timestamp
    if time_ago.total_seconds() < 60:
        time_str = f"{int(time_ago.total_seconds())}s ago"
    elif time_ago.total_seconds() < 3600:
        time_str = f"{int(time_ago.total_seconds() / 60)}m ago"
    else:
        time_str = f"{int(time_ago.total_seconds() / 3600)}h ago"
    
    # Render card
    st.markdown(
        f"""
        <div class="attack-card" style="border-left-color: {sev_color};">
            <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem;">
                <div>
                    <div style="font-size: 1.3rem; font-weight: 700; margin-bottom: 0.5rem;">
                        {sev_icon} {display_attack_type}
                    </div>
                    {f'<div style="color: rgba(255,255,255,0.6); font-size: 0.9rem; margin-bottom: 0.5rem;">{attack_subtype}</div>' if attack_subtype else ''}
                    <div style="color: rgba(255,255,255,0.5); font-size: 0.85rem;">
                        {timestamp.strftime('%B %d, %Y at %I:%M:%S %p')} • {time_str}
                    </div>
                </div>
                <span class="severity-badge severity-{severity.lower()}" style="background: linear-gradient(135deg, {sev_color} 0%, {sev_color}dd 100%);">
                    {severity}
                </span>
            </div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-top: 1.5rem;">
                <div>
                    <div style="color: rgba(255,255,255,0.6); font-size: 0.85rem; margin-bottom: 0.3rem;">Source IP</div>
                    <div style="font-family: 'Courier New', monospace; font-size: 1.1rem; font-weight: 600; color: #667eea;">{src_ip}</div>
                </div>
                <div>
                    <div style="color: rgba(255,255,255,0.6); font-size: 0.85rem; margin-bottom: 0.3rem;">Protocol</div>
                    <div style="font-size: 1.1rem; font-weight: 600;">{protocol}</div>
                </div>
                {f'<div><div style="color: rgba(255,255,255,0.6); font-size: 0.85rem; margin-bottom: 0.3rem;">Packets</div><div style="font-size: 1.1rem; font-weight: 600;">{packet_count_str}</div></div>' if packet_count_str else ''}
                {f'<div><div style="color: rgba(255,255,255,0.6); font-size: 0.85rem; margin-bottom: 0.3rem;">Rate</div><div style="font-size: 1.1rem; font-weight: 600;">{packet_rate_str}</div></div>' if packet_rate_str else ''}
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


def main():
    """Main dashboard application."""
    
    # Modern Header
    st.markdown(
        '<div class="main-header">🛡️ RealTime Attack Detection Dashboard</div>',
        unsafe_allow_html=True
    )
    
    # Live Indicator
    col_status, col_time = st.columns([1, 4])
    with col_status:
        st.markdown(
            '<div style="text-align: center;"><span class="live-indicator"></span><strong style="color: #4caf50;">LIVE</strong></div>',
            unsafe_allow_html=True
        )
    with col_time:
        st.markdown(
            f'<div style="text-align: right; color: rgba(255,255,255,0.6); font-size: 0.9rem;">{datetime.now().strftime("%B %d, %Y • %I:%M:%S %p")}</div>',
            unsafe_allow_html=True
        )
    
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
    
    # Load fresh data
    dashboard_data.load_attack_history()
    stats = dashboard_data.get_attack_stats()
    
    # Check for new attacks
    current_attack_count = len(dashboard_data.get_all_attacks())
    if current_attack_count > dashboard_data.last_attack_count:
        new_attacks = current_attack_count - dashboard_data.last_attack_count
        st.markdown(
            f'<div class="notification-banner">🆕 <strong>{new_attacks} new attack(s) detected!</strong> Refreshing...</div>',
            unsafe_allow_html=True
        )
        dashboard_data.last_attack_count = current_attack_count
        time.sleep(0.3)
        st.rerun()
    
    # Modern Metrics Cards
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Total Attacks</div>
                <div class="metric-value">{stats["total_attacks"]}</div>
                <div style="color: rgba(255,255,255,0.5); font-size: 0.8rem;">+{stats["today_attacks"]} today</div>
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
                <div style="color: rgba(255,255,255,0.5); font-size: 0.8rem;">attacks</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    
    with col3:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Critical</div>
                <div class="metric-value" style="color: #ff1744;">{stats["critical_severity"]}</div>
                <div style="color: rgba(255,255,255,0.5); font-size: 0.8rem;">severity</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    
    with col4:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">High Severity</div>
                <div class="metric-value" style="color: #ff6b6b;">{stats["high_severity"]}</div>
                <div style="color: rgba(255,255,255,0.5); font-size: 0.8rem;">attacks</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    
    with col5:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Blocked IPs</div>
                <div class="metric-value" style="color: #4caf50;">{stats["blocked_ips"]}</div>
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
                color_map = {"CRITICAL": "#ff1744", "HIGH": "#ff6b6b", "MEDIUM": "#ffa500", "LOW": "#4ecdc4"}
                
                fig_timeline = go.Figure()
                for severity in df_timeline["Severity"].unique():
                    df_sev = df_timeline[df_timeline["Severity"] == severity]
                    fig_timeline.add_trace(go.Scatter(
                        x=df_sev["Time"],
                        y=[severity] * len(df_sev),
                        mode='markers',
                        name=severity,
                        marker=dict(size=15, color=color_map.get(severity, "#667eea"), line=dict(width=2, color='white')),
                        hovertemplate='<b>%{text}</b><br>Time: %{x}<br>Severity: %{y}<extra></extra>',
                        text=[f"{row['Attack Type']} from {row['IP']}" for _, row in df_sev.iterrows()]
                    ))
                
                fig_timeline.update_layout(
                    title="",
                    xaxis_title="Time",
                    yaxis_title="Severity",
                    height=400,
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='white', size=12),
                    legend=dict(bgcolor='rgba(0,0,0,0.5)', bordercolor='rgba(255,255,255,0.1)'),
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
                color_discrete_sequence=['#667eea', '#764ba2', '#f093fb', '#ff6b6b', '#ffa500', '#4ecdc4']
            )
            fig_types.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font=dict(color='white', size=12),
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
                    line=dict(color='#667eea', width=3),
                    fill='tonexty',
                    fillcolor='rgba(102, 126, 234, 0.2)'
                ))
                
                attack_times = [t["Time"] for t in traffic_data if t["Attacks"] > 0]
                attack_packets = [t["Packets/sec"] for t in traffic_data if t["Attacks"] > 0]
                
                if attack_times:
                    fig_traffic.add_trace(go.Scatter(
                        x=attack_times,
                        y=attack_packets,
                        mode='markers',
                        name="Attacks",
                        marker=dict(size=18, color='#ff6b6b', symbol='x', line=dict(width=2, color='white'))
                    ))
                
                fig_traffic.update_layout(
                    height=350,
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='white', size=12),
                    legend=dict(bgcolor='rgba(0,0,0,0.5)'),
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
                f'<div style="color: rgba(255,255,255,0.6); margin-bottom: 1rem; font-size: 0.9rem;">📊 Showing {len(recent_attacks)} of {len(dashboard_data.get_all_attacks())} total</div>',
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
        <div style="text-align: center; color: rgba(255,255,255,0.5); padding: 2rem; margin-top: 3rem;">
            🛡️ RealTime Attack Detection System | Last Updated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        </div>
        """,
        unsafe_allow_html=True
    )
    
    # Auto-refresh
    if auto_refresh:
        time.sleep(refresh_interval)
        dashboard_data.load_attack_history()
        dashboard_data.load_blocked_ips()
        st.rerun()


if __name__ == "__main__":
    main()
