# 🛡️ Real-Time Attack Detection System for Cyber-Physical Systems (CPS)

## Complete Project Documentation

---

## 📋 Table of Contents

1. [Project Overview](#project-overview)
2. [Key Features](#key-features)
3. [System Architecture](#system-architecture)
4. [Attack Detection Capabilities](#attack-detection-capabilities)
5. [Components & Modules](#components--modules)
6. [Technologies Used](#technologies-used)
7. [Installation & Setup](#installation--setup)
8. [Usage Guide](#usage-guide)
9. [Configuration](#configuration)
10. [Web Dashboard](#web-dashboard)
11. [Active Defense (IPS)](#active-defense-ips)
12. [Alert Systems](#alert-systems)
13. [File Structure](#file-structure)
14. [Performance & Security](#performance--security)
15. [Troubleshooting](#troubleshooting)

---

## 🎯 Project Overview

**Real-Time Attack Detection System for CPS** is a comprehensive cybersecurity monitoring and detection platform designed to protect both traditional IT systems and Cyber-Physical Systems (CPS) from various cyber attacks. The system provides real-time monitoring, detection, alerting, and automated response capabilities.

### Purpose
- **Real-time threat detection** across network, system logs, and processes
- **Protection of industrial control systems** (ICS/SCADA)
- **Automated incident response** with active defense capabilities
- **Comprehensive monitoring** with modern web dashboard
- **Multi-platform support** (Windows, Linux, macOS)

### Target Users
- **Security professionals** monitoring network security
- **Industrial system administrators** protecting CPS infrastructure
- **IT administrators** securing enterprise networks
- **Security researchers** studying attack patterns
- **Educational institutions** teaching cybersecurity

---

## ✨ Key Features

### 1. **Real-Time Network Monitoring**
- ✅ Live packet capture and analysis
- ✅ Protocol-specific detection (TCP, UDP, ICMP)
- ✅ Industrial protocol monitoring (Modbus, DNP3, OPC-UA, IEC 61850, BACnet)
- ✅ Packet rate analysis and traffic visualization
- ✅ Source IP tracking and analysis

### 2. **Comprehensive Attack Detection**
- ✅ **6 Main Categories** of attack detection
- ✅ **20+ Specific Attack Types** identified
- ✅ Dynamic baseline detection for DDoS
- ✅ Pattern matching for intrusion attempts
- ✅ Anomaly detection for industrial protocols

### 3. **Modern Web Dashboard**
- ✅ **Glassmorphism UI** with smooth animations
- ✅ Real-time attack visualization
- ✅ Interactive charts and graphs
- ✅ Attack timeline and statistics
- ✅ System metrics monitoring
- ✅ Auto-refresh capabilities

### 4. **Active Defense (IPS)**
- ✅ Automatic IP blocking
- ✅ Process termination
- ✅ Account locking
- ✅ Network interface management
- ✅ Service restart capabilities

### 5. **Multi-Channel Alerting**
- ✅ Desktop notifications (Windows, Linux, macOS)
- ✅ Telegram bot integration
- ✅ Terminal output with formatted alerts
- ✅ Log file recording
- ✅ Web dashboard notifications

### 6. **Cross-Platform Support**
- ✅ Windows (with Npcap)
- ✅ Linux (with libpcap)
- ✅ macOS (with libpcap)
- ✅ Platform-specific optimizations

---

## 🏗️ System Architecture

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Attack Detection System                   │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Network    │  │     Log      │  │   Process    │      │
│  │   Sniffer    │  │   Monitor    │  │   Monitor    │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                  │                  │              │
│         └──────────────────┼──────────────────┘             │
│                            │                                 │
│         ┌──────────────────▼──────────────────┐             │
│         │      Detection Engine                │             │
│         │  ┌──────────────────────────────┐   │             │
│         │  │  DDoS Detector               │   │             │
│         │  │  Port Scan Detector          │   │             │
│         │  │  Brute Force Detector        │   │             │
│         │  │  Intrusion Detector          │   │             │
│         │  │  CPS Detector                │   │             │
│         │  │  Modbus Detector             │   │             │
│         │  └──────────────────────────────┘   │             │
│         └──────────────────┬───────────────────┘             │
│                          │                                   │
│         ┌────────────────▼───────────────────┐             │
│         │      Alert & Response System        │             │
│         │  ┌──────────┐  ┌──────────┐       │             │
│         │  │ Desktop  │  │Telegram  │       │             │
│         │  │  Alert   │  │  Alert   │       │             │
│         │  └──────────┘  └──────────┘       │             │
│         │  ┌──────────────────────────┐     │             │
│         │  │   Active Defense (IPS)    │     │             │
│         │  └──────────────────────────┘     │             │
│         └──────────────────┬─────────────────┘             │
│                            │                               │
│         ┌──────────────────▼─────────────────┐            │
│         │      Web Dashboard                  │            │
│         │  (Real-time visualization)          │            │
│         └─────────────────────────────────────┘            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Monitoring Layer**: Network sniffer, log monitor, and process monitor collect data
2. **Detection Layer**: Detectors analyze data for attack patterns
3. **Alert Layer**: Alerts are sent to multiple channels
4. **Response Layer**: Active defense takes automated actions
5. **Visualization Layer**: Web dashboard displays real-time information

---

## 🚨 Attack Detection Capabilities

### Total: **6 Main Categories** with **20+ Specific Attack Types**

#### 1. **DDoS / Flooding Attacks** (2 types)
- **Ping Flood Attack (ICMP)**: Detects ICMP echo request floods
  - Threshold: 10+ ICMP packets in 3 seconds
  - Severity: HIGH
  - Protocol: ICMP (Type 8)
  
- **General Packet Flood (DDoS)**: Detects high packet rates
  - Threshold: 100+ packets in 5 seconds
  - Severity: HIGH
  - Protocols: TCP, UDP, ICMP
  - Features: Dynamic baseline, sliding window analysis

#### 2. **Port Scanning Attacks** (1 type)
- **Port Scanning Attack**: Detects Nmap-style port scans
  - Threshold: 20+ different ports in 30 seconds
  - Severity: HIGH
  - Protocols: TCP, UDP
  - Features: Unique port tracking, pattern identification

#### 3. **Brute Force Login Attacks** (1 type)
- **Brute Force Login Attempt**: Detects multiple failed logins
  - Threshold: 5+ failed attempts in 5 minutes
  - Severity: HIGH
  - Platforms: Linux & Windows
  - Features: Username tracking, IP-based analysis

#### 4. **Intrusion Attempts** (8+ types)
- **Suspicious Command Execution**: Detects malicious commands
  - Commands: `rm -rf`, `chmod 777`, `wget`, `curl`, `netcat`, `python -c`, `bash -c`
  - Severity: HIGH
  
- **Code Injection Patterns**: Detects code execution attempts
  - Patterns: `eval()`, `base64 -d`, `powershell -enc`, `certutil -decode`
  - Severity: CRITICAL
  
- **Failed Login Patterns**: Detects intrusion attempts
  - Threshold: 3+ failed logins
  - Severity: MEDIUM

#### 5. **Cyber-Physical System (CPS) Attacks** (5 types)
- **Unauthorized PLC Access**: Non-whitelisted IP access
- **Command Replay Attack**: Repeated commands within 60 seconds
- **Protocol Violation**: Invalid protocol structure
- **Timing Anomaly**: Unusual command timing patterns
- **Unauthorized Write Operations**: Write commands from unauthorized sources

**Supported Industrial Protocols:**
- Modbus TCP/IP (Port 502)
- DNP3 (Port 20000)
- OPC-UA (Ports 4840, 4841)
- IEC 61850 (Port 102)
- BACnet (Port 47808)

#### 6. **Modbus-Specific Attacks** (3 types)
- **Modbus Command Injection**: Invalid function codes
- **Unauthorized Modbus Write**: Unauthorized write operations
- **Modbus Protocol Violation**: Malformed Modbus packets

---

## 🧩 Components & Modules

### Core Modules

#### 1. **Monitoring Modules** (`monitor/`)

**`network_sniffer.py`**
- Real-time packet capture using Scapy
- Protocol identification (TCP, UDP, ICMP)
- Packet statistics tracking
- Source IP analysis
- Industrial protocol detection

**`log_monitor.py`**
- Linux auth log monitoring (`/var/log/auth.log`)
- Windows Event Log monitoring (Security log)
- Real-time log file watching
- Pattern matching for security events
- Cross-platform support

**`process_monitor.py`**
- CPU usage monitoring per process
- Network I/O tracking
- Process command line analysis
- Resource threshold detection
- Suspicious process identification

**`industrial_protocol_monitor.py`**
- Industrial protocol parsing
- Modbus, DNP3, OPC-UA, IEC 61850, BACnet support
- Protocol-specific command extraction
- Timing pattern analysis

#### 2. **Detection Modules** (`detectors/`)

**`ddos_detector.py`**
- Packet rate analysis
- Dynamic baseline calculation
- Sliding window detection
- ICMP-specific ping flood detection
- Threshold-based alerting

**`portscan_detector.py`**
- Port scanning pattern detection
- Unique port tracking per IP
- Time-window analysis
- Scanning pattern identification

**`brute_force_detector.py`**
- Failed login attempt tracking
- Username targeting detection
- IP-based analysis
- Cross-platform log parsing

**`intrusion_detector.py`**
- Suspicious command detection
- Code injection pattern matching
- Failed login pattern analysis
- Regex-based pattern matching

**`cps_detector.py`**
- CPS attack detection
- Command replay detection
- Protocol violation detection
- Timing anomaly detection
- Unauthorized access detection

**`modbus_detector.py`**
- Modbus-specific attack detection
- Function code validation
- Write operation monitoring
- Protocol structure validation

#### 3. **Alert Modules** (`alerts/`)

**`desktop_alert.py`**
- Cross-platform desktop notifications
- Windows toast notifications
- Linux desktop notifications
- macOS notifications
- Attack detail formatting

**`telegram_alert.py`**
- Telegram bot integration
- Markdown-formatted messages
- Attack detail transmission
- Configurable bot token and chat ID

#### 4. **Active Defense** (`auto_response/`)

**`active_defense.py`**
- Automatic IP blocking
- Process termination
- Account locking
- Network interface management
- Service restart capabilities
- Whitelist management

#### 5. **Utilities** (`utils/`)

**`helper.py`**
- Configuration loading
- Logging setup
- IP validation
- Private IP detection
- Common utility functions

#### 6. **Web Dashboard** (`dashboard/`)

**`app.py`**
- Modern Streamlit-based dashboard
- Glassmorphism UI design
- Real-time attack visualization
- Interactive charts (Plotly)
- System metrics display
- Attack filtering and search

#### 7. **Main Entry Point**

**`main.py`**
- System orchestration
- Component initialization
- Attack handling
- Signal management
- CLI argument parsing
- Statistics tracking

---

## 💻 Technologies Used

### Core Technologies
- **Python 3.7+**: Main programming language
- **Scapy 2.5.0+**: Network packet capture and analysis
- **Streamlit 1.28.0+**: Web dashboard framework
- **Plotly 5.17.0+**: Interactive data visualization
- **Pandas 2.0.0+**: Data manipulation and analysis

### Supporting Libraries
- **psutil 5.9.0+**: System and process monitoring
- **plyer 2.1.0+**: Cross-platform desktop notifications
- **watchdog 3.0.0+**: File system event monitoring
- **requests 2.31.0+**: HTTP requests (Telegram API)
- **scikit-learn 1.3.0+**: Machine learning capabilities
- **numpy 1.24.0+**: Numerical computing
- **pywin32 305+**: Windows-specific functionality

### System Requirements
- **Windows**: Npcap or WinPcap for packet capture
- **Linux**: libpcap-dev for packet capture
- **macOS**: libpcap for packet capture
- **Administrator/Root privileges**: Required for network monitoring

---

## 📦 Installation & Setup

### Prerequisites

1. **Python 3.7 or higher**
2. **Administrator/Root privileges**
3. **Network capture library**:
   - Windows: Install [Npcap](https://npcap.com/)
   - Linux: `sudo apt-get install libpcap-dev` (Ubuntu/Debian)
   - macOS: `brew install libpcap`

### Installation Steps

1. **Clone or download the repository**
   ```bash
   git clone https://github.com/talharabani/Attack-detection-system-for-CPS.git
   cd Attack-detection-system-for-CPS
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Windows-specific setup** (if needed)
   ```bash
   pip install pywin32
   ```

4. **Configure the system**
   - Edit `config.json` to customize detection thresholds
   - Configure Telegram alerts (optional)
   - Set up IP whitelists

5. **Run the system**
   ```bash
   # Run as Administrator (Windows) or with sudo (Linux)
   python main.py -v
   ```

### Telegram Setup (Optional)

1. Create a Telegram bot:
   - Message [@BotFather](https://t.me/botfather) on Telegram
   - Use `/newbot` command
   - Get your bot token

2. Get your chat ID:
   - Message [@userinfobot](https://t.me/userinfobot)
   - Get your chat ID

3. Update `config.json`:
   ```json
   {
     "alerts": {
       "telegram": {
         "enabled": true,
         "bot_token": "YOUR_BOT_TOKEN",
         "chat_id": "YOUR_CHAT_ID"
       }
     }
   }
   ```

---

## 🚀 Usage Guide

### Basic Usage

**Start the detection system:**
```bash
python main.py
```

**Start with verbose logging:**
```bash
python main.py -v
```

**Use custom configuration:**
```bash
python main.py -c /path/to/config.json
```

**Test alert systems:**
```bash
python main.py --test-alerts
```

### Web Dashboard

**Start the dashboard:**
```bash
python run_dashboard.py
```

Or directly:
```bash
streamlit run dashboard/app.py
```

**Access the dashboard:**
- Open browser to: `http://localhost:8501`
- Default port: 8501 (configurable)

### Running as a Service

#### Linux (systemd)

Create `/etc/systemd/system/attack-detection.service`:
```ini
[Unit]
Description=RealTime Attack Detection System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/path/to/RealTimeAttackDetection
ExecStart=/usr/bin/python3 /path/to/RealTimeAttackDetection/main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable attack-detection.service
sudo systemctl start attack-detection.service
```

#### Windows (Task Scheduler)

1. Open Task Scheduler
2. Create new task
3. Set trigger: "At startup" or "At log on"
4. Set action: Start `python.exe` with argument `main.py`
5. Enable "Run with highest privileges"

---

## ⚙️ Configuration

### Configuration File: `config.json`

#### Detection Settings

**DDoS Detection:**
```json
{
  "detection": {
    "ddos": {
      "enabled": true,
      "packet_threshold": 100,
      "time_window_seconds": 5,
      "icmp_threshold": 10,
      "icmp_time_window_seconds": 3,
      "baseline_period_seconds": 30,
      "dynamic_threshold_multiplier": 10,
      "min_packet_size_bytes": 64,
      "ignore_localhost": false,
      "ignore_dns_traffic": true,
      "ip_whitelist": []
    }
  }
}
```

**Port Scan Detection:**
```json
{
  "port_scan": {
    "enabled": true,
    "port_threshold": 20,
    "time_window_seconds": 30,
    "ip_whitelist": []
  }
}
```

**Brute Force Detection:**
```json
{
  "brute_force": {
    "enabled": true,
    "failed_attempts_threshold": 5,
    "time_window_seconds": 300,
    "ip_whitelist": []
  }
}
```

**Intrusion Detection:**
```json
{
  "intrusion": {
    "enabled": true,
    "suspicious_commands": [
      "rm -rf",
      "chmod 777",
      "wget",
      "curl",
      "nc ",
      "netcat",
      "python -c",
      "bash -c"
    ],
    "failed_login_threshold": 3
  }
}
```

**CPS Detection:**
```json
{
  "cps": {
    "enabled": true,
    "enabled_protocols": ["modbus", "dnp3", "opcua", "iec61850", "bacnet"],
    "unauthorized_threshold": 3,
    "replay_window_seconds": 60,
    "timing_anomaly_threshold": 2.0,
    "allowed_ips": [],
    "plc_addresses": []
  }
}
```

#### Alert Settings

```json
{
  "alerts": {
    "desktop": {
      "enabled": true
    },
    "telegram": {
      "enabled": false,
      "bot_token": "YOUR_TELEGRAM_BOT_TOKEN",
      "chat_id": "YOUR_CHAT_ID"
    }
  }
}
```

#### Active Defense Settings

```json
{
  "auto_response": {
    "enabled": true,
    "auto_block_ips": true,
    "auto_kill_processes": true,
    "auto_disable_interface": false,
    "auto_lock_accounts": true,
    "auto_restart_services": false,
    "block_duration_minutes": 60,
    "whitelist_ips": [],
    "protected_services": ["winlogon", "csrss", "lsass"]
  }
}
```

---

## 📊 Web Dashboard

### Features

1. **Real-Time Metrics**
   - Total attacks detected
   - Today's attacks
   - Critical severity count
   - High severity count
   - Blocked IPs count

2. **Visualizations**
   - Attack timeline (interactive scatter plot)
   - Attack types distribution (pie chart)
   - Network traffic graph (line chart with attack markers)
   - System metrics (CPU, Memory, Disk)

3. **Attack Management**
   - Recent attacks display
   - Filter by severity
   - Sort by time or severity
   - Search functionality
   - View all attacks

4. **Modern UI**
   - Glassmorphism design
   - Smooth animations
   - Color-coded severity badges
   - Responsive layout
   - Auto-refresh (configurable)

### Dashboard Access

- **URL**: `http://localhost:8501`
- **Port**: Configurable in `config.json`
- **Auto-refresh**: Every 3 seconds (default)
- **Features**: Real-time updates, filtering, search

---

## 🛡️ Active Defense (IPS)

### Capabilities

1. **Automatic IP Blocking**
   - Blocks attacking IPs automatically
   - Configurable block duration (default: 60 minutes)
   - Whitelist support
   - Platform-specific implementation

2. **Process Termination**
   - Kills suspicious processes
   - Protects critical system processes
   - Configurable protected services list

3. **Account Locking**
   - Locks accounts after brute force attacks
   - Prevents further login attempts
   - Platform-specific implementation

4. **Network Interface Management**
   - Can disable network interfaces (optional)
   - Emergency response capability

5. **Service Management**
   - Can restart services (optional)
   - Service protection list

### Configuration

Enable/disable features in `config.json`:
```json
{
  "auto_response": {
    "enabled": true,
    "auto_block_ips": true,
    "auto_kill_processes": true,
    "auto_lock_accounts": true
  }
}
```

---

## 📁 File Structure

```
RealTimeAttackDetection/
├── main.py                          # Main entry point
├── run_dashboard.py                 # Dashboard launcher
├── test_packet_capture.py           # Packet capture test script
├── config.json                      # Configuration file
├── requirements.txt                 # Python dependencies
├── .gitignore                       # Git ignore file
│
├── monitor/                         # Monitoring modules
│   ├── __init__.py
│   ├── network_sniffer.py          # Network packet capture
│   ├── log_monitor.py              # Log file monitoring
│   ├── process_monitor.py          # Process monitoring
│   └── industrial_protocol_monitor.py  # Industrial protocol monitoring
│
├── detectors/                       # Attack detection modules
│   ├── __init__.py
│   ├── ddos_detector.py            # DDoS/flooding detection
│   ├── portscan_detector.py        # Port scan detection
│   ├── brute_force_detector.py     # Brute force detection
│   ├── intrusion_detector.py      # Intrusion detection
│   ├── cps_detector.py             # CPS attack detection
│   └── modbus_detector.py          # Modbus-specific detection
│
├── alerts/                            # Alert systems
│   ├── __init__.py
│   ├── desktop_alert.py             # Desktop notifications
│   └── telegram_alert.py           # Telegram alerts
│
├── auto_response/                    # Active defense
│   ├── __init__.py
│   └── active_defense.py           # IPS functionality
│
├── dashboard/                        # Web dashboard
│   ├── __init__.py
│   └── app.py                      # Streamlit dashboard
│
├── utils/                            # Utility functions
│   ├── __init__.py
│   └── helper.py                   # Common utilities
│
└── Documentation/                    # Documentation files
    ├── README.md
    ├── ATTACK_TYPES_DETECTED.md
    ├── DASHBOARD_REDESIGN.md
    ├── DASHBOARD_WEB_VIEW_GUIDE.md
    ├── PING_FLOOD_DIAGNOSTICS_FIX.md
    ├── CPS_DETECTION.md
    ├── ACTIVE_DEFENSE.md
    └── ... (other documentation files)
```

---

## 🔒 Performance & Security

### Performance Considerations

- **Network Sniffing**: CPU-intensive on high-traffic networks
- **Process Monitoring**: Configurable interval (default: 5 seconds)
- **Log Monitoring**: Uses file system events for efficiency
- **Memory Management**: Sliding window analysis limits memory usage
- **Attack History**: Limited to last 1000 attacks

### Security Considerations

1. **Privileges**: Run with Administrator/Root privileges
2. **Configuration Security**: Protect `config.json`, especially Telegram tokens
3. **IP Whitelisting**: Add trusted IPs to reduce false positives
4. **Log Rotation**: Configure log rotation to prevent disk space issues
5. **Network Security**: Monitor only authorized networks
6. **Access Control**: Restrict dashboard access if needed

---

## 🐛 Troubleshooting

### Network Sniffer Issues

**Problem**: No packets being captured

**Solutions**:
- **Windows**: 
  - Run as Administrator
  - Install Npcap from https://npcap.com/
  - Check Windows Firewall settings
  
- **Linux/macOS**:
  - Run with `sudo`
  - Install libpcap: `sudo apt-get install libpcap-dev`
  - Check network interface permissions

### Log Monitoring Issues

**Problem**: Logs not being monitored

**Solutions**:
- **Linux**: 
  - Check file permissions: `sudo chmod 644 /var/log/auth.log`
  - Verify log file paths in `config.json`
  
- **Windows**:
  - Run as Administrator
  - Ensure `pywin32` is installed
  - Check Event Viewer permissions

### Dashboard Not Loading

**Problem**: Dashboard won't start

**Solutions**:
- Install Streamlit: `pip install streamlit plotly pandas`
- Check port availability (default: 8501)
- Verify firewall settings
- Check for port conflicts

### Telegram Alerts Not Working

**Problem**: Telegram alerts not sending

**Solutions**:
- Verify bot token is correct
- Check chat ID is correct
- Ensure internet connectivity
- Check Telegram API status
- Verify `enabled: true` in config

---

## 📈 Statistics & Metrics

### System Capabilities

- **Attack Types Detected**: 20+
- **Detection Modules**: 6
- **Monitoring Modules**: 4
- **Alert Channels**: 3 (Desktop, Telegram, Terminal)
- **Industrial Protocols**: 5 (Modbus, DNP3, OPC-UA, IEC 61850, BACnet)
- **Platforms Supported**: 3 (Windows, Linux, macOS)

### Performance Metrics

- **Packet Processing**: Real-time
- **Detection Latency**: < 1 second
- **Memory Usage**: Optimized with sliding windows
- **CPU Usage**: Moderate (depends on traffic)
- **Dashboard Refresh**: 3 seconds (configurable)

---

## 📚 Additional Documentation

- **ATTACK_TYPES_DETECTED.md**: Complete list of detected attack types
- **DASHBOARD_REDESIGN.md**: Dashboard UI documentation
- **DASHBOARD_WEB_VIEW_GUIDE.md**: Dashboard usage guide
- **CPS_DETECTION.md**: CPS attack detection details
- **ACTIVE_DEFENSE.md**: Active defense capabilities
- **HOW_TO_TEST_PING_FLOOD.md**: Testing guide for ping floods
- **TESTING_GUIDE.md**: General testing procedures

---

## 🎓 Educational Use

This project is suitable for:
- **Cybersecurity courses**: Attack detection and prevention
- **Network security training**: Packet analysis and monitoring
- **Industrial security**: CPS/SCADA security
- **Research**: Attack pattern analysis
- **Security awareness**: Understanding cyber threats

---

## ⚠️ Legal & Ethical Considerations

### Important Notes

1. **Authorization Required**: Only monitor networks you own or have explicit permission to monitor
2. **Legal Compliance**: Ensure compliance with local laws and regulations
3. **Ethical Use**: Use responsibly and ethically
4. **Privacy**: Respect privacy of network users
5. **Educational Purpose**: Suitable for educational and authorized security monitoring

### Disclaimer

This tool is for **security monitoring and educational purposes only**. Users are responsible for:
- Ensuring compliance with local laws
- Obtaining proper authorization
- Using the tool ethically
- Not using for malicious purposes

---

## 🤝 Contributing

### Contribution Guidelines

1. Follow PEP 8 style guidelines
2. Add comments and docstrings
3. Test on multiple platforms
4. Update documentation
5. Submit pull requests with clear descriptions

### Code Quality

- **Type Hints**: Used where appropriate
- **Docstrings**: Comprehensive documentation
- **Error Handling**: Robust error handling
- **Logging**: Comprehensive logging system
- **Testing**: Test scripts included

---

## 📞 Support & Resources

### Repository
- **GitHub**: https://github.com/talharabani/Attack-detection-system-for-CPS
- **Issues**: Report bugs and request features
- **Documentation**: Comprehensive documentation included

### Dependencies
- **Scapy**: https://scapy.net/
- **Streamlit**: https://streamlit.io/
- **Plotly**: https://plotly.com/
- **Telegram Bot API**: https://core.telegram.org/bots/api

---

## 🎉 Summary

**Real-Time Attack Detection System for CPS** is a comprehensive, production-ready cybersecurity platform that provides:

✅ **Real-time threat detection** across multiple attack vectors  
✅ **Industrial system protection** for CPS/SCADA networks  
✅ **Modern web dashboard** with beautiful UI  
✅ **Automated response** with active defense capabilities  
✅ **Multi-platform support** for Windows, Linux, and macOS  
✅ **Comprehensive monitoring** of network, logs, and processes  
✅ **20+ attack types** detected in real-time  
✅ **Professional-grade** security monitoring solution  

---

**Version**: 1.0  
**Last Updated**: 2025  
**License**: Educational and Security Monitoring Use  
**Status**: Production Ready  

---

*This documentation provides a complete overview of the Real-Time Attack Detection System for CPS. For specific implementation details, refer to the source code and individual module documentation.*

