# Complete List of Attack Types Detected

## 🛡️ Total: **6 Main Categories** with **20+ Specific Attack Types**

This system can detect a comprehensive range of cyber attacks. Here's the complete breakdown:

---

## 1. **DDoS / Flooding Attacks** 🌊

### Detector: `DDoSDetector`
**Total Attack Types: 2**

#### 1.1 Ping Flood Attack (ICMP)
- **Type**: ICMP Echo Request Flood
- **Detection**: 10+ ICMP ping packets in 3 seconds
- **Severity**: HIGH
- **Protocol**: ICMP (Type 8)
- **Example**: `ping -f` or rapid ping floods
- **Threshold**: Configurable (default: 10 packets in 3 seconds)

#### 1.2 General Packet Flood (DDoS)
- **Type**: General Packet Flood
- **Detection**: 100+ packets in 5 seconds from same IP
- **Severity**: HIGH
- **Protocol**: Mixed (TCP, UDP, ICMP)
- **Example**: High packet rate from single source
- **Threshold**: Configurable (default: 100 packets in 5 seconds)
- **Features**:
  - Dynamic baseline detection (30-second baseline period)
  - Sliding window analysis
  - Packet rate calculation (PPS)

---

## 2. **Port Scanning Attacks** 🔍

### Detector: `PortScanDetector`
**Total Attack Types: 1**

#### 2.1 Port Scanning Attack
- **Type**: Multiple Port Scanning
- **Detection**: 20+ different ports scanned in 30 seconds
- **Severity**: HIGH
- **Protocol**: TCP/UDP
- **Example**: Nmap scans, port sweeps
- **Threshold**: Configurable (default: 20 ports in 30 seconds)
- **Features**:
  - Tracks unique ports per source IP
  - Time-window based detection
  - Identifies scanning patterns

---

## 3. **Brute Force Login Attacks** 🔐

### Detector: `BruteForceDetector`
**Total Attack Types: 1**

#### 3.1 Brute Force Login Attempt
- **Type**: Multiple Failed Login Attempts
- **Detection**: 5+ failed login attempts in 5 minutes
- **Severity**: HIGH
- **Platforms**: Linux & Windows
- **Example**: SSH brute force, RDP attacks
- **Threshold**: Configurable (default: 5 attempts in 300 seconds)
- **Features**:
  - Monitors Linux auth logs (`/var/log/auth.log`)
  - Monitors Windows Event Log (Security log)
  - Tracks usernames being targeted
  - IP-based tracking

---

## 4. **Intrusion Attempts** 🚨

### Detector: `IntrusionDetector`
**Total Attack Types: 8+**

#### 4.1 Suspicious Command Execution
- **Type**: Malicious Command Detection
- **Detection**: Execution of suspicious commands
- **Severity**: HIGH
- **Commands Detected**:
  1. `rm -rf` - Dangerous file deletion
  2. `chmod 777` - Unsafe permission changes
  3. `wget` - Downloading files
  4. `curl` - Downloading files
  5. `nc` / `netcat` - Network connections
  6. `python -c` - Code execution
  7. `bash -c` - Shell command execution

#### 4.2 Code Injection Patterns
- **Type**: Code Injection Detection
- **Detection**: Suspicious code execution patterns
- **Severity**: CRITICAL
- **Patterns Detected**:
  1. `eval()` - Code evaluation
  2. `base64 -d` - Encoded payloads
  3. `powershell -enc` - Encoded PowerShell
  4. `certutil -decode` - Encoded payloads

#### 4.3 Failed Login Pattern
- **Type**: Multiple Failed Logins
- **Detection**: 3+ failed login attempts
- **Severity**: MEDIUM
- **Platforms**: Linux & Windows

---

## 5. **Cyber-Physical System (CPS) Attacks** 🏭

### Detector: `CPSDetector`
**Total Attack Types: 5**

#### 5.1 Unauthorized PLC Access
- **Type**: Unauthorized Access to Industrial Systems
- **Detection**: Access from non-whitelisted IPs
- **Severity**: HIGH
- **Protocols**: Modbus, DNP3, OPC-UA, IEC 61850, BACnet
- **Threshold**: 3+ unauthorized access attempts

#### 5.2 Command Replay Attack
- **Type**: Command Replay Attack
- **Detection**: Same command repeated within 60 seconds
- **Severity**: HIGH
- **Protocols**: All industrial protocols
- **Example**: Replaying captured control commands

#### 5.3 Protocol Violation
- **Type**: Invalid Protocol Structure
- **Detection**: Malformed industrial protocol packets
- **Severity**: CRITICAL
- **Protocols**: Modbus, DNP3, OPC-UA, IEC 61850, BACnet

#### 5.4 Timing Anomaly
- **Type**: Unusual Command Timing
- **Detection**: Commands sent at abnormal intervals
- **Severity**: MEDIUM
- **Protocols**: All industrial protocols
- **Threshold**: 2x normal timing deviation

#### 5.5 Unauthorized Write Operations
- **Type**: Unauthorized Control Commands
- **Detection**: Write commands from unauthorized sources
- **Severity**: CRITICAL
- **Protocols**: Modbus, DNP3, OPC-UA

**Supported Industrial Protocols:**
- **Modbus TCP/IP** (Port 502)
- **DNP3** (Port 20000)
- **OPC-UA** (Ports 4840, 4841)
- **IEC 61850** (Port 102)
- **BACnet** (Port 47808)

---

## 6. **Modbus-Specific Attacks** ⚙️

### Detector: `ModbusDetector`
**Total Attack Types: 3**

#### 6.1 Modbus Command Injection
- **Type**: Invalid Function Code
- **Detection**: Invalid or malicious Modbus function codes
- **Severity**: CRITICAL
- **Protocol**: Modbus TCP/IP (Port 502)
- **Example**: Function code 255 or out-of-range codes

#### 6.2 Unauthorized Modbus Write
- **Type**: Unauthorized Write Operations
- **Detection**: 5+ write operations from unauthorized IP
- **Severity**: CRITICAL
- **Protocol**: Modbus TCP/IP
- **Write Functions Monitored**:
  - Write Single Coil (5)
  - Write Single Register (6)
  - Write Multiple Coils (15)
  - Write Multiple Registers (16)
  - Write File Record (21)
  - Mask Write Register (22)
  - Read/Write Multiple Registers (23)

#### 6.3 Modbus Protocol Violation
- **Type**: Malformed Modbus Packet
- **Detection**: Invalid packet structure
- **Severity**: HIGH
- **Protocol**: Modbus TCP/IP

---

## 📊 Summary Statistics

### By Category:
- **Network Attacks**: 3 types (DDoS, Ping Flood, Port Scan)
- **Authentication Attacks**: 1 type (Brute Force)
- **Intrusion Attacks**: 8+ types (Suspicious commands, code injection)
- **Industrial/CPS Attacks**: 8 types (CPS + Modbus specific)
- **Total**: **20+ specific attack types**

### By Severity:
- **CRITICAL**: 6 attack types
- **HIGH**: 12+ attack types
- **MEDIUM**: 2+ attack types

### By Protocol:
- **ICMP**: Ping Flood
- **TCP**: Port Scan, DDoS, Modbus, DNP3, OPC-UA, IEC 61850
- **UDP**: Port Scan, DDoS, BACnet
- **Application Layer**: Brute Force, Intrusion (log-based)

---

## 🔧 Detection Capabilities

### Real-Time Monitoring:
✅ **Network Packet Analysis** - Real-time packet capture and analysis
✅ **Log File Monitoring** - Linux auth logs & Windows Event Logs
✅ **Process Monitoring** - CPU and network usage tracking
✅ **Industrial Protocol Parsing** - Deep packet inspection for industrial protocols

### Detection Methods:
✅ **Threshold-Based** - Configurable thresholds for each attack type
✅ **Baseline-Based** - Dynamic baseline for DDoS detection
✅ **Pattern Matching** - Regex patterns for suspicious commands
✅ **Anomaly Detection** - Timing anomalies, protocol violations
✅ **Signature-Based** - Command replay detection

### Alert Systems:
✅ **Desktop Notifications** - Windows toast notifications
✅ **Telegram Alerts** - Real-time Telegram bot notifications
✅ **Terminal Display** - Beautiful formatted attack alerts
✅ **Web Dashboard** - Real-time web-based dashboard
✅ **Log File** - Detailed attack logging

---

## 📝 Configuration

All detection thresholds and settings are configurable in `config.json`:

```json
{
  "detection": {
    "ddos": {
      "packet_threshold": 100,
      "icmp_threshold": 10,
      "time_window_seconds": 5
    },
    "port_scan": {
      "port_threshold": 20,
      "time_window_seconds": 30
    },
    "brute_force": {
      "failed_attempts_threshold": 5,
      "time_window_seconds": 300
    },
    "intrusion": {
      "suspicious_commands": [...],
      "failed_login_threshold": 3
    },
    "cps": {
      "unauthorized_threshold": 3,
      "replay_window_seconds": 60
    },
    "modbus": {
      "write_threshold": 5
    }
  }
}
```

---

## 🎯 Quick Reference

| Attack Category | Detector | Attack Types | Severity |
|----------------|----------|--------------|----------|
| DDoS/Flooding | DDoSDetector | 2 | HIGH |
| Port Scanning | PortScanDetector | 1 | HIGH |
| Brute Force | BruteForceDetector | 1 | HIGH |
| Intrusion | IntrusionDetector | 8+ | HIGH/CRITICAL |
| CPS Attacks | CPSDetector | 5 | HIGH/CRITICAL |
| Modbus Attacks | ModbusDetector | 3 | CRITICAL |
| **TOTAL** | **6 Detectors** | **20+** | **Various** |

---

## 🚀 Active Defense (IPS)

The system also includes **Active Defense** capabilities:

✅ **Auto-Block IPs** - Automatically block attacking IPs
✅ **Auto-Kill Processes** - Terminate suspicious processes
✅ **Auto-Lock Accounts** - Lock accounts after brute force
✅ **Auto-Disable Interface** - Disable network interface (optional)

---

**This system provides comprehensive protection against a wide range of cyber attacks!** 🛡️

