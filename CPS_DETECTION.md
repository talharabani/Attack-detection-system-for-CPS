# Cyber-Physical System (CPS) Attack Detection

## Overview

The system now includes comprehensive **Cyber-Physical System (CPS) attack detection** capabilities. This module monitors industrial control systems, SCADA networks, and industrial protocols to detect attacks on critical infrastructure.

## Supported Industrial Protocols

### 1. Modbus TCP/IP (Port 502)
- **Read Operations**: Coils, Discrete Inputs, Holding Registers, Input Registers
- **Write Operations**: Single/Multiple Coils, Single/Multiple Registers
- **Attack Detection**: Command injection, unauthorized writes, invalid function codes

### 2. DNP3 (Port 20000)
- **Control Operations**: Direct Operate, Select and Operate
- **Attack Detection**: Unauthorized commands, protocol violations

### 3. OPC-UA (Ports 4840, 4841)
- **Communication**: Secure Channel, Session messages
- **Attack Detection**: Unauthorized access, data manipulation

### 4. IEC 61850 (Port 102)
- **MMS Protocol**: Manufacturing Message Specification
- **Attack Detection**: Protocol violations, unauthorized access

### 5. BACnet (Port 47808)
- **Building Automation**: HVAC, lighting control
- **Attack Detection**: Unauthorized building control commands

## Detected Attack Types

### 1. Modbus Command Injection
- **Detection**: Invalid function codes, malformed packets
- **Severity**: CRITICAL
- **Example**: Attacker sends invalid Modbus function code to crash PLC

### 2. Unauthorized PLC Access
- **Detection**: Access from non-whitelisted IPs
- **Severity**: HIGH
- **Example**: External IP attempting to connect to PLC

### 3. Unauthorized Write Operations
- **Detection**: Write commands from unauthorized sources
- **Severity**: CRITICAL
- **Example**: Unauthorized write to control register

### 4. Command Replay Attacks
- **Detection**: Same command repeated within replay window
- **Severity**: HIGH
- **Example**: Attacker replays captured control commands

### 5. Protocol Violations
- **Detection**: Invalid protocol structure, malformed packets
- **Severity**: HIGH
- **Example**: DNP3 packet with invalid control field

### 6. Timing Anomalies
- **Detection**: Unusual timing between commands
- **Severity**: MEDIUM
- **Example**: Commands sent too quickly or too slowly

### 7. Unusual Read/Write Patterns
- **Detection**: Excessive write operations
- **Severity**: HIGH
- **Example**: Rapid write operations to multiple addresses

### 8. SCADA Protocol Manipulation
- **Detection**: Unauthorized protocol modifications
- **Severity**: CRITICAL
- **Example**: Manipulation of control system communications

### 9. Control System Reconnaissance
- **Detection**: Scanning of industrial ports
- **Severity**: MEDIUM
- **Example**: Port scanning on Modbus, DNP3 ports

## Configuration

### config.json Settings

```json
{
  "detection": {
    "cps": {
      "enabled": true,
      "enabled_protocols": ["modbus", "dnp3", "opcua", "iec61850", "bacnet"],
      "unauthorized_threshold": 3,
      "replay_window_seconds": 60,
      "timing_anomaly_threshold": 2.0,
      "allowed_ips": ["192.168.1.100", "10.0.0.5"],
      "plc_addresses": ["192.168.1.50", "10.0.0.10"]
    },
    "modbus": {
      "enabled": true,
      "write_threshold": 5,
      "allowed_ips": ["192.168.1.100"],
      "plc_addresses": ["192.168.1.50"]
    },
    "scada": {
      "enabled": true,
      "reconnaissance_threshold": 10,
      "command_anomaly_threshold": 5,
      "allowed_ips": [],
      "hmi_addresses": []
    }
  }
}
```

### Configuration Parameters

#### CPS Detector
- **enabled**: Enable/disable CPS detection
- **enabled_protocols**: List of protocols to monitor
- **unauthorized_threshold**: Number of unauthorized attempts before alert
- **replay_window_seconds**: Time window for replay detection
- **timing_anomaly_threshold**: Multiplier for timing anomaly detection
- **allowed_ips**: Whitelist of authorized IP addresses
- **plc_addresses**: Known PLC IP addresses

#### Modbus Detector
- **enabled**: Enable/disable Modbus-specific detection
- **write_threshold**: Number of write operations before alert
- **allowed_ips**: Authorized Modbus client IPs
- **plc_addresses**: Known Modbus PLC addresses

#### SCADA Detector
- **enabled**: Enable/disable SCADA detection
- **reconnaissance_threshold**: Port scan threshold
- **command_anomaly_threshold**: Anomalous command threshold
- **allowed_ips**: Authorized HMI/SCADA IPs
- **hmi_addresses**: Known HMI addresses

## How It Works

### 1. Protocol Detection
- Network sniffer captures packets on industrial protocol ports
- Industrial protocol monitor identifies protocol type
- Protocol-specific parsers extract command information

### 2. Attack Detection
- **Unauthorized Access**: Checks source IP against whitelist
- **Command Replay**: Tracks command signatures and timing
- **Protocol Violations**: Validates protocol structure
- **Timing Anomalies**: Analyzes command timing patterns
- **Read/Write Patterns**: Monitors operation frequencies

### 3. Alert Generation
- Attack information formatted for alerts
- Desktop notifications sent
- Telegram alerts (if configured)
- Detailed logging with attack context

## Example Attack Scenarios

### Scenario 1: Modbus Command Injection
```
Attacker sends: Invalid function code (255) to PLC
Detection: Protocol violation detected
Alert: "Modbus Command Injection from 192.168.1.200"
```

### Scenario 2: Unauthorized PLC Write
```
Attacker sends: Write command from unauthorized IP
Detection: 5+ write operations from non-whitelisted IP
Alert: "Unauthorized Modbus Write from 10.0.0.50"
```

### Scenario 3: Command Replay
```
Attacker replays: Previously captured write command
Detection: Same command signature within 60 seconds
Alert: "Command Replay Attack from 192.168.1.100"
```

### Scenario 4: Timing Anomaly
```
Attacker sends: Commands at unusual intervals
Detection: Timing differs >2x from baseline
Alert: "Timing Anomaly detected from 10.0.0.5"
```

## Setup Instructions

### 1. Configure Allowed IPs
Edit `config.json` and add authorized IPs:
```json
{
  "detection": {
    "cps": {
      "allowed_ips": ["192.168.1.100", "10.0.0.5"]
    }
  }
}
```

### 2. Configure PLC Addresses
Add known PLC/HMI addresses:
```json
{
  "detection": {
    "cps": {
      "plc_addresses": ["192.168.1.50", "10.0.0.10"]
    }
  }
}
```

### 3. Enable Protocols
Select which protocols to monitor:
```json
{
  "detection": {
    "cps": {
      "enabled_protocols": ["modbus", "dnp3", "opcua"]
    }
  }
}
```

### 4. Run the System
```bash
python main.py
```

## Alert Examples

### Desktop Notification
```
🚨 CPS Attack Detected
Severity: CRITICAL
Source IP: 192.168.1.200
Type: Modbus Command Injection
Protocol: modbus
function_code: 255
```

### Telegram Alert
```
🚨 CPS Attack Detected

Severity: CRITICAL
Source IP: 192.168.1.200
Attack Type: Modbus Command Injection
Protocol: modbus
Function Code: 255
Invalid Commands: 3
```

## Testing CPS Detection

### Test 1: Modbus Port Scan
```bash
# Scan Modbus port (should trigger reconnaissance detection)
nmap -p 502 <target_ip>
```

### Test 2: Modbus Command Injection
```python
# Send invalid Modbus function code
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('<plc_ip>', 502))
# Send invalid function code
sock.send(b'\x00\x01\x00\x00\x00\x06\x01\xFF\x00\x00\x00\x01')
```

### Test 3: Unauthorized Write
```python
# Send write command from unauthorized IP
# System should detect if IP not in allowed_ips
```

## Limitations

1. **No Physical Sensor Monitoring**: This system monitors network traffic only, not physical process variables
2. **Protocol Parsing**: Simplified parsing for some protocols (full implementation requires protocol libraries)
3. **Encrypted Traffic**: Cannot analyze encrypted OPC-UA or other encrypted protocols
4. **Baseline Learning**: Timing anomaly detection requires baseline establishment

## Best Practices

1. **Whitelist Authorized IPs**: Only allow known HMI/SCADA systems
2. **Monitor Write Operations**: Write operations are more critical than reads
3. **Set Appropriate Thresholds**: Adjust based on your network's normal traffic
4. **Regular Updates**: Keep protocol parsers updated for new attack patterns
5. **Log Analysis**: Review CPS attack logs regularly

## Integration with Existing System

The CPS detection integrates seamlessly with the existing attack detection system:

- **Network Sniffer**: Captures industrial protocol traffic
- **CPS Detector**: Analyzes protocol-specific attacks
- **Modbus Detector**: Specialized Modbus attack detection
- **Alert System**: Sends CPS-specific alerts
- **Main System**: Orchestrates all components

## Future Enhancements

- Full protocol library integration (pymodbus, pydnp3)
- Machine learning for anomaly detection
- Physical process correlation (if sensors available)
- Encrypted protocol analysis
- Real-time protocol visualization

---

**Your system now has comprehensive CPS attack detection capabilities!** 🛡️

