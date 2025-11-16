# RealTimeAttackDetection

A comprehensive real-time cyber attack detection system built with Python. This system monitors network traffic, system logs, and processes to detect various types of cyber attacks and sends alerts via desktop notifications and/or Telegram.

## 🛡️ Features

### Detected Attack Types

1. **DDoS / Flooding Attacks**
   - Detects high packet rates from the same IP address
   - Configurable threshold and time window
   - Real-time packet analysis

2. **Port Scanning**
   - Detects Nmap-style port scanning attempts
   - Monitors connection attempts to multiple ports
   - Identifies scanning patterns

3. **Brute Force Login Attempts**
   - Monitors authentication logs (Linux and Windows)
   - Detects multiple failed login attempts
   - Tracks usernames being targeted

4. **Intrusion Attempts**
   - Detects suspicious commands in logs
   - Monitors failed login patterns
   - Identifies unauthorized access attempts

5. **Suspicious Process Activity**
   - Monitors CPU and network usage
   - Detects processes with abnormal resource consumption
   - Identifies potentially malicious processes

## 📋 Requirements

- Python 3.7 or higher
- Administrator/Root privileges (for network packet capture)
- Operating System: Windows, Linux, or macOS

## 🚀 Installation

### 1. Clone or Download the Project

```bash
cd RealTimeAttackDetection
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

**Note for Windows users:** If you encounter issues with `pywin32`, you may need to install it separately:

```bash
pip install pywin32
```

**Note for Linux users:** You may need to install additional system packages:

```bash
# Ubuntu/Debian
sudo apt-get install python3-dev libpcap-dev

# CentOS/RHEL
sudo yum install python3-devel libpcap-devel
```

### 3. Configure the System

Edit `config.json` to customize detection thresholds and alert settings:

```json
{
  "detection": {
    "ddos": {
      "enabled": true,
      "packet_threshold": 100,
      "time_window_seconds": 10
    },
    "port_scan": {
      "enabled": true,
      "port_threshold": 20,
      "time_window_seconds": 30
    },
    "brute_force": {
      "enabled": true,
      "failed_attempts_threshold": 5,
      "time_window_seconds": 300
    }
  },
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

### 4. Configure Telegram Alerts (Optional)

To enable Telegram alerts:

1. Create a Telegram bot by messaging [@BotFather](https://t.me/botfather) on Telegram
2. Get your bot token
3. Get your chat ID (you can use [@userinfobot](https://t.me/userinfobot))
4. Update `config.json` with your bot token and chat ID

## 🎯 Usage

### Basic Usage

Run the system with default configuration:

```bash
python main.py
```

### Advanced Usage

```bash
# Use custom configuration file
python main.py -c /path/to/config.json

# Enable verbose logging
python main.py -v

# Test alert systems
python main.py --test-alerts
```

### Running as a Background Service

#### Linux (systemd)

Create a service file `/etc/systemd/system/attack-detection.service`:

```ini
[Unit]
Description=RealTimeAttackDetection Service
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

Enable and start the service:

```bash
sudo systemctl enable attack-detection.service
sudo systemctl start attack-detection.service
```

#### Windows (Task Scheduler)

1. Open Task Scheduler
2. Create a new task
3. Set trigger to "At startup" or "At log on"
4. Set action to start `python.exe` with argument `main.py`
5. Set "Run with highest privileges"

## 📁 Project Structure

```
RealTimeAttackDetection/
├── monitor/                 # Monitoring modules
│   ├── network_sniffer.py   # Network packet capture
│   ├── log_monitor.py       # Log file monitoring
│   └── process_monitor.py   # Process monitoring
├── detectors/               # Attack detection modules
│   ├── ddos_detector.py     # DDoS detection
│   ├── portscan_detector.py # Port scan detection
│   ├── brute_force_detector.py # Brute force detection
│   └── intrusion_detector.py  # Intrusion detection
├── alerts/                  # Alert systems
│   ├── desktop_alert.py     # Desktop notifications
│   └── telegram_alert.py    # Telegram notifications
├── utils/                   # Utility functions
│   └── helper.py            # Common utilities
├── main.py                  # Main entry point
├── config.json              # Configuration file
├── requirements.txt         # Python dependencies
└── README.md                # This file
```

## 🔍 How Detection Works

### DDoS Detection

- Monitors packet rate from each source IP
- Triggers alert when packet count exceeds threshold within time window
- Calculates packets per second for analysis

### Port Scan Detection

- Tracks unique destination ports per source IP
- Detects when an IP attempts to connect to multiple ports
- Identifies scanning patterns (sequential or random)

### Brute Force Detection

- Monitors authentication logs for failed login attempts
- Tracks failed attempts per IP address
- Alerts when threshold is exceeded within time window
- Identifies targeted usernames

### Intrusion Detection

- Analyzes log entries for suspicious commands
- Monitors for patterns like:
  - `rm -rf` (destructive commands)
  - `chmod 777` (permission changes)
  - `wget`/`curl` (file downloads)
  - `nc`/`netcat` (network tools)
  - Base64 encoded commands
  - PowerShell encoded commands
- Tracks multiple failed logins as intrusion attempts

### Process Monitoring

- Monitors CPU usage per process
- Tracks network I/O per process
- Alerts on processes exceeding thresholds
- Identifies processes with suspicious command lines

## ⚙️ Configuration Options

### Detection Thresholds

- **DDoS**: `packet_threshold` (default: 100), `time_window_seconds` (default: 10)
- **Port Scan**: `port_threshold` (default: 20), `time_window_seconds` (default: 30)
- **Brute Force**: `failed_attempts_threshold` (default: 5), `time_window_seconds` (default: 300)
- **Process**: `cpu_threshold_percent` (default: 80), `network_threshold_mbps` (default: 10)

### IP Whitelisting

Add IP addresses to whitelist in `config.json` to exclude them from detection:

```json
{
  "detection": {
    "ddos": {
      "ip_whitelist": ["192.168.1.100", "10.0.0.1"]
    }
  }
}
```

### Log Paths

Configure log file paths for your system:

```json
{
  "logs": {
    "linux_auth_log": "/var/log/auth.log",
    "linux_syslog": "/var/log/syslog",
    "windows_event_log": "Security"
  }
}
```

## 🔔 Alert Systems

### Desktop Notifications

- Uses `plyer` library for cross-platform notifications
- Shows toast notifications on Windows, Linux, and macOS
- Displays attack type, severity, and source IP

### Telegram Alerts

- Sends formatted messages to Telegram
- Includes detailed attack information
- Supports Markdown formatting
- Requires bot token and chat ID configuration

## 🛠️ Troubleshooting

### Network Sniffer Not Working

**Linux/macOS:**
- Ensure you're running with root/sudo privileges
- Check that the network interface is correct
- Verify `libpcap` is installed

**Windows:**
- Run as Administrator
- Install Npcap or WinPcap
- Check Windows Firewall settings

### Log Monitoring Not Working

**Linux:**
- Ensure log files exist and are readable
- Check file permissions: `sudo chmod 644 /var/log/auth.log`
- Verify `watchdog` package is installed

**Windows:**
- Run as Administrator
- Ensure `pywin32` is installed
- Check Event Viewer permissions

### Process Monitoring Issues

- Ensure `psutil` is installed
- Run with appropriate privileges
- Some processes may require elevated permissions to monitor

### Telegram Alerts Not Sending

- Verify bot token is correct
- Check chat ID is correct
- Ensure internet connectivity
- Check Telegram API status

## 📊 Performance Considerations

- Network sniffing can be CPU-intensive on high-traffic networks
- Process monitoring runs at configurable intervals (default: 5 seconds)
- Log monitoring uses file system events for efficiency
- All detectors use time-windowed analysis to manage memory

## 🔒 Security Considerations

- **Run with appropriate privileges**: Network monitoring requires elevated permissions
- **Protect configuration**: Keep `config.json` secure, especially Telegram tokens
- **Whitelist trusted IPs**: Add known-good IPs to whitelist to reduce false positives
- **Review alerts**: Regularly review detected attacks and adjust thresholds
- **Log rotation**: Configure log rotation to prevent disk space issues

## 📝 Logging

The system logs to both console and file (if configured). Log levels:

- **DEBUG**: Detailed information for debugging
- **INFO**: General information about system operation
- **WARNING**: Potential issues or important events
- **ERROR**: Error conditions
- **CRITICAL**: Attack detections

## 🤝 Contributing

This is a production-quality cybersecurity tool. When contributing:

1. Follow PEP 8 style guidelines
2. Add comments and docstrings
3. Test on multiple operating systems
4. Update documentation as needed

## ⚠️ Disclaimer

This tool is for security monitoring and educational purposes. Users are responsible for:

- Ensuring compliance with local laws and regulations
- Obtaining proper authorization before monitoring networks
- Using the tool ethically and responsibly
- Not using the tool for malicious purposes

## 📄 License

This project is provided as-is for educational and security monitoring purposes.

## 📸 Screenshots

_Add screenshots of the system in action here_

---

**RealTimeAttackDetection** - Real-time cyber attack detection for Windows, Linux, and macOS

