# 🚀 How to Run the Real-Time Attack Detection System

## Quick Start Guide

### Prerequisites

1. **Python 3.7 or higher** installed
2. **Administrator/Root privileges** (required for network packet capture)
3. **Windows**: Install [Npcap](https://npcap.com/download/) for packet capture
4. **Linux/macOS**: Install libpcap (`sudo apt-get install libpcap-dev` on Ubuntu)

---

## Step-by-Step Instructions

### Step 1: Navigate to Project Directory

Open PowerShell (Windows) or Terminal (Linux/macOS) and navigate to the project:

```powershell
# Windows
cd "C:\Users\123\Data\IS project\RealTimeAttackDetection"

# Linux/macOS
cd /path/to/RealTimeAttackDetection
```

---

### Step 2: Install Python Dependencies

```powershell
pip install -r requirements.txt
```

**If you encounter issues on Windows:**
```powershell
pip install pywin32
```

**If you encounter issues on Linux:**
```bash
sudo apt-get install python3-dev libpcap-dev
```

---

### Step 3: Configure Shodan API Key (Optional but Recommended)

1. Create a `.env` file in the project root directory
2. Add your Shodan API key:

```env
SHODAN_API_KEY=OrRrvs0GIH8cuxQToeunr8Z76Ld7FYIG
```

**Note:** The API key is already configured, but you can update it if needed.

---

### Step 4: Run the Detection System

#### Option A: Basic Run (Recommended for First Time)

**Windows (Run PowerShell as Administrator):**
```powershell
python main.py
```

**Linux/macOS (Run with sudo):**
```bash
sudo python3 main.py
```

#### Option B: Verbose Mode (See Detailed Logs)

```powershell
python main.py -v
```

#### Option C: Test Alerts First

```powershell
python main.py --test-alerts
```

This will test if desktop notifications work.

---

### Step 5: Start the Web Dashboard (Optional)

Open a **new terminal window** and run:

```powershell
python run_dashboard.py
```

Or directly:
```powershell
streamlit run dashboard/app.py
```

**Access the dashboard:**
- Open your browser to: `http://localhost:8501`
- The dashboard will auto-refresh every 3 seconds

---

## 🎯 What You'll See

### Terminal Output

When you run `python main.py`, you'll see:

```
============================================================
Starting RealTimeAttackDetection System
============================================================
[OK] Network sniffer started
[OK] Log monitor started
[OK] Process monitor started

Detector Status:
  - DDoS Detector: [ENABLED]
  - Port Scan Detector: [ENABLED]
  - Brute Force Detector: [ENABLED]
  - Intrusion Detector: [ENABLED]
  - CPS Detector: [ENABLED]
  - Modbus Detector: [ENABLED]

Alert Status:
  - Desktop Alerts: [ENABLED]
  - Telegram Alerts: [DISABLED]

Active Defense (IPS) Status:
  - Auto-Response: [ENABLED]
  - Auto-Block IPs: [ENABLED]

============================================================
System is running. Press Ctrl+C to stop.
============================================================
```

### When an Attack is Detected

You'll see a formatted alert like this:

```
================================================================================
🚨 ATTACK DETECTED #1
================================================================================
Attack Type:     DDoS/Flooding
Subtype:        General Packet Flood
Source IP:       192.168.100.66
Severity:        HIGH
Details:         Type: General Packet Flood | Packets: 150 | Rate: 48.63 PPS | Protocol: Mixed

--------------------------------------------------------------------------------
🔍 SHODAN THREAT INTELLIGENCE
--------------------------------------------------------------------------------
Organization:    Example Corp
ISP:            Example ISP
Location:       United States, New York
Open Ports:     22, 80, 443, 502, 8080 (+5 more)
Vulnerabilities: CVE-2021-1234, CVE-2021-5678 (+3 more)
Tags:           ICS, SCADA, Modbus
Threat Level:   HIGH
Honeypot Score: 0.15 (Likely Real)
Available Exploits: 5 found
Timestamp:       2025-11-16 11:38:44
================================================================================
```

---

## 🖥️ Running on Windows

### Important: Run as Administrator

1. **Right-click** on PowerShell
2. Select **"Run as Administrator"**
3. Navigate to project directory
4. Run `python main.py`

### Install Npcap (Required for Packet Capture)

1. Download from: https://npcap.com/download/
2. Install Npcap
3. **Restart your computer** after installation
4. Run the system as Administrator

---

## 🐧 Running on Linux

### Install System Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3-dev libpcap-dev

# CentOS/RHEL
sudo yum install python3-devel libpcap-devel
```

### Run with sudo

```bash
sudo python3 main.py
```

---

## 🍎 Running on macOS

### Install Dependencies

```bash
brew install libpcap
```

### Run with sudo

```bash
sudo python3 main.py
```

---

## 🧪 Testing the System

### Test 1: Desktop Alerts

```powershell
python main.py --test-alerts
```

You should see a desktop notification.

### Test 2: Simulate Ping Flood Attack

From another computer on the same network:

```powershell
# Windows
ping -t -l 64 <target_ip>

# Linux/macOS
ping -f <target_ip>
```

The system should detect this as a Ping Flood attack.

### Test 3: Simulate Port Scan

From another terminal:

```powershell
# Windows PowerShell
Test-NetConnection -ComputerName localhost -Port 80,443,22,21,25

# Linux/macOS
nmap -p 80,443,22,21,25 localhost
```

The system should detect this as a Port Scan attack.

---

## 📊 Running Both System and Dashboard

### Terminal 1: Run Detection System

```powershell
python main.py -v
```

### Terminal 2: Run Web Dashboard

```powershell
python run_dashboard.py
```

Then open browser to: `http://localhost:8501`

---

## ⚙️ Configuration

### Edit Detection Thresholds

Edit `config.json` to adjust sensitivity:

```json
{
  "detection": {
    "ddos": {
      "packet_threshold": 100,        // Lower = more sensitive
      "time_window_seconds": 5
    },
    "port_scan": {
      "port_threshold": 20,           // Lower = more sensitive
      "time_window_seconds": 30
    }
  }
}
```

### Enable Telegram Alerts (Optional)

1. Create a Telegram bot via [@BotFather](https://t.me/botfather)
2. Get your bot token and chat ID
3. Edit `config.json`:

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

## 🛑 Stopping the System

Press `Ctrl+C` in the terminal to gracefully stop the system.

You'll see:
```
Shutting down RealTimeAttackDetection System...
[OK] Network sniffer stopped
[OK] Log monitor stopped
[OK] Process monitor stopped

Statistics:
  - Total attacks detected: 5
  - Runtime: 120.50 seconds

System stopped.
```

---

## 🐛 Troubleshooting

### Problem: "No packets being captured"

**Solutions:**
- **Windows**: 
  - Run as Administrator
  - Install Npcap and restart computer
  - Check Windows Firewall settings
  
- **Linux/macOS**:
  - Run with `sudo`
  - Install libpcap: `sudo apt-get install libpcap-dev`

### Problem: "ModuleNotFoundError: No module named 'scapy'"

**Solution:**
```powershell
pip install scapy
```

### Problem: "Permission denied" errors

**Solution:**
- Run as Administrator (Windows) or with `sudo` (Linux/macOS)
- Network packet capture requires elevated privileges

### Problem: "Shodan API key not found"

**Solution:**
- Create `.env` file in project root
- Add: `SHODAN_API_KEY=your_key_here`
- System will work without Shodan, but threat intelligence won't be available

### Problem: Dashboard won't start

**Solution:**
```powershell
pip install streamlit plotly pandas
streamlit run dashboard/app.py
```

### Problem: "No information available" from Shodan

**Solution:**
- This is normal - not all IPs are in Shodan database
- System continues working without Shodan data

---

## 📝 Command Line Options

```powershell
# Basic run
python main.py

# Verbose logging (see all debug info)
python main.py -v

# Custom config file
python main.py -c /path/to/config.json

# Test alerts
python main.py --test-alerts
```

---

## 🎯 Quick Reference

| Task | Command |
|------|---------|
| Install dependencies | `pip install -r requirements.txt` |
| Run system | `python main.py` (as Admin/sudo) |
| Run with verbose | `python main.py -v` |
| Test alerts | `python main.py --test-alerts` |
| Start dashboard | `python run_dashboard.py` |
| Access dashboard | `http://localhost:8501` |
| Stop system | `Ctrl+C` |

---

## ✅ Checklist Before Running

- [ ] Python 3.7+ installed
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] Running as Administrator (Windows) or with sudo (Linux/macOS)
- [ ] Npcap installed (Windows) or libpcap installed (Linux/macOS)
- [ ] `.env` file created with Shodan API key (optional)
- [ ] `config.json` configured (optional)

---

## 🎉 You're Ready!

Once you see:
```
System is running. Press Ctrl+C to stop.
```

Your system is actively monitoring for attacks! 🛡️

**The system will:**
- ✅ Capture network packets in real-time
- ✅ Monitor log files for suspicious activity
- ✅ Track process behavior
- ✅ Detect 20+ attack types
- ✅ Send alerts when attacks are detected
- ✅ Enrich attacks with Shodan threat intelligence
- ✅ Display everything in terminal and web dashboard

---

## 📚 Need More Help?

- See `README.md` for complete documentation
- See `PROJECT_SUMMARY.md` for project overview
- See `SHODAN_INTEGRATION.md` for Shodan details
- See `ATTACK_TYPES_DETECTED.md` for all detected attacks

---

**Happy Monitoring!** 🚀🛡️

