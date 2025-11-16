# Quick Start Guide - RealTimeAttackDetection

## What Has Been Created

I've built a **complete, production-ready Python project** for real-time cyber attack detection. Here's what you have:

### 📦 Complete Project Structure (15 files)

1. **Main Entry Point**
   - `main.py` - Orchestrates everything, handles CLI arguments, starts all monitors

2. **Monitoring Modules** (3 files)
   - `monitor/network_sniffer.py` - Captures network packets in real-time using Scapy
   - `monitor/log_monitor.py` - Monitors Linux auth logs and Windows Event Logs
   - `monitor/process_monitor.py` - Tracks CPU/network usage of running processes

3. **Attack Detectors** (4 files)
   - `detectors/ddos_detector.py` - Detects DDoS/flooding attacks (high packet rates)
   - `detectors/portscan_detector.py` - Detects port scanning attempts
   - `detectors/brute_force_detector.py` - Detects brute force login attempts
   - `detectors/intrusion_detector.py` - Detects suspicious commands and intrusions

4. **Alert Systems** (2 files)
   - `alerts/desktop_alert.py` - Sends desktop toast notifications
   - `alerts/telegram_alert.py` - Sends alerts via Telegram Bot API

5. **Utilities**
   - `utils/helper.py` - Common functions (config loading, logging, IP validation)

6. **Configuration & Docs**
   - `config.json` - All detection thresholds and settings
   - `requirements.txt` - Python dependencies
   - `README.md` - Complete documentation

### 🎯 Key Features Implemented

✅ **Real-time packet capture** - Uses Scapy to sniff network traffic  
✅ **Cross-platform log monitoring** - Works on Linux AND Windows  
✅ **Process monitoring** - Tracks suspicious CPU/network usage  
✅ **5 attack types detected** - DDoS, Port Scan, Brute Force, Intrusion, Suspicious Processes  
✅ **Dual alert system** - Desktop notifications + Telegram  
✅ **Modular architecture** - Clean, reusable code  
✅ **Configurable thresholds** - All detection parameters in JSON  
✅ **Threading-based** - All monitors run in parallel  
✅ **Error handling** - Graceful degradation if components fail  
✅ **Production quality** - Comments, docstrings, logging throughout

---

## 🚀 How to Run the Project

### Step 1: Install Dependencies

Open PowerShell or Command Prompt in the project directory:

```powershell
cd "C:\Users\123\Data\IS project\RealTimeAttackDetection"
pip install -r requirements.txt
```

**Note for Windows:**
- You may need to install Npcap: https://npcap.com/download/
- Run PowerShell as Administrator if you get permission errors

### Step 2: Test the System (Optional)

Test if alerts work:

```powershell
python main.py --test-alerts
```

This will send a test desktop notification. You should see a toast notification.

### Step 3: Run the Detection System

**Option A: Basic Run (Normal Mode)**
```powershell
python main.py
```

**Option B: Verbose Mode (See all debug info)**
```powershell
python main.py -v
```

**Option C: Custom Config File**
```powershell
python main.py -c config.json
```

### Step 4: Stop the System

Press `Ctrl+C` to gracefully stop all monitors.

---

## ⚠️ Important Notes for Windows

### Running as Administrator

**Network packet capture requires Administrator privileges:**

1. Right-click PowerShell/Command Prompt
2. Select "Run as Administrator"
3. Navigate to project directory
4. Run `python main.py`

### If Network Sniffer Fails

If you see errors about network interface:
- Install **Npcap** from https://npcap.com/download/
- Restart your computer after installation
- Run as Administrator

### If Log Monitoring Fails

Windows Event Log monitoring requires:
- `pywin32` installed (should be in requirements.txt)
- Running as Administrator

---

## 📊 What Happens When You Run It

1. **System Initializes**
   - Loads configuration from `config.json`
   - Sets up logging
   - Initializes all detectors and monitors

2. **Monitors Start** (in parallel threads)
   - Network sniffer captures packets
   - Log monitor watches authentication logs
   - Process monitor checks running processes

3. **Detectors Analyze** (in real-time)
   - Each packet → DDoS & Port Scan detectors
   - Each log entry → Brute Force & Intrusion detectors
   - Each process → Intrusion detector

4. **Alerts Sent** (when attack detected)
   - Desktop notification appears
   - Telegram message sent (if configured)

5. **Console Output** shows:
   - System status
   - Detector status
   - Attack detections (with details)

---

## 🔧 Configuration

Edit `config.json` to customize:

### Adjust Detection Thresholds

```json
{
  "detection": {
    "ddos": {
      "packet_threshold": 100,      // Lower = more sensitive
      "time_window_seconds": 10
    },
    "port_scan": {
      "port_threshold": 20,          // Lower = more sensitive
      "time_window_seconds": 30
    }
  }
}
```

### Enable Telegram Alerts

1. Create a Telegram bot via [@BotFather](https://t.me/botfather)
2. Get your bot token
3. Get your chat ID (use [@userinfobot](https://t.me/userinfobot))
4. Update `config.json`:

```json
{
  "alerts": {
    "telegram": {
      "enabled": true,
      "bot_token": "YOUR_BOT_TOKEN_HERE",
      "chat_id": "YOUR_CHAT_ID_HERE"
    }
  }
}
```

---

## 🧪 Testing the System

### Test 1: Desktop Alerts
```powershell
python main.py --test-alerts
```
Should show a desktop notification.

### Test 2: Simulate Port Scan
Open another terminal and run:
```powershell
# This will trigger port scan detection
Test-NetConnection -ComputerName localhost -Port 80,443,22,21,25,53,110,143,993,995
```

### Test 3: Check Logs
The system logs to console. With `-v` flag, you'll see detailed debug info.

---

## 📝 Example Output

When running, you'll see:

```
============================================================
Starting RealTimeAttackDetection System
============================================================
✓ Network sniffer started
✓ Log monitor started
✓ Process monitor started

Detector Status:
  - DDoS Detector: ✓ Enabled
  - Port Scan Detector: ✓ Enabled
  - Brute Force Detector: ✓ Enabled
  - Intrusion Detector: ✓ Enabled

Alert Status:
  - Desktop Alerts: ✓ Enabled
  - Telegram Alerts: ✗ Disabled

============================================================
System is running. Press Ctrl+C to stop.
============================================================
```

When an attack is detected:
```
[ATTACK #1] Port Scanning detected from 192.168.1.100 (Severity: MEDIUM)
```

---

## 🐛 Troubleshooting

### "Scapy not available"
```powershell
pip install scapy
```

### "Permission denied" (Network)
- Run as Administrator
- Install Npcap

### "No module named 'win32evtlog'"
```powershell
pip install pywin32
```

### "File not found: config.json"
- Make sure you're in the `RealTimeAttackDetection` directory
- Check that `config.json` exists

---

## 📚 More Information

See `README.md` for complete documentation including:
- Detailed feature descriptions
- Advanced configuration
- Running as a service
- Security considerations

---

**You're all set!** The system is ready to detect attacks in real-time. 🛡️

