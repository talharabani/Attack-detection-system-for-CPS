# Dashboard Web View - Attack Alerts Guide

## ✅ What's Been Fixed

The dashboard now properly displays all attack alerts from the terminal in the web view! Here's what was improved:

### 1. **Enhanced Log Parser**
- ✅ Now correctly extracts **packet count** from "Packets: 2" format
- ✅ Now correctly extracts **packet rate** from "Rate: 48.63 PPS" format  
- ✅ Now correctly extracts **protocol** from "Protocol: Mixed" format
- ✅ Now correctly extracts **attack subtype** from "Type: General Packet Flood" format

### 2. **Real-Time Notifications**
- ✅ Shows notification banner when new attacks are detected
- ✅ Auto-refreshes to show latest attacks
- ✅ Displays all attack details in beautiful cards

## 🚀 How to Use the Dashboard

### Step 1: Start the Detection System
```powershell
# In one terminal (as Administrator)
cd "C:\Users\123\Data\IS project\RealTimeAttackDetection"
python main.py -v
```

### Step 2: Start the Dashboard
```powershell
# In another terminal
cd "C:\Users\123\Data\IS project\RealTimeAttackDetection"
python run_dashboard.py
```

Or directly:
```powershell
streamlit run dashboard/app.py
```

### Step 3: Open in Browser
The dashboard will automatically open at:
```
http://localhost:8501
```

If it doesn't open automatically, manually navigate to that URL in your browser.

## 📊 What You'll See in the Dashboard

### 1. **Attack Cards**
Each attack is displayed as a beautiful card showing:
- 🚨 Attack type (DDoS/Flooding, Ping Flood, etc.)
- 📍 Source IP address
- ⚠️ Severity (CRITICAL, HIGH, MEDIUM, LOW)
- 📦 Packet count
- 📈 Packet rate (PPS)
- 🔌 Protocol (ICMP, TCP, UDP, Mixed)
- ⏰ Timestamp

### 2. **Real-Time Updates**
- **Auto-refresh**: Dashboard automatically refreshes every 3 seconds (configurable)
- **New attack notifications**: Green banner appears when new attacks are detected
- **Live metrics**: Attack counts update in real-time

### 3. **Filtering & Sorting**
- Filter by severity (All, CRITICAL, HIGH, MEDIUM, LOW)
- Sort by: Newest First, Oldest First, or Severity
- Search attacks by IP, type, or message

### 4. **Metrics Dashboard**
- Total Attacks detected
- Today's Attacks
- High Severity count
- Blocked IPs count

## 🎯 Example: What Attack #624 Looks Like

When you see this in the terminal:
```
🚨 ATTACK DETECTED #624
Attack Type:     DDoS/Flooding
Subtype:        General Packet Flood
Source IP:       192.168.100.26
Severity:        HIGH
Details:         Type: General Packet Flood | Packets: 2 | Rate: 48.63 PPS | Protocol: Mixed
```

You'll see this in the dashboard:
- **Card with red border** (HIGH severity)
- **Attack Type**: "DDoS/Flooding"
- **Subtype**: "General Packet Flood"
- **Source IP**: `192.168.100.26`
- **Severity Badge**: "HIGH" (red)
- **Packet Count**: "2 packets"
- **Traffic Rate**: "48.63 packets/sec"
- **Protocol**: "Mixed"
- **Timestamp**: Full date and time

## ⚙️ Dashboard Settings

### Auto-Refresh
- **Enabled by default**: Dashboard refreshes every 3 seconds
- **Adjustable**: Change refresh interval in sidebar (1-10 seconds)
- **Manual refresh**: Click "🔄 Refresh Now" button anytime

### View Options
Toggle these in the sidebar:
- ✅ Show Traffic Graph
- ✅ Show Active Connections
- ✅ Show Attack Timeline
- ✅ Show System Metrics
- ✅ Show Attack Types Chart

## 🔍 Troubleshooting

### Attacks Not Showing Up?

1. **Check if dashboard is running**
   ```powershell
   # Make sure you see:
   # "Starting RealTime Attack Detection Dashboard"
   # "Dashboard will open at: http://localhost:8501"
   ```

2. **Check log file location**
   - Default: `attack_detection.log` in project root
   - Verify in `config.json`: `"log_file": "attack_detection.log"`

3. **Click "🔄 Refresh Now"**
   - Manually refresh to force reload

4. **Check browser console**
   - Open browser DevTools (F12)
   - Look for any JavaScript errors

5. **Verify log file has attacks**
   ```powershell
   # Check if log file exists and has content
   Get-Content attack_detection.log | Select-String "ATTACK #"
   ```

### Dashboard Not Loading?

1. **Install dependencies**
   ```powershell
   pip install streamlit plotly pandas psutil
   ```

2. **Check port availability**
   - Default port: 8501
   - If busy, use: `streamlit run dashboard/app.py --server.port 8502`

3. **Check firewall**
   - Allow Python/Streamlit through Windows Firewall

## 📝 Notes

- **Dashboard reads from log file**: Attacks are parsed from `attack_detection.log`
- **Real-time updates**: Dashboard checks log file every refresh interval
- **No database needed**: All data comes from log file parsing
- **Persistent history**: Dashboard shows last 1000 attacks

## 🎨 Dashboard Features

### Attack Timeline
- Visual timeline of all attacks
- Color-coded by severity
- Interactive hover for details

### Network Traffic Graph
- Shows packet rate over time
- Highlights attack periods
- Real-time updates

### System Metrics
- CPU usage
- Memory usage
- Disk usage
- Active connections

### Attack Types Chart
- Pie chart of attack types
- Distribution visualization
- Click to filter

## 🚀 Quick Start

1. **Terminal 1** (Detection System):
   ```powershell
   python main.py -v
   ```

2. **Terminal 2** (Dashboard):
   ```powershell
   python run_dashboard.py
   ```

3. **Browser**: Open `http://localhost:8501`

4. **Watch**: Attacks appear in real-time! 🎉

---

**That's it!** Your attacks from the terminal will now appear in the beautiful web dashboard automatically! 🛡️

