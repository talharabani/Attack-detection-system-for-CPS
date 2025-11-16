# Testing Ping Flood Detection

## ✅ YES - The System CAN Detect Ping Attacks!

The system has been **enhanced** to specifically detect **ping flood attacks** (ICMP echo request floods) from other systems.

## How It Works

1. **Network Sniffer** captures ALL ICMP packets (including ping/echo requests)
2. **DDoS Detector** analyzes packet rates and specifically identifies when:
   - ICMP echo requests (ping packets) exceed the threshold
   - 80% or more of packets from an IP are ICMP ping packets
3. **Alert System** sends notifications with specific "Ping Flood Attack" identification

## Current Detection Settings

From `config.json`:
- **Packet Threshold**: 100 packets
- **Time Window**: 10 seconds
- **Detection**: If 100+ packets in 10 seconds → Alert triggered

This means if another system sends **100+ ping packets in 10 seconds**, it will be detected as a **Ping Flood Attack**.

## How to Test Ping Flood Detection

### Option 1: Test from Another Computer

1. **On the target machine** (where RealTimeAttackDetection is running):
   ```powershell
   # Run as Administrator
   python main.py -v
   ```

2. **On another computer** (attacker machine):
   ```bash
   # Linux/Mac
   ping -f -c 200 <target_ip>
   
   # Windows PowerShell
   Test-Connection -ComputerName <target_ip> -Count 200
   ```

   Or use a ping flood tool:
   ```bash
   # Linux
   ping -f <target_ip>
   
   # Or use hping3 for more control
   hping3 -1 --flood <target_ip>
   ```

### Option 2: Test Locally (Self-Ping)

**Windows:**
```powershell
# Run as Administrator
# In one terminal, start the detection system:
python main.py -v

# In another terminal (also as Admin), flood ping yourself:
ping -t -l 64 127.0.0.1
# Then quickly send many pings (Ctrl+C to stop)
```

**Linux:**
```bash
# Terminal 1: Start detection system (as root)
sudo python3 main.py -v

# Terminal 2: Flood ping
ping -f 127.0.0.1
# Or use hping3
sudo hping3 -1 --flood 127.0.0.1
```

### Option 3: Use a Ping Flood Script

Create a simple Python script to send many pings:

```python
import subprocess
import time

target_ip = "127.0.0.1"  # Change to target IP
count = 200

# Windows
subprocess.run(["ping", "-n", str(count), target_ip])

# Linux/Mac
# subprocess.run(["ping", "-c", str(count), target_ip])
```

## What You'll See When Ping Flood is Detected

### Console Output:
```
WARNING - PING FLOOD detected from 192.168.1.100: 150 ICMP echo requests (150 total packets) in 2.45s
CRITICAL - [ATTACK #1] Ping Flood Attack (ICMP) detected from 192.168.1.100 (Severity: HIGH)
```

### Desktop Notification:
```
🚨 Ping Flood Attack (ICMP) Detected
Severity: HIGH
Source IP: 192.168.1.100
ICMP Ping Packets: 150
Total Packets: 150
Rate: 61.22 pkt/s
```

### Telegram Alert (if configured):
```
🚨 Ping Flood Attack (ICMP) Detected

Severity: HIGH
Source IP: 192.168.1.100
ICMP Ping Packets: 150
Total Packets: 150
Rate: 61.22 packets/sec
Time Window: 10s
Protocol: ICMP Echo Request
```

## Adjusting Sensitivity

To make ping flood detection **more sensitive** (detect smaller attacks), edit `config.json`:

```json
{
  "detection": {
    "ddos": {
      "packet_threshold": 50,    // Lower = more sensitive (was 100)
      "time_window_seconds": 5     // Shorter = faster detection (was 10)
    }
  }
}
```

**Example**: With `packet_threshold: 50` and `time_window_seconds: 5`, the system will detect if 50+ packets arrive in 5 seconds.

## Important Notes

1. **Run as Administrator**: Network packet capture requires elevated privileges
2. **Install Npcap**: Windows users need Npcap installed for packet capture
3. **Firewall**: Make sure firewall allows ICMP if testing from another machine
4. **False Positives**: Normal ping usage won't trigger (needs 100+ packets in 10 seconds)

## Detection Algorithm

The system detects ping floods by:
1. Capturing all network packets (including ICMP)
2. Tracking packets per source IP
3. Counting ICMP echo requests (type 8) specifically
4. If 80%+ of packets from an IP are ICMP ping packets AND threshold exceeded → **Ping Flood Alert**

## Troubleshooting

**Q: No detection when pinging?**
- Check if running as Administrator
- Verify Npcap is installed (Windows)
- Check if packet threshold is too high (try lowering in config.json)
- Use `-v` flag to see debug output

**Q: Too many false positives?**
- Increase `packet_threshold` in config.json
- Increase `time_window_seconds` to require more packets over longer time

**Q: Can't capture packets?**
- Windows: Install Npcap and run as Admin
- Linux: Run with `sudo`
- Check network interface permissions

---

**The system is now ready to detect ping flood attacks!** 🛡️

