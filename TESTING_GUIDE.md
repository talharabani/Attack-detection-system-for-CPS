# Testing Guide - How to Verify Detection Works

## ⚠️ CRITICAL: Make Sure Detection Actually Works

### Step 1: Run System with Debug Mode

```powershell
# Run as Administrator
python main.py -v
```

You should see:
```
DDoS detector initialized: ICMP_threshold=10 packets in 3s (IMMEDIATE DETECTION)
⚠️  ICMP ping flood will trigger after 10 ICMP packets in 3 seconds
Starting packet capture on interface: default
Capturing ALL packets including ICMP...
```

### Step 2: Test from Another Laptop

**On the target machine (where system is running):**
- Make sure it's running as Administrator
- Check console for: "Capturing ALL packets including ICMP..."

**On attacker laptop:**
```bash
# Send 20+ pings quickly
ping -n 20 <target_ip>

# Or continuous flood
ping -t <target_ip>
```

### Step 3: What You Should See

**In console (target machine):**
```
🔍 ICMP PING packet from 192.168.1.100 (type=8)
🔍 ICMP packets from 192.168.1.100: 10 ICMP in 3s (Threshold: 10)
🚨🚨🚨 PING FLOOD DETECTED from 192.168.1.100: 10 ICMP packets in 3s
[ATTACK #1] Ping Flood Attack (ICMP) detected from 192.168.1.100
```

**If you DON'T see this:**
1. Check if running as Administrator
2. Check if Npcap is installed (Windows)
3. Check if network sniffer started successfully
4. Look for error messages in console

### Step 4: Verify Packets Are Being Captured

With debug mode on, you should see:
- `🔍 ICMP PING packet from [IP]` for each ping
- If you don't see this, packets aren't being captured

### Step 5: Troubleshooting

**No packets captured?**
- Run as Administrator
- Install Npcap (Windows)
- Check firewall isn't blocking
- Try different network interface

**Packets captured but no detection?**
- Check threshold: Should be 10 ICMP packets in 3 seconds
- Check debug logs for ICMP counts
- Verify ICMP packets have `protocol=1` and `icmp_type=8`

**Still not working?**
- Lower threshold to 5 in config.json
- Check if packets are being filtered
- Verify network interface is correct

---

## Current Settings

- **ICMP Threshold**: 10 packets
- **ICMP Time Window**: 3 seconds
- **Detection**: Immediate (no baseline wait)
- **Debug Mode**: Enabled (shows all ICMP packets)

**This means: 10+ pings in 3 seconds = ALERT**

