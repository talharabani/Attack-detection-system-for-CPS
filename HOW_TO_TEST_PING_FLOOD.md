# How to Test Ping Flood Detection

## ✅ GOOD NEWS: Packet Capture is Working!

The test script confirmed that:
- ✅ Scapy can capture packets
- ✅ ICMP packets ARE being captured
- ✅ Your other laptop (192.168.100.66) is sending pings

## 🔍 The Problem: Normal Pings ≠ Ping Flood

**Normal ping rate**: ~1 ping per second
**Flood threshold**: 10 pings in 3 seconds (≈3.3 pings/second)

Normal pings won't trigger the flood detection!

## 🚀 How to Send a REAL Ping Flood

### Option 1: Windows (from another laptop)
```cmd
ping -t -l 64 192.168.100.26
```
Then open **multiple command prompts** and run the same command in each. This will send multiple pings simultaneously.

### Option 2: Linux/Mac (from another laptop)
```bash
# Send 100 pings as fast as possible
ping -c 100 -f 192.168.100.26

# OR use hping3 for more control
hping3 -1 --flood 192.168.100.26
```

### Option 3: Use a Flood Tool
```bash
# On Linux/Mac, use nping (comes with Nmap)
nping --icmp --rate 10 192.168.100.26

# Or use hping3
hping3 -1 -i u10000 192.168.100.26  # 10 pings per second
```

## 📊 What You Should See

When running `python main.py -v`, you should see:

```
[ICMP] Packet captured: type=8, from 192.168.100.66
[PING] ICMP ping packet received from 192.168.100.66
[ICMP] PING packet from 192.168.100.66 (type=8)
[ICMP-COUNT] ICMP packets from 192.168.100.66: 10 ICMP in 3s (Threshold: 10)
[ALERT] PING FLOOD DETECTED from 192.168.100.66: 10 ICMP packets in 3s
[ATTACK #1] Ping Flood Attack (ICMP) detected from 192.168.100.66
```

## ⚠️ If You Still Don't See Packets

1. **Make sure you're running as Administrator**
   ```powershell
   # Right-click PowerShell/CMD -> Run as Administrator
   cd "C:\Users\123\Data\IS project\RealTimeAttackDetection"
   python main.py -v
   ```

2. **Check if packets are being captured**
   - You should see: `[SNIFFER] Captured 100 packets so far...`
   - If you DON'T see this, packet capture isn't working

3. **Verify Npcap is installed**
   - Download from: https://npcap.com/
   - Install and restart

4. **Check the network interface**
   - The system will use the default interface
   - Make sure it's the correct one (usually your WiFi/Ethernet adapter)

## 🎯 Quick Test

1. **On THIS machine** (as Administrator):
   ```powershell
   python main.py -v
   ```

2. **On the OTHER laptop**, send rapid pings:
   ```cmd
   # Windows
   ping -t -l 64 192.168.100.26
   # Then open 3-4 more CMD windows and run the same command
   ```

3. **Watch the console** - you should see ICMP packets being logged immediately!

## 📝 Current Settings

- **ICMP Threshold**: 10 packets
- **Time Window**: 3 seconds
- **Detection**: Immediate (no baseline wait for ICMP)

If you send 10+ pings in 3 seconds, it WILL trigger!

