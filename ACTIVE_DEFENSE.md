# Active Defense / Auto-Response System (IPS)

## Overview

The system now includes **Intrusion Prevention System (IPS)** capabilities that automatically respond to detected attacks, not just detect them.

## Features

### 1. Automatic IP Blocking
- **Windows**: Uses `netsh advfirewall` to block attacker IPs
- **Linux**: Uses `iptables` to block attacker IPs
- **Action**: Automatically blocks IPs when HIGH/CRITICAL severity attacks are detected

### 2. Process Termination
- Automatically kills suspicious processes
- Protects critical system processes from being killed
- Logs all terminated processes

### 3. Network Interface Control
- Can temporarily disable network interfaces
- Useful for isolating compromised systems
- Configurable per attack type

### 4. Account Locking
- Automatically locks user accounts after brute force attacks
- **Windows**: Uses `net user /active:no`
- **Linux**: Uses `usermod -L`

### 5. Service Management
- Can restart important system services
- Protects critical services from being restarted
- Useful for recovering from service-based attacks

## Configuration

### config.json Settings

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
    "whitelist_ips": ["192.168.1.100"],
    "protected_services": ["winlogon", "csrss", "lsass"]
  }
}
```

### Parameters

- **enabled**: Enable/disable active defense
- **auto_block_ips**: Automatically block attacker IPs
- **auto_kill_processes**: Automatically kill suspicious processes
- **auto_disable_interface**: Disable network interface on attack
- **auto_lock_accounts**: Lock accounts after brute force
- **auto_restart_services**: Restart services automatically
- **block_duration_minutes**: How long to block IPs (currently permanent)
- **whitelist_ips**: IPs that should never be blocked
- **protected_services**: Services that should never be restarted

## How It Works

### Attack Response Flow

```
Attack Detected
    ↓
Check Severity
    ↓
HIGH/CRITICAL?
    ↓
Yes → Block IP Address
    ↓
Kill Suspicious Process (if detected)
    ↓
Lock Account (if brute force)
    ↓
Log Response Actions
```

### Example Responses

#### DDoS Attack Response
```
Attack: DDoS from 192.168.1.200
Response:
  ✓ Blocked IP 192.168.1.200 using firewall
  ✓ Logged response action
```

#### Brute Force Response
```
Attack: Brute force from 10.0.0.5
Response:
  ✓ Blocked IP 10.0.0.5
  ✓ Locked user account: admin
```

#### Suspicious Process Response
```
Attack: Suspicious process detected
Response:
  ✓ Killed process: malware.exe (PID: 1234)
  ✓ Blocked source IP
```

## Security Considerations

### ⚠️ Important Notes

1. **Run as Administrator/Root**: Active defense requires elevated privileges
2. **Whitelist Important IPs**: Add trusted IPs to whitelist to prevent blocking
3. **Test Before Production**: Test auto-response in a safe environment first
4. **Monitor Blocked IPs**: Review blocked IPs regularly
5. **Backup Firewall Rules**: Keep backups of firewall configurations

### Protected Processes

The system will NOT kill:
- System processes (system, kernel, init)
- Critical Windows processes (winlogon, csrss, lsass)
- Processes in protected_services list

### Whitelist IPs

Always whitelist:
- Your own IP addresses
- Trusted management systems
- Monitoring systems
- Backup servers

## Manual Commands

### View Blocked IPs (Windows)
```powershell
netsh advfirewall firewall show rule name=all | findstr BlockAttack
```

### View Blocked IPs (Linux)
```bash
iptables -L INPUT -n --line-numbers
```

### Unblock IP (Windows)
```powershell
netsh advfirewall firewall delete rule name="BlockAttack_192_168_1_200"
```

### Unblock IP (Linux)
```bash
iptables -D INPUT -s 192.168.1.200 -j DROP
```

## Statistics

The system tracks:
- Number of blocked IPs
- Number of killed processes
- Number of locked accounts
- Response history

View statistics in the dashboard or via API.

## Integration

Active defense is automatically integrated:
- Triggers on HIGH/CRITICAL severity attacks
- Works with all detector types
- Logs all actions
- Can be disabled per attack type

## Best Practices

1. **Start Conservative**: Enable only IP blocking initially
2. **Monitor First**: Run in detection-only mode first
3. **Whitelist Trusted**: Add all trusted IPs to whitelist
4. **Review Logs**: Regularly review blocked IPs and actions
5. **Test Responses**: Test each response type in safe environment

---

**Your system is now an IPS (Intrusion Prevention System) with active defense capabilities!** 🛡️⚔️

