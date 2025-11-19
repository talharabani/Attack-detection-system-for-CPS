# 🔍 Shodan Threat Intelligence Integration

## Overview

Full Shodan threat intelligence integration has been added to the CPS Attack Detection System. This module automatically enriches attack alerts with comprehensive threat intelligence data from Shodan.

## Features

### 1. **IP Lookup & Enrichment**
- Automatically fetches information about attacking IPs
- Retrieves open ports, vulnerabilities (CVEs), ISP, organization, OS, hostnames, and device type
- Geographic location data
- Service banners and product information

### 2. **Shodan Search Queries**
- Search the entire Shodan database
- Support for filters: `port:`, `org:`, `product:`, `country:`, `vulnerabilities:`
- Example: `port:502 org:Microsoft country:US`

### 3. **Exploit Database Integration**
- Automatically fetches related exploits when vulnerabilities are detected
- Searches Shodan Exploits database by CVE, port, or product
- Provides exploit details and descriptions

### 4. **DNS & Tools**
- DNS lookup and reverse DNS
- Honeypot probability scoring
- Host scanning capabilities

### 5. **Automatic Threat Enrichment**
- **Triggered automatically** when an attack is detected
- Enriches alerts with:
  - Open ports
  - CVEs and vulnerabilities
  - Available exploits
  - Service banners
  - Tags (ICS, database, router, etc.)
  - Geographic and ISP information
  - Threat level calculation

## Installation

### 1. Install Dependencies

```bash
pip install shodan python-dotenv
```

Or install all requirements:
```bash
pip install -r requirements.txt
```

### 2. Configure API Key

**Option 1: Environment Variable (Recommended)**
```bash
# Create .env file in project root
echo SHODAN_API_KEY=your_api_key_here > .env
```

**Option 2: Direct in Code (Not Recommended)**
The API key is already configured in `shodan_client.py` as a fallback, but using environment variables is more secure.

### 3. Get Your Shodan API Key

1. Sign up at https://account.shodan.io/
2. Get your API key from the account page
3. Add it to `.env` file

## Usage

### Automatic Enrichment

Shodan enrichment happens **automatically** when an attack is detected. No additional configuration needed!

When an attack is detected:
1. System automatically calls Shodan API
2. Retrieves comprehensive IP information
3. Fetches related exploits if vulnerabilities found
4. Calculates threat level
5. Displays all information in terminal and web dashboard

### Manual Usage

You can also use Shodan client directly:

```python
from threat_intel.shodan_client import ShodanClient

# Initialize client
client = ShodanClient()

# Get IP information
ip_info = client.get_ip_info("8.8.8.8")

# Search Shodan
results = client.search("port:502 country:US")

# Get exploits
exploits = client.get_exploits("CVE-2021-44228")

# DNS lookup
dns_info = client.dns_lookup("example.com")

# Reverse DNS
reverse_dns = client.reverse_dns("8.8.8.8")

# Honeypot score
honeypot = client.get_honeypot_score("192.168.1.1")

# Request scan
scan_result = client.scan_host("192.168.1.1")
```

## What You'll See

### Terminal Output

When an attack is detected, you'll see:

```
================================================================================
🚨 ATTACK DETECTED #1
================================================================================
Attack Type:     DDoS/Flooding
Subtype:        General Packet Flood
Source IP:       192.168.100.66
Severity:        HIGH
Details:         Type: General Packet Flood | Packets: 2 | Rate: 48.63 PPS | Protocol: Mixed

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

### Web Dashboard

In the web dashboard, each attack card has an expandable **"🔍 Shodan Threat Intelligence"** section showing:
- Location & Organization
- Network Information (ports, OS, device type)
- Vulnerabilities (CVEs)
- Tags
- Honeypot Score
- Available Exploits
- Services

## API Methods

### `get_ip_info(ip: str)`
Get comprehensive information about an IP address.

**Returns:**
- `open_ports`: List of open ports
- `vulnerabilities`: List of CVEs
- `isp`: ISP information
- `org`: Organization
- `os`: Operating system
- `hostnames`: List of hostnames
- `device_type`: Device type
- `location`: Geographic location (country, city, coordinates)
- `tags`: List of tags
- `services`: Service banners

### `search(query: str, facets: Optional[List[str]] = None)`
Search the Shodan database.

**Example queries:**
- `port:502` - Find devices on port 502 (Modbus)
- `org:Microsoft` - Find Microsoft devices
- `product:Apache country:US` - Find Apache servers in US
- `vulnerabilities:CVE-2021-44228` - Find vulnerable devices

### `get_exploits(query: str)`
Search Shodan Exploits database.

**Example queries:**
- `CVE-2021-44228` - Find exploits for specific CVE
- `port:502` - Find exploits for port 502
- `product:Apache` - Find exploits for Apache

### `dns_lookup(domain: str)`
DNS lookup for a domain name.

### `reverse_dns(ip: str)`
Reverse DNS lookup for an IP address.

### `get_honeypot_score(ip: str)`
Get honeypot probability score (0.0 = likely real, 1.0 = likely honeypot).

### `scan_host(ip: str)`
Request Shodan to scan a host (requires scan credits).

### `enrich_attack_info(ip: str)`
Main enrichment method that combines all Shodan data for an attack.

## Threat Level Calculation

The system automatically calculates a threat level based on:
- **Vulnerabilities**: +2 points per CVE
- **Exploits**: +3 points per exploit
- **ICS/SCADA Tags**: +5 points (critical for CPS)
- **Open Ports**: +2 points if >10 ports
- **Honeypot Score**: +3 points if <0.3 (likely real threat)

**Threat Levels:**
- **CRITICAL**: ≥15 points
- **HIGH**: ≥10 points
- **MEDIUM**: ≥5 points
- **LOW**: <5 points

## Security

### API Key Protection
- ✅ API key stored in environment variables (`.env` file)
- ✅ Never logged or exposed in UI
- ✅ `.env` file is in `.gitignore`
- ✅ Fallback to default key if env var not set (for testing)

### Error Handling
- ✅ All API calls wrapped in try-except
- ✅ System continues working even if Shodan fails
- ✅ Graceful degradation (no crashes)
- ✅ Detailed error logging

## Configuration

### Enable/Disable Shodan

Shodan is **enabled by default** if API key is found. To disable:

1. Remove API key from `.env`
2. Or set `SHODAN_API_KEY=""` in environment

### Rate Limiting

Shodan API has rate limits based on your account type:
- **Free**: 1 request per second
- **Member**: 1 request per second
- **One-time scan**: 100 requests per second

The system includes automatic retry logic with exponential backoff.

## Integration Points

### 1. Main Attack Handler (`main.py`)
- Automatically enriches attack info when attack detected
- Displays Shodan data in terminal
- Includes Shodan data in log files

### 2. Web Dashboard (`dashboard/app.py`)
- Displays Shodan data in attack cards
- Expandable section with all threat intelligence
- Beautiful formatting and visualization

### 3. Log Files
- Shodan data included in attack logs
- Format: `Shodan: Org: Example Corp, Ports: 10, CVEs: 3`

## Example Output

### Terminal
```
🔍 SHODAN THREAT INTELLIGENCE
Organization:    Amazon Technologies Inc.
ISP:            Amazon.com
Location:       United States, Virginia
Open Ports:     22, 80, 443, 8080, 8443
Vulnerabilities: CVE-2021-44228, CVE-2021-45046
Tags:           cloud, aws
Threat Level:   MEDIUM
Honeypot Score: 0.25 (Likely Real)
Available Exploits: 2 found
```

### Web Dashboard
- Expandable card showing all Shodan data
- Color-coded threat levels
- Organized sections for easy reading
- Click to expand/collapse

## Troubleshooting

### Shodan Not Working

**Problem**: No Shodan data appearing

**Solutions**:
1. Check API key is set: `echo $SHODAN_API_KEY` (Linux/Mac) or check `.env` file
2. Verify API key is valid: Test at https://account.shodan.io/
3. Check internet connection
4. Review logs for Shodan errors

### API Rate Limits

**Problem**: "Rate limit exceeded" errors

**Solutions**:
1. System automatically retries with backoff
2. Upgrade Shodan account for higher limits
3. Reduce attack detection frequency (if testing)

### No Data for IP

**Problem**: Shodan returns no data for an IP

**Possible reasons**:
- IP has never been scanned by Shodan
- IP is private/local (Shodan only has public IPs)
- IP is very new

**Solution**: This is normal - not all IPs are in Shodan database

## API Credits

Shodan API usage:
- **IP Lookup**: 1 credit per lookup
- **Search**: 1 credit per search
- **Exploits**: 1 credit per search
- **DNS**: Free
- **Honeypot**: Free
- **Scan**: Requires scan credits

Monitor your usage at: https://account.shodan.io/

## Files Created/Modified

### New Files
- `threat_intel/shodan_client.py` - Main Shodan client
- `threat_intel/__init__.py` - Module initialization
- `.env.example` - Example environment file
- `SHODAN_INTEGRATION.md` - This documentation

### Modified Files
- `main.py` - Added Shodan integration to attack handler
- `dashboard/app.py` - Added Shodan display to attack cards
- `requirements.txt` - Added shodan and python-dotenv
- `.gitignore` - Added .env files

## Summary

✅ **Full Shodan integration** with all major features  
✅ **Automatic threat enrichment** on attack detection  
✅ **Terminal and web dashboard** display  
✅ **Secure API key handling**  
✅ **Error handling** and graceful degradation  
✅ **No breaking changes** to existing code  

**Your system now has enterprise-grade threat intelligence!** 🛡️🔍

