# 🚀 Advanced Dashboard Features

## Overview

The dashboard has been enhanced with comprehensive real-time monitoring, attacker profiling, and export capabilities.

---

## ✅ New Features Added

### 1. **Real-Time Graphs** 📈

#### **PPS (Packets Per Second) Graph**
- Real-time visualization of network packet rates
- Shows attack activity overlays
- Updates every 10 seconds
- Displays last 30 minutes of data

#### **Per-IP Traffic Graph**
- Bar chart showing total packets per attacking IP
- Identifies top attackers
- Includes detailed table with:
  - Total packets per IP
  - Average PPS
  - Attack count
  - Last seen timestamp

#### **Attack Timeline**
- Enhanced timeline visualization
- Shows attacks over time with PPS values
- Color-coded by severity
- Interactive hover tooltips

#### **Protocol Breakdown**
- **Pie Chart**: Attack distribution by protocol (TCP, UDP, ICMP)
- **Bar Chart**: Total packets per protocol
- Real-time protocol statistics

---

### 2. **Attacker Profile Page** 👤

Comprehensive profile for each attacking IP address:

#### **Key Information:**
- **IP Address**: Source IP of attacker
- **Reputation Score**: 0-100 (lower = higher risk)
- **Total Attacks**: Number of attacks from this IP
- **Total Packets**: Sum of all packets
- **Max PPS**: Highest packet rate observed
- **Threat Level**: Shodan threat assessment

#### **Why Flagged:**
- Multiple attacks detected
- High packet rate (>500 PPS)
- High severity attacks
- Known vulnerabilities (CVEs)
- Shodan threat level

#### **Location & Network:**
- **Country**: Geographic location
- **City**: City location
- **ISP**: Internet Service Provider
- **Organization**: Organization name
- **ASN**: Autonomous System Number
- **Open Ports**: List of open ports
- **First/Last Seen**: Timestamps

#### **Attack Statistics:**
- Attack types breakdown
- Severity distribution
- Known vulnerabilities (CVEs)
- Honeypot probability score

#### **Recent Attacks:**
- List of recent attacks from this IP
- Full attack details with Shodan data

---

### 3. **Export Functionality** 💾

Export attack logs in multiple formats:

#### **CSV Export**
- Spreadsheet-compatible format
- Includes: ID, Timestamp, Attack Type, Source IP, Severity, Packet Count, PPS, Protocol, Country, ISP, Organization
- One-click download

#### **JSON Export**
- Complete attack data in JSON format
- Includes all attack details and Shodan data
- Machine-readable format

#### **ElasticSearch Export**
- Bulk import format for ElasticSearch
- Ready for indexing
- Includes index operations
- Usage: `curl -X POST 'localhost:9200/_bulk' -H 'Content-Type: application/json' --data-binary @file.json`

#### **Grafana Export**
- Time series format for Grafana
- Ready for dashboard visualization
- Includes tags for filtering
- Import as JSON data source

#### **Export Configuration:**
- Time range filtering (All, Last 24 Hours, Last 7 Days, Last 30 Days)
- Custom ElasticSearch index name
- Regenerate exports with filters

---

## 📊 Dashboard Navigation

The dashboard now has **4 main tabs**:

1. **📊 Dashboard** - Main overview with metrics and recent attacks
2. **📈 Real-Time Graphs** - All real-time visualizations
3. **👤 Attacker Profiles** - Detailed attacker information
4. **💾 Export** - Export functionality

---

## 🎯 How to Use

### **Viewing Real-Time Graphs:**
1. Click on **"📈 Real-Time Graphs"** tab
2. View PPS graph, per-IP traffic, protocol breakdown, and attack timeline
3. Graphs auto-update based on refresh interval

### **Viewing Attacker Profiles:**
1. Click on **"👤 Attacker Profiles"** tab
2. Select an IP from the dropdown
3. View comprehensive profile including:
   - Reputation score
   - Location information
   - Attack statistics
   - Why it was flagged
   - Recent attacks

### **Exporting Logs:**
1. Click on **"💾 Export"** tab
2. Choose export format (CSV, JSON, ElasticSearch, Grafana)
3. Optionally configure time range and settings
4. Click download button
5. File will be saved with timestamp

---

## 🔧 Technical Details

### **Data Sources:**
- Attack history from SQLite database
- Shodan threat intelligence (if available)
- Real-time packet statistics
- Protocol breakdown from attack data

### **Performance:**
- Efficient data aggregation
- Cached calculations
- Optimized for 1000+ attacks
- Real-time updates every 3-10 seconds

### **File Locations:**
- **Dashboard**: `dashboard/app.py`
- **Export Utils**: `dashboard/export_utils.py`
- **Attack Logger**: `utils/attack_logger.py`

---

## 📝 Example Use Cases

### **1. Identify Top Attackers:**
- Go to **Real-Time Graphs** → **Per-IP Traffic**
- View bar chart and table
- Identify IPs with highest packet counts

### **2. Investigate Specific Attacker:**
- Go to **Attacker Profiles**
- Select IP from dropdown
- Review reputation score, location, and attack history
- Check why it was flagged

### **3. Export for Analysis:**
- Go to **Export** tab
- Select time range (e.g., Last 7 Days)
- Download CSV for Excel analysis
- Or download JSON for custom scripts

### **4. Integrate with ElasticSearch:**
- Go to **Export** tab
- Download ElasticSearch bulk format
- Import into ElasticSearch cluster
- Create Kibana dashboards

### **5. Visualize in Grafana:**
- Go to **Export** tab
- Download Grafana time series format
- Import into Grafana
- Create time series visualizations

---

## 🎨 UI Features

- **Modern Glassmorphism Design**: Beautiful transparent cards
- **Real-Time Updates**: Auto-refresh every 3-10 seconds
- **Interactive Graphs**: Hover tooltips, zoom, pan
- **Color-Coded Severity**: Visual indicators for threat levels
- **Responsive Layout**: Works on all screen sizes

---

## 🚀 Future Enhancements

Potential additions:
- Real-time packet capture visualization
- Geographic attack map
- Custom alert rules
- Automated report generation
- Integration with SIEM systems
- Machine learning threat scoring

---

**Last Updated**: 2025-01-16
**Version**: 2.0

