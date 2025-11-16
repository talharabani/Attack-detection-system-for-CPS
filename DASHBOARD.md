# Real-Time Web Dashboard

## Overview

A professional web-based dashboard for real-time monitoring of the attack detection system. Built with Streamlit for easy deployment and beautiful visualizations.

## Features

### 📊 Live Metrics
- **Total Attacks**: Cumulative attack count
- **Today's Attacks**: Attacks detected today
- **High Severity**: Critical attacks count
- **Blocked IPs**: IPs blocked by active defense

### 📈 Visualizations
- **Attack Timeline**: Real-time attack detection timeline
- **Network Traffic Graph**: Live packet rate visualization
- **System Metrics**: CPU, Memory, Disk usage
- **Active Connections**: Current network connections

### 🔄 Auto-Refresh
- Configurable refresh interval (1-10 seconds)
- Real-time updates without page reload
- Manual refresh option

### 🎨 Professional UI
- Clean, modern interface
- Color-coded alerts
- Responsive layout
- Dark/light theme support

## Installation

### 1. Install Dependencies
```bash
pip install streamlit plotly pandas
```

Or install all requirements:
```bash
pip install -r requirements.txt
```

### 2. Run Dashboard

**Option A: Using run_dashboard.py**
```bash
python run_dashboard.py
```

**Option B: Direct Streamlit**
```bash
streamlit run dashboard/app.py
```

**Option C: Custom Port**
```bash
streamlit run dashboard/app.py --server.port 8502
```

## Access Dashboard

Once running, open your browser to:
```
http://localhost:8501
```

## Dashboard Sections

### 1. Header
- System name and status
- Current time

### 2. Metrics Row
- 4 key metrics displayed as cards
- Delta indicators for changes

### 3. Main Content Area

#### Left Column:
- **Attack Timeline**: Scatter plot of detected attacks
- **Network Traffic**: Line graph of packet rates

#### Right Column:
- **Recent Attacks**: List of latest attacks
- **System Metrics**: CPU, Memory, Disk usage with progress bars

### 4. Bottom Section
- **Active Connections**: Table of current network connections
- Shows local/remote addresses, status, PID

## Configuration

### config.json Settings

```json
{
  "dashboard": {
    "enabled": true,
    "port": 8501,
    "refresh_interval_seconds": 3,
    "max_attack_history": 1000
  }
}
```

### Parameters

- **enabled**: Enable/disable dashboard
- **port**: Port number for dashboard (default: 8501)
- **refresh_interval_seconds**: Auto-refresh interval
- **max_attack_history**: Maximum attacks to display

## Sidebar Controls

### Settings
- **Auto Refresh**: Toggle auto-refresh
- **Refresh Interval**: Slider for refresh rate (1-10 seconds)
- **Refresh Now**: Manual refresh button

### View Options
- **Show Traffic Graph**: Toggle traffic visualization
- **Show Active Connections**: Toggle connections table
- **Show Attack Timeline**: Toggle attack timeline
- **Show System Metrics**: Toggle system metrics

## Data Sources

### Attack History
- Loaded from `attack_detection.log`
- Parses attack detection messages
- Shows last 1000 attacks

### Network Traffic
- Currently simulated (can be connected to sniffer)
- Shows packets per second
- Updates in real-time

### System Metrics
- Uses `psutil` for system stats
- CPU, Memory, Disk usage
- Live updates

### Active Connections
- Uses `psutil.net_connections()`
- Shows ESTABLISHED connections
- Displays top 20 connections

## Customization

### Change Colors
Edit `dashboard/app.py`:
```python
# Update color scheme
fig_traffic.add_trace(go.Scatter(
    ...
    line=dict(color='#your_color')
))
```

### Add New Metrics
Add to metrics row:
```python
with col5:
    st.metric("New Metric", value)
```

### Add New Visualizations
Add new plotly charts:
```python
fig = px.bar(data, x='x', y='y')
st.plotly_chart(fig, use_container_width=True)
```

## Integration with Main System

The dashboard can be run alongside the main detection system:

**Terminal 1:**
```bash
python main.py
```

**Terminal 2:**
```bash
python run_dashboard.py
```

Both systems can run simultaneously.

## Advanced Features

### Real-Time Data Connection
To connect dashboard to live sniffer data:

1. Create shared data store (Redis, SQLite, or file)
2. Update sniffer to write metrics
3. Update dashboard to read from store

### Authentication
Add authentication:
```python
# In app.py
import streamlit_authenticator as stauth

authenticator = stauth.Authenticate(...)
name, authentication_status, username = authenticator.login()
```

### Alerts in Dashboard
Show real-time alerts:
```python
if new_attack:
    st.error(f"🚨 Attack detected: {attack_type}")
```

## Troubleshooting

### Dashboard Won't Start
```bash
# Check if port is in use
netstat -an | findstr 8501  # Windows
lsof -i :8501              # Linux/Mac

# Use different port
streamlit run dashboard/app.py --server.port 8502
```

### No Data Showing
- Check if `attack_detection.log` exists
- Verify log file path in config.json
- Check file permissions

### Performance Issues
- Increase refresh interval
- Reduce max_attack_history
- Limit connection display count

## Screenshots

The dashboard includes:
- Professional metrics cards
- Interactive Plotly charts
- Real-time attack timeline
- System resource monitoring
- Active connection tracking

## Future Enhancements

- [ ] Real-time data streaming from sniffer
- [ ] Attack map visualization
- [ ] Protocol breakdown charts
- [ ] Export functionality
- [ ] Multi-user support
- [ ] Alert notifications in dashboard
- [ ] Historical data analysis
- [ ] Custom report generation

---

**Your system now has a professional real-time monitoring dashboard!** 📊🛡️

