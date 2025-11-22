# 🛡️ Extension System Guide

## Overview

The extension system allows you to distribute the Attack Detection System as a standalone package that users can download and install on their own machines. Each installation is completely isolated with its own database and dashboard.

## Architecture

### Public Download Page
- **Route**: `/` (default public route)
- **File**: `dashboard/download_page.py`
- **Purpose**: Shows download page to users
- **Access**: Public (no password required)
- **Features**: 
  - Extension download button
  - Installation instructions
  - Feature showcase
  - Privacy information

### Private Dashboard
- **Route**: `/dashboard` (password protected)
- **File**: `dashboard/app.py`
- **Purpose**: Your private monitoring dashboard
- **Access**: Password protected
- **Features**: 
  - Real-time attack monitoring
  - Attack analytics
  - Export functionality
  - All dashboard features

## Setup Instructions

### 1. Configure Dashboard Password

Edit `config.json` and set a password:

```json
{
  "dashboard": {
    "password": "your_secure_password_here"
  }
}
```

**Important**: If no password is set, the dashboard will be publicly accessible.

### 2. Build the Extension

Run the build script to create the standalone executable:

```bash
python build_extension.py
```

This will:
- Create a PyInstaller executable
- Package all necessary files
- Create configuration wizard
- Generate installation guide
- Create startup scripts

The extension package will be in `extension_build/` directory.

### 3. Run Public Download Page

To show the download page to users:

```bash
python run_public_download.py
```

Or:

```bash
python run_dashboard.py download
```

Users visiting `http://localhost:8501` will see the download page, NOT your private dashboard.

### 4. Run Private Dashboard

To access your private dashboard:

```bash
python run_dashboard.py dashboard
```

Or simply:

```bash
python run_dashboard.py
```

You'll need to enter the password set in `config.json`.

## User Flow

### For You (System Owner)

1. **Build Extension**: Run `python build_extension.py`
2. **Start Public Page**: Run `python run_public_download.py`
3. **Share URL**: Users visit your URL and see download page
4. **Access Dashboard**: Use `python run_dashboard.py dashboard` for private access

### For Users (Extension Users)

1. **Visit URL**: Go to your public download page
2. **Download**: Click download button to get extension package
3. **Extract**: Extract the package to a folder
4. **Configure**: Run `python config_wizard.py` (first time setup)
5. **Start**: Run `AttackDetectionSystem.exe` (or `./start.sh` on Linux/Mac)
6. **Access Dashboard**: Open `http://localhost:8501` in browser
7. **Monitor**: View their own isolated dashboard

## Security Features

### Password Protection
- Dashboard requires password from `config.json`
- Password is checked on every page load
- Session-based authentication (stored in Streamlit session state)

### Data Isolation
- Each extension installation has its own:
  - Database (`attack_database.json`)
  - Log files (`attack_detection.log`)
  - Configuration (`config.json`)
  - Dashboard instance

### No Data Sharing
- Your dashboard data is completely separate from user data
- Users cannot see your attacks or configuration
- Each system operates independently

## Building the Extension

### Prerequisites

```bash
pip install pyinstaller
```

### Build Process

```bash
python build_extension.py
```

### Build Output

The build process creates:

```
extension_build/
├── AttackDetectionSystem.exe  (or .app/.bin on other platforms)
├── config.json
├── requirements.txt
├── README.md
├── config_wizard.py
├── INSTALLATION.md
└── start.bat / start.sh
```

### Distribution

Distribute the entire `extension_build/` folder. Users extract it and run the executable.

## Configuration Wizard

The configuration wizard (`config_wizard.py`) helps users set up:

1. **Network Interface**: Select which network interface to monitor
2. **Dashboard Password**: Set password for their dashboard
3. **Detection Thresholds**: Configure sensitivity levels
4. **Alert Settings**: Enable/disable notifications

## Troubleshooting

### Password Not Working

- Check `config.json` has `"password"` field set
- Password is case-sensitive
- Clear browser cache if session is stuck

### Extension Build Fails

- Ensure PyInstaller is installed: `pip install pyinstaller`
- Check all dependencies are in `requirements.txt`
- Verify Python version compatibility

### Port Conflicts

- Change dashboard port in `config.json`:
  ```json
  {
    "dashboard": {
      "port": 8502
    }
  }
  ```

### Users Can't See Download Page

- Make sure you're running `run_public_download.py`
- Check firewall settings
- Verify port 8501 is accessible

## Best Practices

1. **Strong Password**: Use a strong password for your dashboard
2. **Regular Updates**: Rebuild extension when you update the system
3. **Version Control**: Tag extension versions for distribution
4. **Documentation**: Keep installation guide updated
5. **Testing**: Test extension on clean system before distribution

## Advanced Configuration

### Custom Download Page

Edit `dashboard/download_page.py` to customize:
- Branding
- Features list
- Installation instructions
- Contact information

### Custom Extension Branding

Modify build script to:
- Add custom icon
- Change executable name
- Include custom assets
- Add license information

## Support

For issues or questions:
1. Check `INSTALLATION.md` in extension package
2. Review main project documentation
3. Check configuration wizard output
4. Verify all dependencies are installed

