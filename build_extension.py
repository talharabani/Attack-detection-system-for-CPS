"""
Build script to create standalone extension package for Attack Detection System.
Uses PyInstaller to bundle the entire system into a single executable.
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path
import json

# Project root
project_root = Path(__file__).parent
build_dir = project_root / "extension_build"
dist_dir = project_root / "dist"

def check_dependencies():
    """Check if required build tools are installed."""
    print("🔍 Checking dependencies...")
    
    try:
        import PyInstaller
        print("✅ PyInstaller is installed")
    except ImportError:
        print("❌ PyInstaller not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
        print("✅ PyInstaller installed")
    
    return True

def create_spec_file():
    """Create PyInstaller spec file for the extension."""
    print("📝 Creating PyInstaller spec file...")
    
    spec_content = """# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('config.json', '.'),
        ('dashboard', 'dashboard'),
        ('detectors', 'detectors'),
        ('alerts', 'alerts'),
        ('monitor', 'monitor'),
        ('utils', 'utils'),
        ('threat_intel', 'threat_intel'),
        ('auto_response', 'auto_response'),
    ],
    hiddenimports=[
        'streamlit',
        'scapy',
        'plotly',
        'pandas',
        'psutil',
        'reportlab',
        'matplotlib',
        'shodan',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='AttackDetectionSystem',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
"""
    
    spec_path = project_root / "extension.spec"
    with open(spec_path, "w") as f:
        f.write(spec_content)
    
    print(f"✅ Spec file created: {spec_path}")
    return spec_path

def build_executable():
    """Build the executable using PyInstaller."""
    print("🔨 Building executable...")
    
    spec_path = project_root / "extension.spec"
    
    # Change to project root directory
    os.chdir(project_root)
    
    # Run PyInstaller
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--clean",
        "--noconfirm",
        str(spec_path)
    ]
    
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print("❌ Build failed!")
        print(result.stderr)
        return False
    
    print("✅ Build successful!")
    return True

def create_installer_package():
    """Create installer package with all necessary files."""
    print("📦 Creating installer package...")
    
    # Create build directory
    build_dir.mkdir(exist_ok=True)
    
    # Copy executable
    exe_name = "AttackDetectionSystem.exe" if sys.platform == "win32" else "AttackDetectionSystem"
    exe_path = dist_dir / exe_name
    
    if exe_path.exists():
        shutil.copy2(exe_path, build_dir / exe_name)
        print(f"✅ Copied executable: {exe_name}")
    else:
        print(f"❌ Executable not found: {exe_path}")
        return False
    
    # Copy configuration files
    config_files = ["config.json", "requirements.txt", "README.md"]
    for file in config_files:
        src = project_root / file
        if src.exists():
            shutil.copy2(src, build_dir / file)
            print(f"✅ Copied: {file}")
    
    # Create configuration wizard script
    create_config_wizard_script(build_dir)
    
    # Create installation guide
    create_installation_guide(build_dir)
    
    # Create startup script
    create_startup_script(build_dir, exe_name)
    
    print(f"✅ Package created in: {build_dir}")
    return True

def create_config_wizard_script(build_dir):
    """Create configuration wizard script."""
    wizard_script = build_dir / "config_wizard.py"
    
    content = '''"""
Configuration Wizard for Attack Detection System Extension.
Run this on first launch to set up the system.
"""

import json
import sys
from pathlib import Path

def run_wizard():
    """Run the configuration wizard."""
    print("=" * 60)
    print("🛡️ Attack Detection System - Configuration Wizard")
    print("=" * 60)
    print()
    
    config_path = Path("config.json")
    
    # Load existing config or create new
    if config_path.exists():
        with open(config_path, "r") as f:
            config = json.load(f)
    else:
        config = {}
    
    # Network Interface
    print("📡 Network Interface Configuration")
    print("Available interfaces:")
    try:
        import psutil
        interfaces = list(psutil.net_if_addrs().keys())
        for i, iface in enumerate(interfaces, 1):
            print(f"  {i}. {iface}")
        
        choice = input("Select interface number (or press Enter for auto-detect): ").strip()
        if choice and choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(interfaces):
                if "network" not in config:
                    config["network"] = {}
                config["network"]["interface"] = interfaces[idx]
                print(f"✅ Selected: {interfaces[idx]}")
    except Exception as e:
        print(f"⚠️ Could not list interfaces: {e}")
    
    print()
    
    # Dashboard Password
    print("🔒 Dashboard Security")
    password = input("Set dashboard password (press Enter to skip): ").strip()
    if password:
        if "dashboard" not in config:
            config["dashboard"] = {}
        config["dashboard"]["password"] = password
        print("✅ Password set")
    else:
        print("⚠️ No password set - dashboard will be publicly accessible")
    
    print()
    
    # Detection Thresholds
    print("⚙️ Detection Thresholds")
    print("Configure detection sensitivity (press Enter for defaults):")
    
    if "detection" not in config:
        config["detection"] = {}
    
    # DDoS threshold
    ddos_threshold = input("DDoS packet threshold (default: 1000): ").strip()
    if ddos_threshold and ddos_threshold.isdigit():
        if "ddos" not in config["detection"]:
            config["detection"]["ddos"] = {}
        config["detection"]["ddos"]["packet_threshold"] = int(ddos_threshold)
    
    # Port scan threshold
    port_threshold = input("Port scan threshold (default: 20): ").strip()
    if port_threshold and port_threshold.isdigit():
        if "port_scan" not in config["detection"]:
            config["detection"]["port_scan"] = {}
        config["detection"]["port_scan"]["port_threshold"] = int(port_threshold)
    
    print()
    
    # Save config
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    
    print("✅ Configuration saved!")
    print()
    print("=" * 60)
    print("🎉 Setup complete! You can now start the system.")
    print("=" * 60)

if __name__ == "__main__":
    try:
        run_wizard()
    except KeyboardInterrupt:
        print("\\n\\n⚠️ Configuration cancelled")
        sys.exit(1)
    except Exception as e:
        print(f"\\n❌ Error: {e}")
        sys.exit(1)
'''
    
    with open(wizard_script, "w") as f:
        f.write(content)
    
    print("✅ Configuration wizard script created")

def create_installation_guide(build_dir):
    """Create installation guide."""
    guide_path = build_dir / "INSTALLATION.md"
    
    content = """# 🛡️ Attack Detection System - Installation Guide

## Quick Start

1. **Extract** the extension package to a folder
2. **Run** the configuration wizard: `python config_wizard.py`
3. **Start** the system: Run `AttackDetectionSystem.exe` (Windows) or `./start.sh` (Linux/Mac)
4. **Access** the dashboard at `http://localhost:8501`

## Configuration

### First-Time Setup

Run the configuration wizard to set up:
- Network interface selection
- Dashboard password
- Detection thresholds
- Alert preferences

### Manual Configuration

Edit `config.json` to customize:
- Detection thresholds
- Alert settings
- Network interface
- Dashboard port

## Usage

### Starting the System

**Windows:**
```
AttackDetectionSystem.exe
```

**Linux/Mac:**
```
./start.sh
```

### Accessing the Dashboard

1. Open your browser
2. Navigate to `http://localhost:8501`
3. Enter your dashboard password (if set)

### Stopping the System

Press `Ctrl+C` in the terminal or close the application window.

## Features

- ✅ Real-time attack detection
- ✅ Web dashboard
- ✅ Desktop notifications
- ✅ Export functionality
- ✅ Threat intelligence

## Troubleshooting

### Port Already in Use

If port 8501 is already in use, change it in `config.json`:
```json
{
  "dashboard": {
    "port": 8502
  }
}
```

### Permission Errors

On Linux/Mac, you may need to run with sudo for packet capture:
```bash
sudo ./AttackDetectionSystem
```

### Network Interface Issues

List available interfaces:
```python
import psutil
print(psutil.net_if_addrs().keys())
```

Then set the interface in `config.json`.

## Support

For issues or questions, please refer to the main project documentation.
"""
    
    with open(guide_path, "w") as f:
        f.write(content)
    
    print("✅ Installation guide created")

def create_startup_script(build_dir, exe_name):
    """Create startup script for different platforms."""
    if sys.platform == "win32":
        # Windows batch script
        script_path = build_dir / "start.bat"
        content = f"""@echo off
echo Starting Attack Detection System...
{exe_name}
pause
"""
    else:
        # Linux/Mac shell script
        script_path = build_dir / "start.sh"
        content = f"""#!/bin/bash
echo "Starting Attack Detection System..."
./{exe_name}
"""
        # Make executable
        os.chmod(script_path, 0o755)
    
    with open(script_path, "w") as f:
        f.write(content)
    
    print(f"✅ Startup script created: {script_path.name}")

def main():
    """Main build process."""
    print("=" * 60)
    print("🛡️ Building Attack Detection System Extension")
    print("=" * 60)
    print()
    
    # Check dependencies
    if not check_dependencies():
        return False
    
    # Create spec file
    create_spec_file()
    
    # Build executable
    if not build_executable():
        return False
    
    # Create installer package
    if not create_installer_package():
        return False
    
    print()
    print("=" * 60)
    print("✅ Build Complete!")
    print("=" * 60)
    print(f"📦 Extension package location: {build_dir}")
    print(f"📄 Executable: {build_dir / ('AttackDetectionSystem.exe' if sys.platform == 'win32' else 'AttackDetectionSystem')}")
    print()
    print("Next steps:")
    print("1. Test the executable in the build directory")
    print("2. Distribute the entire 'extension_build' folder")
    print("3. Users can run the configuration wizard and start the system")
    print()
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️ Build cancelled")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Build error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

