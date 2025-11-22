# 🚀 Quick Start Guide - Extension System

## ✅ Installation Complete!

All dependencies have been installed successfully:
- ✅ PyInstaller (for building extension)
- ✅ Streamlit (for dashboard)
- ✅ All required packages from requirements.txt

## 🎯 How to Run the System

### Option 1: Public Download Page (For Users)

This shows the download page to users visiting your URL:

```bash
python run_public_download.py
```

**Access:** `http://localhost:8501`
- Users see download page
- They can download the extension
- They CANNOT see your private dashboard

### Option 2: Private Dashboard (For You)

This shows your password-protected dashboard:

```bash
python run_dashboard.py dashboard
```

Or simply:

```bash
python run_dashboard.py
```

**Access:** `http://localhost:8501`
- Password: `12345` (set in config.json)
- You see your private monitoring dashboard
- All your attack data and analytics

### Option 3: Build Extension Package

To create the standalone extension for distribution:

```bash
python build_extension.py
```

This creates the extension package in `extension_build/` folder.

## 🔒 Security

**Dashboard Password:** `12345` (configured in `config.json`)

To change the password, edit `config.json`:
```json
{
  "dashboard": {
    "password": "your_new_password"
  }
}
```

## 📋 System Status

✅ **All Dependencies Installed**
- PyInstaller: ✅
- Streamlit: ✅
- Plotly: ✅
- Pandas: ✅
- Scapy: ✅
- All other packages: ✅

✅ **Extension System Ready**
- Public download page: ✅
- Password-protected dashboard: ✅
- Build system: ✅
- Configuration wizard: ✅

## 🎉 Next Steps

1. **Test Public Page:**
   ```bash
   python run_public_download.py
   ```
   Open `http://localhost:8501` in browser

2. **Test Private Dashboard:**
   ```bash
   python run_dashboard.py dashboard
   ```
   Open `http://localhost:8501` and enter password: `12345`

3. **Build Extension (Optional):**
   ```bash
   python build_extension.py
   ```
   This creates the standalone package for distribution

## 📝 Notes

- The public download page and private dashboard use the same port (8501)
- Run only ONE at a time
- Stop one before starting the other (Ctrl+C)
- Password is case-sensitive

## 🆘 Troubleshooting

**Port Already in Use:**
- Stop any running Streamlit instances
- Or change port in `config.json`:
  ```json
  {
    "dashboard": {
      "port": 8502
    }
  }
  ```

**Password Not Working:**
- Check `config.json` has password as string: `"password": "12345"`
- Clear browser cache
- Restart the dashboard

**Extension Build Fails:**
- Ensure PyInstaller is installed: `pip install pyinstaller`
- Check all files are in place
- Review build_extension.py output

---

**System is ready to use! 🎉**

