# 🎯 Which Command Should I Use?

## Quick Answer

### 👥 For Users to Download Extension
```bash
python run_public_download.py
```
- Shows: **Public Download Page**
- Users see: Download button, installation instructions, features
- Password: **NOT required**
- Purpose: Let users download your extension

---

### 🔒 For Your Private Dashboard
```bash
python run_dashboard.py dashboard
```
- Shows: **Your Private Monitoring Dashboard**
- You see: Attack data, analytics, graphs, attacker profiles
- Password: **Required** (`12345`)
- Purpose: Monitor your network and view attack data

---

## Detailed Comparison

| Feature | `run_public_download.py` | `run_dashboard.py dashboard` |
|---------|-------------------------|------------------------------|
| **Who sees it** | Users/Public | You (Private) |
| **Password** | ❌ No | ✅ Yes (`12345`) |
| **Shows** | Download page | Attack monitoring dashboard |
| **Purpose** | Distribution | Monitoring |
| **Your data** | ❌ Hidden | ✅ Visible |
| **Extension download** | ✅ Yes | ❌ No |

---

## Common Scenarios

### Scenario 1: I want users to download my extension
**Solution:**
```bash
python run_public_download.py
```
Then share the URL: `http://localhost:8501` (or your public IP)

---

### Scenario 2: I want to monitor my network
**Solution:**
```bash
python run_dashboard.py dashboard
```
Then open: `http://localhost:8501` and enter password: `12345`

---

### Scenario 3: I want both (at different times)
**Solution:**
1. **First**, run download page for users:
   ```bash
   python run_public_download.py
   ```
2. **Stop it** (Ctrl+C)
3. **Then**, run your dashboard:
   ```bash
   python run_dashboard.py dashboard
   ```

**Note:** You can only run ONE at a time (same port 8501)

---

## Visual Guide

```
┌─────────────────────────────────────┐
│  python run_public_download.py     │
│  (For Users)                         │
├─────────────────────────────────────┤
│  Shows: Download Page               │
│  Password: NOT required             │
│  Users can: Download extension      │
│  Users see: Your private data? NO  │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│  python run_dashboard.py dashboard  │
│  (For You)                          │
├─────────────────────────────────────┤
│  Shows: Your Dashboard              │
│  Password: Required (12345)         │
│  You can: Monitor attacks           │
│  You see: Your private data? YES   │
└─────────────────────────────────────┘
```

---

## Still Confused?

**Ask yourself:**
- "Do I want users to download something?" → Use `run_public_download.py`
- "Do I want to see my attack data?" → Use `run_dashboard.py dashboard`

---

## Quick Reference Card

```
┌─────────────────────────────────────────────┐
│  QUICK REFERENCE                            │
├─────────────────────────────────────────────┤
│                                             │
│  👥 USERS DOWNLOAD                          │
│  → python run_public_download.py            │
│                                             │
│  🔒 YOUR DASHBOARD                          │
│  → python run_dashboard.py dashboard        │
│                                             │
└─────────────────────────────────────────────┘
```

