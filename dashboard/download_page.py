"""
Public Download Page for Attack Detection System Extension.
Users visiting the root URL will see this page instead of the private dashboard.
"""

import streamlit as st
from pathlib import Path
import sys
import os

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Page configuration
st.set_page_config(
    page_title="🛡️ Download Attack Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Beautiful CSS matching the dark theme
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');
    
    :root {
        --bg-primary: #121212;
        --bg-secondary: #1a1a1a;
        --text-primary: #E0E0E0;
        --text-secondary: #B0B0B0;
        --border-color: #444444;
        --accent-color: #888888;
    }
    
    .stApp {
        background: linear-gradient(135deg, #121212 0%, #1a1a1a 100%);
        color: var(--text-primary);
    }
    
    .download-hero {
        text-align: center;
        padding: 4rem 2rem;
        background: linear-gradient(135deg, rgba(136, 136, 136, 0.1) 0%, rgba(68, 68, 68, 0.1) 100%);
        border-radius: 20px;
        margin: 2rem 0;
        border: 1px solid var(--border-color);
    }
    
    .download-hero h1 {
        font-size: 3.5rem;
        font-weight: 800;
        background: linear-gradient(135deg, #E0E0E0 0%, #888888 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 1rem;
    }
    
    .feature-card {
        background: rgba(26, 26, 26, 0.8);
        border: 1px solid var(--border-color);
        border-radius: 15px;
        padding: 2rem;
        margin: 1rem 0;
        transition: transform 0.3s ease, box-shadow 0.3s ease;
    }
    
    .feature-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 10px 30px rgba(136, 136, 136, 0.2);
    }
    
    .download-button {
        background: linear-gradient(135deg, #888888 0%, #444444 100%);
        color: white;
        padding: 1rem 3rem;
        border-radius: 10px;
        font-size: 1.2rem;
        font-weight: 600;
        border: none;
        cursor: pointer;
        transition: transform 0.2s ease;
    }
    
    .download-button:hover {
        transform: scale(1.05);
    }
    
    .step-box {
        background: rgba(26, 26, 26, 0.6);
        border-left: 4px solid var(--accent-color);
        padding: 1.5rem;
        margin: 1rem 0;
        border-radius: 5px;
    }
</style>
""", unsafe_allow_html=True)

def main():
    """Render the public download page."""
    
    # Hero Section
    st.markdown("""
    <div class="download-hero">
        <h1>🛡️ Real-Time Attack Detection System</h1>
        <p style="font-size: 1.3rem; color: var(--text-secondary); margin-top: 1rem;">
            Protect your network with advanced real-time attack detection and monitoring
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Main Content
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("## 📦 Download Extension")
        st.markdown("""
        <div class="feature-card">
            <h3>🚀 Standalone Extension Package</h3>
            <p style="color: var(--text-secondary);">
                Download the complete attack detection system as a standalone executable. 
                Install it on your machine and get your own isolated dashboard and monitoring system.
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        # Check if extension package exists
        extension_dir = project_root / "extension_build"
        exe_path = None
        
        if extension_dir.exists():
            # Look for .exe file (Windows)
            exe_files = list(extension_dir.glob("*.exe"))
            if exe_files:
                exe_path = exe_files[0]
            else:
                # Look for other executable formats
                for ext in ["*.app", "*.bin", "*.run"]:
                    files = list(extension_dir.glob(ext))
                    if files:
                        exe_path = files[0]
                        break
        
        if exe_path and exe_path.exists():
            st.success(f"✅ Extension package ready: `{exe_path.name}`")
            
            # Read file for download
            with open(exe_path, "rb") as f:
                file_bytes = f.read()
            
            st.download_button(
                label="⬇️ Download Extension (Standalone)",
                data=file_bytes,
                file_name=exe_path.name,
                mime="application/octet-stream",
                use_container_width=True,
                key="download_extension"
            )
            
            file_size_mb = exe_path.stat().st_size / (1024 * 1024)
            st.caption(f"📦 File size: {file_size_mb:.1f} MB")
        else:
            st.warning("⚠️ Extension package not yet built. Please build it first using the build script.")
            st.info("💡 To build the extension, run: `python build_extension.py`")
        
        st.markdown("---")
        
        # Installation Instructions
        st.markdown("## 📋 Installation Instructions")
        
        st.markdown("""
        <div class="step-box">
            <h4>Step 1: Download</h4>
            <p>Click the download button above to get the standalone extension package.</p>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
        <div class="step-box">
            <h4>Step 2: Install</h4>
            <p><strong>Windows:</strong> Run the downloaded .exe file and follow the installation wizard.</p>
            <p><strong>Linux/Mac:</strong> Extract the package and run the installer script.</p>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
        <div class="step-box">
            <h4>Step 3: Configure</h4>
            <p>On first launch, the configuration wizard will guide you through:</p>
            <ul>
                <li>Network interface selection</li>
                <li>Detection threshold settings</li>
                <li>Alert preferences</li>
                <li>Dashboard password setup</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
        <div class="step-box">
            <h4>Step 4: Start Monitoring</h4>
            <p>Launch the system and start monitoring your network in real-time!</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("## ✨ Features")
        
        features = [
            ("🔍 Real-Time Detection", "Detects 20+ types of cyber attacks instantly"),
            ("📊 Live Dashboard", "Beautiful web dashboard with real-time graphs"),
            ("🚨 Smart Alerts", "Desktop and Telegram notifications"),
            ("🛡️ Active Defense", "Automated IP blocking and threat response"),
            ("📈 Analytics", "Comprehensive attack analytics and reporting"),
            ("💾 Export Data", "CSV, JSON, PDF, ElasticSearch, Grafana exports"),
            ("🌐 Threat Intel", "Shodan integration for IP intelligence"),
            ("📡 Packet Analysis", "Live packet capture and visualization")
        ]
        
        for icon_title, description in features:
            st.markdown(f"""
            <div class="feature-card">
                <h4>{icon_title}</h4>
                <p style="color: var(--text-secondary); font-size: 0.9rem;">{description}</p>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("---")
        st.markdown("## 🔒 Privacy")
        st.info("""
        **Your data is completely isolated:**
        - Each installation has its own database
        - No data sharing between users
        - All processing happens locally
        - No cloud dependencies
        """)
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: var(--text-secondary); padding: 2rem;">
        <p>🛡️ Real-Time Attack Detection System for Cyber-Physical Systems</p>
        <p style="font-size: 0.9rem;">Version 1.0 • Built with ❤️ for Network Security</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()

