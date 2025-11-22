"""
Public Download Page for Attack Detection System Extension.
Users visiting the root URL will see this page instead of the private dashboard.

IMPORTANT: This is a PUBLIC page - NO PASSWORD REQUIRED!
"""

import streamlit as st
from pathlib import Path
import sys
import os

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# CRITICAL: Clear any authentication state to ensure this is truly public
if "authenticated" in st.session_state:
    del st.session_state.authenticated

# Page configuration - CRITICAL: This must be set BEFORE any other Streamlit calls
st.set_page_config(
    page_title="🛡️ Download Attack Detection System - PUBLIC PAGE",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
    menu_items={
        'Get Help': None,
        'Report a bug': None,
        'About': "Public Download Page - No Password Required"
    }
)

# CRITICAL: Ensure this is the main entry point and not app.py
# Verify we're running the correct file
try:
    import __main__
    if hasattr(__main__, '__file__'):
        current_file = Path(__main__.__file__).name
        if 'download_page' not in current_file.lower():
            # This shouldn't happen, but if it does, show an error
            st.error(f"❌ ERROR: Wrong file loaded! Expected download_page.py but got {current_file}")
            st.stop()
except:
    pass  # If we can't check, continue anyway

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
    """Render the public download page - NO PASSWORD REQUIRED."""
    
    # IMPORTANT: This is a PUBLIC page - no authentication needed
    # Clear any authentication state that might have been set
    if "authenticated" in st.session_state:
        del st.session_state.authenticated
    
    # BIG WARNING if password check appears (should never happen)
    st.markdown("""
    <div style="text-align: center; padding: 2rem; background: rgba(39, 174, 96, 0.2); border: 3px solid #27ae60; border-radius: 15px; margin-bottom: 2rem;">
        <h1 style="color: #27ae60; margin: 0; font-size: 2.5rem;">✅ PUBLIC DOWNLOAD PAGE</h1>
        <h2 style="color: #E0E0E0; margin: 0.5rem 0 0 0;">🔓 NO PASSWORD REQUIRED - OPEN ACCESS</h2>
        <p style="color: #B0B0B0; margin: 1rem 0 0 0; font-size: 1.1rem;">If you see a password prompt, something is wrong!</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Additional header
    st.markdown("""
    <div style="text-align: center; padding: 1rem; background: rgba(136, 136, 136, 0.2); border-radius: 10px; margin-bottom: 2rem;">
        <h2 style="color: #E0E0E0; margin: 0;">📥 Download Extension Here</h2>
        <p style="color: #B0B0B0; margin: 0.5rem 0 0 0;">This is the public download page for users - completely open access</p>
    </div>
    """, unsafe_allow_html=True)
    
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
        
        # Always show download section
        st.markdown("### ⬇️ Download Extension")
        
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
            try:
                with open(exe_path, "rb") as f:
                    file_bytes = f.read()
                
                st.download_button(
                    label="⬇️ Download Extension (Standalone Executable)",
                    data=file_bytes,
                    file_name=exe_path.name,
                    mime="application/octet-stream",
                    use_container_width=True,
                    key="download_extension"
                )
                
                file_size_mb = exe_path.stat().st_size / (1024 * 1024)
                st.caption(f"📦 File size: {file_size_mb:.1f} MB")
            except Exception as e:
                st.error(f"Error reading extension file: {e}")
        else:
            # Show download options even if extension not built
            st.warning("⚠️ Standalone executable not yet built.")
            
            # Option 1: Download source code
            st.markdown("#### 📥 Download Source Code (Alternative)")
            st.info("""
            **You can download the complete source code and run it directly:**
            - All features included
            - Requires Python 3.7+
            - Install dependencies: `pip install -r requirements.txt`
            - Run: `python main.py` for detection, `python run_dashboard.py` for dashboard
            """)
            
            # Create a zip of the project for download
            import zipfile
            import io
            
            try:
                # Create zip in memory
                zip_buffer = io.BytesIO()
                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                    # Add key files
                    key_files = [
                        'main.py', 'config.json', 'requirements.txt', 'README.md',
                        'run_dashboard.py', 'run_public_download.py'
                    ]
                    key_dirs = ['dashboard', 'detectors', 'monitor', 'alerts', 'utils', 'auto_response', 'threat_intel']
                    
                    for file in key_files:
                        file_path = project_root / file
                        if file_path.exists():
                            zip_file.write(file_path, file)
                    
                    for dir_name in key_dirs:
                        dir_path = project_root / dir_name
                        if dir_path.exists() and dir_path.is_dir():
                            for file_path in dir_path.rglob('*.py'):
                                if '__pycache__' not in str(file_path):
                                    zip_file.write(file_path, file_path.relative_to(project_root))
                
                zip_buffer.seek(0)
                
                st.download_button(
                    label="⬇️ Download Source Code (ZIP)",
                    data=zip_buffer.getvalue(),
                    file_name="AttackDetectionSystem-Source.zip",
                    mime="application/zip",
                    use_container_width=True,
                    key="download_source"
                )
                st.caption("📦 Contains all source code files")
            except Exception as e:
                st.error(f"Error creating source package: {e}")
            
            st.markdown("---")
            st.markdown("#### 🔨 Build Standalone Executable")
            st.info("""
            **To create a standalone executable (no Python required):**
            1. Run: `python build_extension.py`
            2. Wait for build to complete
            3. Find executable in `extension_build/` folder
            4. The download button will appear here automatically
            """)
        
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

# CRITICAL: This must be called directly, not imported
if __name__ == "__main__":
    # Double-check we're running the right file
    import sys
    if 'app.py' in sys.argv[0] or 'app.py' in str(Path(__file__).name):
        st.error("❌ ERROR: app.py is being loaded instead of download_page.py!")
        st.error("Please run: python run_public_download.py")
        st.stop()
    
    # Run the main function
    main()
else:
    # If imported, still run main() to ensure it works
    main()

