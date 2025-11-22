"""
Launch the public download page.
This is what users see when they visit your website.
"""

import subprocess
import sys
from pathlib import Path

def main():
    """Launch public download page."""
    project_root = Path(__file__).parent
    download_path = project_root / "dashboard" / "download_page.py"
    
    print("=" * 60)
    print("🛡️ Public Download Page")
    print("=" * 60)
    
    # Print the exact file being run for debugging
    abs_path = download_path.absolute()
    print(f"📄 Running file: {download_path.name}")
    print(f"📂 Full path: {abs_path}")
    print(f"✅ File exists: {download_path.exists()}")
    print()
    
    # Use port 8502 to avoid conflicts with dashboard
    port = "8502"
    print(f"🌐 Download page will open at: http://localhost:{port}")
    print("📥 Users visiting this URL will see the download page")
    print("🔒 They will NOT see your private dashboard")
    print("=" * 60)
    print("Press Ctrl+C to stop")
    print("=" * 60)
    print()
    
    try:
        # Use absolute path and explicitly specify the file
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", str(abs_path),
            "--server.port", port,
            "--server.headless", "false",
            "--server.fileWatcherType", "none",  # Disable file watching to prevent conflicts
            "--browser.gatherUsageStats", "false"
        ])
    except KeyboardInterrupt:
        print("\nDownload page stopped.")
    except Exception as e:
        print(f"Error starting download page: {e}")
        print("\nMake sure Streamlit is installed:")
        print("  pip install streamlit plotly pandas")

if __name__ == "__main__":
    main()

