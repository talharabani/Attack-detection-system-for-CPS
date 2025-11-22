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
    print(f"Download page will open at: http://localhost:8501")
    print("Users visiting this URL will see the download page")
    print("They will NOT see your private dashboard")
    print("=" * 60)
    print("Press Ctrl+C to stop")
    print("=" * 60)
    
    try:
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", str(download_path),
            "--server.port", "8501",
            "--server.headless", "false"
        ])
    except KeyboardInterrupt:
        print("\nDownload page stopped.")
    except Exception as e:
        print(f"Error starting download page: {e}")
        print("\nMake sure Streamlit is installed:")
        print("  pip install streamlit plotly pandas")

if __name__ == "__main__":
    main()

