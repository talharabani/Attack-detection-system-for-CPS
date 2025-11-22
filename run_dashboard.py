"""
Launch the Real-Time Web Dashboard with routing support.
- Default route (/) shows public download page
- /dashboard route shows private dashboard (password protected)
"""

import subprocess
import sys
from pathlib import Path
import os

def main():
    """Launch Streamlit dashboard with routing."""
    project_root = Path(__file__).parent
    
    # Check if we should show download page or dashboard
    # Use environment variable or command line argument
    show_download = os.environ.get("SHOW_DOWNLOAD", "false").lower() == "true"
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "download":
            show_download = True
        elif sys.argv[1] == "dashboard":
            show_download = False
    
    if show_download:
        # Show public download page
        dashboard_path = project_root / "dashboard" / "download_page.py"
        print("=" * 60)
        print("🛡️ Public Download Page")
        print("=" * 60)
        print(f"Download page will open at: http://localhost:8501")
        print("Users can download the extension from here")
        print("=" * 60)
    else:
        # Show private dashboard
        dashboard_path = project_root / "dashboard" / "app.py"
        print("=" * 60)
        print("🛡️ Private Dashboard")
        print("=" * 60)
        print(f"Dashboard will open at: http://localhost:8501")
        print("This is the private dashboard (password protected)")
        print("Press Ctrl+C to stop the dashboard")
        print("=" * 60)
    
    try:
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", str(dashboard_path),
            "--server.port", "8501",
            "--server.headless", "false"
        ])
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    except Exception as e:
        print(f"Error starting dashboard: {e}")
        print("\nMake sure Streamlit is installed:")
        print("  pip install streamlit plotly pandas")

if __name__ == "__main__":
    main()
