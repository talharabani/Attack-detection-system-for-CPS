"""
Launch the Real-Time Web Dashboard.
Run this script to start the Streamlit dashboard.
"""

import subprocess
import sys
from pathlib import Path

def main():
    """Launch Streamlit dashboard."""
    dashboard_path = Path(__file__).parent / "dashboard" / "app.py"
    
    print("=" * 60)
    print("Starting RealTime Attack Detection Dashboard")
    print("=" * 60)
    print(f"Dashboard will open at: http://localhost:8501")
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

