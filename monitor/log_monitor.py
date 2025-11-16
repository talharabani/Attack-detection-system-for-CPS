"""
Log file monitor for Linux and Windows systems.
Monitors authentication logs and system logs for suspicious activities.
"""

import threading
import time
import os
import sys
import platform
from typing import Callable, Optional, List
from pathlib import Path
import logging

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    logging.warning("Watchdog not available. Log monitoring may be limited.")

# Windows-specific imports
if sys.platform == 'win32':
    try:
        import win32evtlog
        import win32evtlogutil
        import win32con
        WINDOWS_EVENT_LOG_AVAILABLE = True
    except ImportError:
        WINDOWS_EVENT_LOG_AVAILABLE = False
        logging.warning("pywin32 not available. Windows event log monitoring disabled.")
else:
    WINDOWS_EVENT_LOG_AVAILABLE = False

from utils.helper import load_config


logger = logging.getLogger(__name__)


class LogFileHandler(FileSystemEventHandler):
    """
    File system event handler for log file monitoring.
    """
    
    def __init__(self, log_callback: Callable, log_path: str):
        """
        Initialize log file handler.
        
        Args:
            log_callback: Function to call when new log entries are detected
            log_path: Path to the log file being monitored
        """
        self.log_callback = log_callback
        self.log_path = log_path
        self.last_position = self._get_file_size()
    
    def _get_file_size(self) -> int:
        """Get current file size."""
        try:
            return os.path.getsize(self.log_path)
        except OSError:
            return 0
    
    def on_modified(self, event):
        """Handle file modification event."""
        if event.src_path == self.log_path and not event.is_directory:
            self._read_new_lines()
    
    def _read_new_lines(self):
        """Read new lines from log file."""
        try:
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Seek to last known position
                f.seek(self.last_position)
                
                # Read new lines
                new_lines = f.readlines()
                
                if new_lines:
                    for line in new_lines:
                        line = line.strip()
                        if line:
                            self.log_callback(line, self.log_path)
                    
                    # Update position
                    self.last_position = f.tell()
        
        except Exception as e:
            logger.error(f"Error reading log file {self.log_path}: {e}")


class LogMonitor:
    """
    Monitor log files for suspicious activities.
    Supports both Linux and Windows log monitoring.
    """
    
    def __init__(self, log_callback: Callable):
        """
        Initialize log monitor.
        
        Args:
            log_callback: Function to call when log entry is detected
        """
        self.log_callback = log_callback
        self.running = False
        self.observer = None
        self.windows_event_thread = None
        self.log_handlers = []
        
        # Load configuration
        try:
            self.config = load_config()
            self.linux_auth_log = self.config.get("logs", {}).get("linux_auth_log", "/var/log/auth.log")
            self.linux_syslog = self.config.get("logs", {}).get("linux_syslog", "/var/log/syslog")
            self.windows_event_log = self.config.get("logs", {}).get("windows_event_log", "Security")
        except Exception as e:
            logger.warning(f"Could not load config: {e}")
            self.linux_auth_log = "/var/log/auth.log"
            self.linux_syslog = "/var/log/syslog"
            self.windows_event_log = "Security"
    
    def _monitor_linux_log(self, log_path: str):
        """
        Monitor Linux log file using watchdog.
        
        Args:
            log_path: Path to log file
        """
        if not WATCHDOG_AVAILABLE:
            logger.error("Watchdog not available. Cannot monitor log files.")
            return
        
        if not os.path.exists(log_path):
            logger.warning(f"Log file does not exist: {log_path}")
            return
        
        try:
            log_dir = os.path.dirname(log_path)
            handler = LogFileHandler(self.log_callback, log_path)
            self.log_handlers.append(handler)
            
            observer = Observer()
            observer.schedule(handler, log_dir, recursive=False)
            observer.start()
            
            logger.info(f"Monitoring Linux log: {log_path}")
            
            # Keep observer running
            while self.running:
                time.sleep(1)
            
            observer.stop()
            observer.join()
        
        except Exception as e:
            logger.error(f"Error monitoring Linux log {log_path}: {e}")
    
    def _monitor_windows_event_log(self):
        """
        Monitor Windows Event Log for security events.
        """
        if not WINDOWS_EVENT_LOG_AVAILABLE:
            logger.warning("Windows event log monitoring not available")
            return
        
        try:
            # Open event log
            hand = win32evtlog.OpenEventLog(None, self.windows_event_log)
            
            # Read events in a loop
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            logger.info(f"Monitoring Windows Event Log: {self.windows_event_log}")
            
            last_read = 0
            
            while self.running:
                events = win32evtlog.ReadEventLog(hand, flags, last_read)
                
                if events:
                    for event in events:
                        # Filter for security-related events (failed logins, etc.)
                        event_id = event.EventID
                        event_strings = event.StringInserts
                        
                        # Event IDs for failed logins: 4625, 4776
                        if event_id in [4625, 4776, 4648, 4624]:
                            log_entry = f"EventID: {event_id}, Time: {event.TimeGenerated}, Strings: {event_strings}"
                            self.log_callback(log_entry, "WindowsEventLog")
                    
                    last_read = events[-1].RecordNumber
                
                time.sleep(2)  # Check every 2 seconds
            
            win32evtlog.CloseEventLog(hand)
        
        except Exception as e:
            logger.error(f"Error monitoring Windows event log: {e}")
    
    def start(self):
        """Start log monitoring."""
        if self.running:
            logger.warning("Log monitor is already running")
            return
        
        self.running = True
        system = platform.system()
        
        if system == "Linux":
            # Monitor Linux auth log
            if os.path.exists(self.linux_auth_log):
                thread = threading.Thread(
                    target=self._monitor_linux_log,
                    args=(self.linux_auth_log,),
                    daemon=True
                )
                thread.start()
            
            # Monitor syslog if different from auth.log
            if os.path.exists(self.linux_syslog) and self.linux_syslog != self.linux_auth_log:
                thread = threading.Thread(
                    target=self._monitor_linux_log,
                    args=(self.linux_syslog,),
                    daemon=True
                )
                thread.start()
        
        elif system == "Windows":
            # Monitor Windows Event Log
            if WINDOWS_EVENT_LOG_AVAILABLE:
                self.windows_event_thread = threading.Thread(
                    target=self._monitor_windows_event_log,
                    daemon=True
                )
                self.windows_event_thread.start()
            else:
                logger.warning("Windows event log monitoring requires pywin32")
        
        else:
            logger.warning(f"Unsupported operating system: {system}")
        
        logger.info("Log monitor started")
    
    def stop(self):
        """Stop log monitoring."""
        if not self.running:
            return
        
        self.running = False
        
        if self.windows_event_thread:
            self.windows_event_thread.join(timeout=5)
        
        logger.info("Log monitor stopped")

