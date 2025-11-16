"""
Process monitoring for detecting suspicious system processes.
Monitors CPU and network usage of running processes.
"""

import threading
import time
from typing import Callable, Dict, List, Optional
import logging
import platform

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logging.warning("psutil not available. Process monitoring will be disabled.")

from utils.helper import load_config


logger = logging.getLogger(__name__)


class ProcessMonitor:
    """
    Monitor system processes for suspicious activity.
    Detects processes with high CPU or network usage.
    """
    
    def __init__(self, process_callback: Callable):
        """
        Initialize process monitor.
        
        Args:
            process_callback: Function to call when suspicious process is detected
        """
        if not PSUTIL_AVAILABLE:
            raise ImportError("psutil is required for process monitoring. Install with: pip install psutil")
        
        self.process_callback = process_callback
        self.running = False
        self.monitor_thread = None
        self.process_history = {}  # Track process usage over time
        
        # Load configuration
        try:
            config = load_config()
            process_config = config.get("detection", {}).get("process", {})
            self.cpu_threshold = process_config.get("cpu_threshold_percent", 80)
            self.network_threshold_mbps = process_config.get("network_threshold_mbps", 10)
            self.check_interval = process_config.get("check_interval_seconds", 5)
        except Exception as e:
            logger.warning(f"Could not load config: {e}")
            self.cpu_threshold = 80
            self.network_threshold_mbps = 10
            self.check_interval = 5
    
    def _get_process_info(self, proc: psutil.Process) -> Optional[Dict]:
        """
        Get detailed information about a process.
        
        Args:
            proc: psutil.Process object
            
        Returns:
            Dictionary with process information or None
        """
        try:
            # Get process details
            proc_info = {
                "pid": proc.pid,
                "name": proc.name(),
                "cpu_percent": proc.cpu_percent(interval=0.1),
                "memory_percent": proc.memory_percent(),
                "status": proc.status(),
                "create_time": proc.create_time(),
                "username": proc.username() if hasattr(proc, 'username') else "N/A"
            }
            
            # Get network I/O
            try:
                net_io = proc.io_counters()
                if net_io:
                    # Calculate network usage (bytes sent + received)
                    bytes_sent = net_io.write_bytes
                    bytes_recv = net_io.read_bytes
                    total_bytes = bytes_sent + bytes_recv
                    
                    proc_info["network_bytes_sent"] = bytes_sent
                    proc_info["network_bytes_recv"] = bytes_recv
                    proc_info["network_total_bytes"] = total_bytes
            except (psutil.AccessDenied, AttributeError):
                proc_info["network_bytes_sent"] = 0
                proc_info["network_bytes_recv"] = 0
                proc_info["network_total_bytes"] = 0
            
            # Get command line
            try:
                proc_info["cmdline"] = " ".join(proc.cmdline())
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                proc_info["cmdline"] = "N/A"
            
            # Get executable path
            try:
                proc_info["exe"] = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                proc_info["exe"] = "N/A"
            
            return proc_info
        
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
    
    def _calculate_network_speed(self, pid: int, current_bytes: int) -> float:
        """
        Calculate network speed in Mbps for a process.
        
        Args:
            pid: Process ID
            current_bytes: Current total network bytes
            
        Returns:
            Network speed in Mbps
        """
        current_time = time.time()
        
        if pid in self.process_history:
            prev_bytes, prev_time = self.process_history[pid]
            time_diff = current_time - prev_time
            
            if time_diff > 0:
                bytes_diff = current_bytes - prev_bytes
                # Convert bytes to bits, then to Mbps
                speed_mbps = (bytes_diff * 8) / (time_diff * 1_000_000)
                return speed_mbps
        
        # Update history
        self.process_history[pid] = (current_bytes, current_time)
        return 0.0
    
    def _check_processes(self):
        """
        Check all running processes for suspicious activity.
        """
        suspicious_processes = []
        
        try:
            # Get all processes
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_info = self._get_process_info(proc)
                    
                    if not proc_info:
                        continue
                    
                    # Check CPU usage
                    cpu_usage = proc_info["cpu_percent"]
                    is_cpu_suspicious = cpu_usage > self.cpu_threshold
                    
                    # Check network usage
                    network_bytes = proc_info.get("network_total_bytes", 0)
                    network_speed = self._calculate_network_speed(proc_info["pid"], network_bytes)
                    is_network_suspicious = network_speed > self.network_threshold_mbps
                    
                    # If process is suspicious, add to list
                    if is_cpu_suspicious or is_network_suspicious:
                        proc_info["network_speed_mbps"] = network_speed
                        proc_info["is_cpu_suspicious"] = is_cpu_suspicious
                        proc_info["is_network_suspicious"] = is_network_suspicious
                        suspicious_processes.append(proc_info)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        
        except Exception as e:
            logger.error(f"Error checking processes: {e}")
        
        # Report suspicious processes
        for proc_info in suspicious_processes:
            self.process_callback(proc_info)
        
        # Clean up old process history (keep only last 100 processes)
        if len(self.process_history) > 100:
            # Remove processes that no longer exist
            current_pids = {p.pid for p in psutil.process_iter(['pid'])}
            self.process_history = {
                pid: data for pid, data in self.process_history.items()
                if pid in current_pids
            }
    
    def _monitor_loop(self):
        """
        Main monitoring loop running in separate thread.
        """
        logger.info("Process monitor started")
        
        while self.running:
            try:
                self._check_processes()
                time.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"Error in process monitor loop: {e}")
                time.sleep(self.check_interval)
    
    def start(self):
        """Start process monitoring in a separate thread."""
        if self.running:
            logger.warning("Process monitor is already running")
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Process monitor started")
    
    def stop(self):
        """Stop process monitoring."""
        if not self.running:
            return
        
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        logger.info("Process monitor stopped")
    
    def get_system_stats(self) -> Dict:
        """
        Get overall system statistics.
        
        Returns:
            Dictionary with system statistics
        """
        try:
            return {
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage('/').percent if platform.system() != 'Windows' else psutil.disk_usage('C:\\').percent,
                "process_count": len(list(psutil.process_iter()))
            }
        except Exception as e:
            logger.error(f"Error getting system stats: {e}")
            return {}

