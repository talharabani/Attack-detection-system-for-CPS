"""
Active Defense / Auto-Response System (IPS - Intrusion Prevention System).
Automatically blocks attacks and mitigates threats.
"""

import subprocess
import platform
import logging
import time
import psutil
from typing import Dict, List, Optional
from pathlib import Path

from utils.helper import load_config, is_valid_ip


logger = logging.getLogger(__name__)


class ActiveDefense:
    """
    Active defense system that automatically responds to detected attacks.
    Implements IPS (Intrusion Prevention System) capabilities.
    """
    
    def __init__(self):
        """Initialize active defense system."""
        self.enabled = True
        self.system = platform.system()
        self.blocked_ips = set()
        self.killed_processes = []
        self.locked_accounts = set()
        
        # Load configuration
        try:
            config = load_config()
            auto_response_config = config.get("auto_response", {})
            self.enabled = auto_response_config.get("enabled", True)
            self.auto_block_ips = auto_response_config.get("auto_block_ips", True)
            self.auto_kill_processes = auto_response_config.get("auto_kill_processes", True)
            self.auto_disable_interface = auto_response_config.get("auto_disable_interface", False)
            self.auto_lock_accounts = auto_response_config.get("auto_lock_accounts", True)
            self.auto_restart_services = auto_response_config.get("auto_restart_services", False)
            self.block_duration_minutes = auto_response_config.get("block_duration_minutes", 60)
            self.whitelist_ips = set(auto_response_config.get("whitelist_ips", []))
            self.protected_services = auto_response_config.get("protected_services", [])
        except Exception as e:
            logger.warning(f"Could not load config: {e}")
            self.auto_block_ips = True
            self.auto_kill_processes = True
            self.auto_disable_interface = False
            self.auto_lock_accounts = True
            self.auto_restart_services = False
            self.block_duration_minutes = 60
            self.whitelist_ips = set()
            self.protected_services = []
        
        logger.info(f"Active defense system initialized (enabled: {self.enabled})")
    
    def block_ip_windows(self, ip: str) -> bool:
        """
        Block IP address using Windows firewall.
        
        Args:
            ip: IP address to block
            
        Returns:
            True if successful, False otherwise
        """
        if not is_valid_ip(ip):
            return False
        
        try:
            # Create firewall rule to block IP
            rule_name = f"BlockAttack_{ip.replace('.', '_')}"
            
            # Check if rule already exists
            check_cmd = [
                "netsh", "advfirewall", "firewall", "show", "rule",
                f"name={rule_name}"
            ]
            
            result = subprocess.run(
                check_cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and rule_name in result.stdout:
                logger.info(f"IP {ip} already blocked")
                return True
            
            # Create blocking rule
            block_cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip}",
                "enable=yes"
            ]
            
            result = subprocess.run(
                block_cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                self.blocked_ips.add(ip)
                logger.warning(f"✓ Blocked IP {ip} using Windows firewall")
                return True
            else:
                logger.error(f"Failed to block IP {ip}: {result.stderr}")
                return False
        
        except Exception as e:
            logger.error(f"Error blocking IP {ip} on Windows: {e}")
            return False
    
    def block_ip_linux(self, ip: str) -> bool:
        """
        Block IP address using Linux iptables.
        
        Args:
            ip: IP address to block
            
        Returns:
            True if successful, False otherwise
        """
        if not is_valid_ip(ip):
            return False
        
        try:
            # Check if rule already exists
            check_cmd = ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"]
            result = subprocess.run(check_cmd, capture_output=True, timeout=5)
            
            if result.returncode == 0:
                logger.info(f"IP {ip} already blocked")
                return True
            
            # Add blocking rule
            block_cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            result = subprocess.run(
                block_cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                self.blocked_ips.add(ip)
                logger.warning(f"✓ Blocked IP {ip} using iptables")
                return True
            else:
                logger.error(f"Failed to block IP {ip}: {result.stderr}")
                return False
        
        except Exception as e:
            logger.error(f"Error blocking IP {ip} on Linux: {e}")
            return False
    
    def block_ip(self, ip: str) -> bool:
        """
        Block IP address using system firewall.
        
        Args:
            ip: IP address to block
            
        Returns:
            True if successful, False otherwise
        """
        if not self.enabled or not self.auto_block_ips:
            return False
        
        if ip in self.whitelist_ips:
            logger.info(f"IP {ip} is whitelisted, not blocking")
            return False
        
        if ip in self.blocked_ips:
            logger.info(f"IP {ip} already blocked")
            return True
        
        if self.system == "Windows":
            return self.block_ip_windows(ip)
        elif self.system == "Linux":
            return self.block_ip_linux(ip)
        else:
            logger.warning(f"IP blocking not supported on {self.system}")
            return False
    
    def kill_process(self, pid: int, process_name: str = None) -> bool:
        """
        Kill a suspicious process.
        
        Args:
            pid: Process ID
            process_name: Process name (optional)
            
        Returns:
            True if successful, False otherwise
        """
        if not self.enabled or not self.auto_kill_processes:
            return False
        
        try:
            process = psutil.Process(pid)
            
            # Don't kill critical system processes
            if process_name and any(critical in process_name.lower() for critical in 
                                   ['system', 'kernel', 'init', 'winlogon', 'csrss']):
                logger.warning(f"Not killing critical process: {process_name} (PID: {pid})")
                return False
            
            # Kill the process
            process.terminate()
            time.sleep(1)
            
            # Force kill if still running
            if process.is_running():
                process.kill()
            
            self.killed_processes.append({
                "pid": pid,
                "name": process_name or process.name(),
                "timestamp": time.time()
            })
            
            logger.warning(f"✓ Killed suspicious process: {process_name or 'Unknown'} (PID: {pid})")
            return True
        
        except psutil.NoSuchProcess:
            logger.info(f"Process {pid} already terminated")
            return True
        except psutil.AccessDenied:
            logger.error(f"Access denied when trying to kill process {pid}")
            return False
        except Exception as e:
            logger.error(f"Error killing process {pid}: {e}")
            return False
    
    def disable_network_interface(self, interface_name: str) -> bool:
        """
        Temporarily disable a network interface.
        
        Args:
            interface_name: Name of network interface
            
        Returns:
            True if successful, False otherwise
        """
        if not self.enabled or not self.auto_disable_interface:
            return False
        
        try:
            if self.system == "Windows":
                cmd = ["netsh", "interface", "set", "interface", 
                      f"name={interface_name}", "admin=disable"]
            elif self.system == "Linux":
                cmd = ["ifdown", interface_name]
            else:
                logger.warning(f"Interface disabling not supported on {self.system}")
                return False
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                logger.warning(f"✓ Disabled network interface: {interface_name}")
                return True
            else:
                logger.error(f"Failed to disable interface {interface_name}: {result.stderr}")
                return False
        
        except Exception as e:
            logger.error(f"Error disabling interface {interface_name}: {e}")
            return False
    
    def lock_user_account(self, username: str) -> bool:
        """
        Lock a user account after brute force attempts.
        
        Args:
            username: Username to lock
            
        Returns:
            True if successful, False otherwise
        """
        if not self.enabled or not self.auto_lock_accounts:
            return False
        
        if username in self.locked_accounts:
            logger.info(f"Account {username} already locked")
            return True
        
        try:
            if self.system == "Windows":
                # Windows: Use net user command
                cmd = ["net", "user", username, "/active:no"]
            elif self.system == "Linux":
                # Linux: Use usermod or passwd
                cmd = ["usermod", "-L", username]
            else:
                logger.warning(f"Account locking not supported on {self.system}")
                return False
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                self.locked_accounts.add(username)
                logger.warning(f"✓ Locked user account: {username}")
                return True
            else:
                logger.error(f"Failed to lock account {username}: {result.stderr}")
                return False
        
        except Exception as e:
            logger.error(f"Error locking account {username}: {e}")
            return False
    
    def restart_service(self, service_name: str) -> bool:
        """
        Restart an important system service.
        
        Args:
            service_name: Name of service to restart
            
        Returns:
            True if successful, False otherwise
        """
        if not self.enabled or not self.auto_restart_services:
            return False
        
        if service_name in self.protected_services:
            logger.warning(f"Service {service_name} is protected, not restarting")
            return False
        
        try:
            if self.system == "Windows":
                # Stop service
                subprocess.run(
                    ["net", "stop", service_name],
                    capture_output=True,
                    timeout=30
                )
                time.sleep(2)
                # Start service
                result = subprocess.run(
                    ["net", "start", service_name],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            elif self.system == "Linux":
                result = subprocess.run(
                    ["systemctl", "restart", service_name],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            else:
                logger.warning(f"Service restart not supported on {self.system}")
                return False
            
            if result.returncode == 0:
                logger.warning(f"✓ Restarted service: {service_name}")
                return True
            else:
                logger.error(f"Failed to restart service {service_name}: {result.stderr}")
                return False
        
        except Exception as e:
            logger.error(f"Error restarting service {service_name}: {e}")
            return False
    
    def handle_attack(self, attack_info: Dict):
        """
        Automatically respond to detected attack.
        
        Args:
            attack_info: Dictionary containing attack information
        """
        if not self.enabled:
            return
        
        attack_type = attack_info.get("attack_type", "")
        src_ip = attack_info.get("src_ip")
        severity = attack_info.get("severity", "UNKNOWN")
        
        logger.info(f"Active defense responding to {attack_type} from {src_ip}")
        
        # Block IP for high severity attacks
        if severity in ["HIGH", "CRITICAL"] and src_ip and src_ip != "unknown":
            self.block_ip(src_ip)
        
        # Kill suspicious process if detected
        pid = attack_info.get("pid")
        process_name = attack_info.get("process_name")
        if pid and self.auto_kill_processes:
            self.kill_process(pid, process_name)
        
        # Lock account for brute force attacks
        if attack_type == "Brute Force Login":
            username = attack_info.get("usernames_attempted", [])
            if username and isinstance(username, list) and len(username) > 0:
                self.lock_user_account(username[0])
        
        # Additional responses based on attack type
        if attack_type == "CPS Attack":
            # For CPS attacks, might want to disable interface
            if self.auto_disable_interface:
                # Get interface from attack info if available
                interface = attack_info.get("interface")
                if interface:
                    self.disable_network_interface(interface)
    
    def get_statistics(self) -> Dict:
        """
        Get active defense statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            "enabled": self.enabled,
            "blocked_ips_count": len(self.blocked_ips),
            "blocked_ips": list(self.blocked_ips),
            "killed_processes_count": len(self.killed_processes),
            "locked_accounts_count": len(self.locked_accounts),
            "locked_accounts": list(self.locked_accounts)
        }

