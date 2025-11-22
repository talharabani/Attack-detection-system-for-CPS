"""
RealTimeAttackDetection - Main Entry Point
Orchestrates all monitoring, detection, and alerting components.
"""

import sys
import signal
import threading
import time
import argparse
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from utils.helper import load_config, setup_logging
from utils.attack_logger import AttackLogger
from utils.notification_manager import NotificationManager
from monitor.network_sniffer import NetworkSniffer
from monitor.log_monitor import LogMonitor
from monitor.process_monitor import ProcessMonitor
from detectors.ddos_detector import DDoSDetector
from detectors.portscan_detector import PortScanDetector
from detectors.brute_force_detector import BruteForceDetector
from detectors.intrusion_detector import IntrusionDetector
from detectors.cps_detector import CPSDetector
from detectors.modbus_detector import ModbusDetector
from alerts.desktop_alert import DesktopAlert
from alerts.telegram_alert import TelegramAlert
from alerts.discord_alert import DiscordAlert
from auto_response.active_defense import ActiveDefense
from threat_intel.shodan_client import ShodanClient

import logging

logger = logging.getLogger(__name__)


class AttackDetectionSystem:
    """
    Main system orchestrator for real-time attack detection.
    """
    
    def __init__(self, config_path: str = "config.json"):
        """
        Initialize the attack detection system.
        
        Args:
            config_path: Path to configuration file
        """
        self.config = load_config(config_path)
        self.running = False
        
        # Initialize alert systems
        self.desktop_alert = DesktopAlert()
        self.telegram_alert = TelegramAlert()
        self.discord_alert = DiscordAlert()
        
        # Initialize active defense (IPS)
        self.active_defense = ActiveDefense()
        
        # Initialize attack logger (database)
        try:
            self.attack_logger = AttackLogger()
            logger.info("Attack logger initialized")
        except Exception as e:
            logger.error(f"Could not initialize attack logger: {e}")
            self.attack_logger = None
        
        # Initialize notification manager (rate limiting)
        try:
            rate_limit = self.config.get("alerts", {}).get("rate_limit_seconds", 60)
            self.notification_manager = NotificationManager(rate_limit_seconds=rate_limit)
            logger.info(f"Notification manager initialized (rate limit: {rate_limit}s)")
        except Exception as e:
            logger.error(f"Could not initialize notification manager: {e}")
            self.notification_manager = None
        
        # Initialize Shodan threat intelligence (optional)
        try:
            self.shodan_client = ShodanClient()
            if self.shodan_client.enabled:
                logger.info("Shodan threat intelligence enabled")
            else:
                logger.warning("Shodan threat intelligence disabled (no API key)")
        except Exception as e:
            logger.warning(f"Could not initialize Shodan client: {e}")
            self.shodan_client = None
        
        # Initialize detectors
        self.ddos_detector = DDoSDetector(self._handle_attack)
        self.portscan_detector = PortScanDetector(self._handle_attack)
        self.brute_force_detector = BruteForceDetector(self._handle_attack)
        self.intrusion_detector = IntrusionDetector(self._handle_attack)
        
        # Initialize CPS detectors
        self.cps_detector = CPSDetector(self._handle_attack)
        self.modbus_detector = ModbusDetector(self._handle_attack)
        
        # Initialize monitors
        self.network_sniffer = None
        self.log_monitor = None
        self.process_monitor = None
        
        # Statistics
        self.attack_count = 0
        self.start_time = None
        
        # Periodic cleanup task for notification manager
        self._last_cleanup_time = time.time()
    
    def _handle_attack(self, attack_info: dict):
        """
        Handle detected attack - send alerts and display in terminal.
        
        Args:
            attack_info: Dictionary containing attack information
        """
        self.attack_count += 1
        
        attack_type = attack_info.get("attack_type", "Unknown")
        attack_subtype = attack_info.get("attack_subtype", "")
        src_ip = attack_info.get("src_ip", "unknown")
        severity = attack_info.get("severity", "UNKNOWN")
        packet_count = attack_info.get("packet_count")
        packet_rate = attack_info.get("packet_rate", attack_info.get("packet_rate_pps"))
        protocol = attack_info.get("protocol", "Unknown")
        
        # Format human-readable attack details
        attack_details = []
        
        if attack_subtype:
            attack_details.append(f"Type: {attack_subtype}")
        
        if packet_count is not None:
            attack_details.append(f"Packets: {int(packet_count):,}")
        
        if packet_rate is not None and isinstance(packet_rate, (int, float)):
            attack_details.append(f"Rate: {packet_rate:.2f} PPS")
        
        if protocol and protocol != "Unknown":
            attack_details.append(f"Protocol: {protocol}")
        
        details_str = " | ".join(attack_details) if attack_details else ""
        
        # Enrich with Shodan threat intelligence
        shodan_data = None
        if self.shodan_client and self.shodan_client.enabled and src_ip != "unknown":
            try:
                shodan_data = self.shodan_client.enrich_attack_info(src_ip)
                if shodan_data:
                    attack_info["shodan_data"] = shodan_data
                    logger.info(f"Shodan enrichment completed for {src_ip}")
            except Exception as e:
                logger.warning(f"Shodan enrichment failed for {src_ip}: {e}")
        
        # Format packet count and rate for display
        packet_count_display = ""
        packet_rate_display = ""
        
        if packet_count is not None:
            if isinstance(packet_count, (int, float)):
                if packet_count >= 1000:
                    packet_count_display = f"{int(packet_count):,}+"
                else:
                    packet_count_display = f"{int(packet_count):,}"
            else:
                packet_count_display = str(packet_count)
        
        if packet_rate is not None and isinstance(packet_rate, (int, float)):
            if packet_rate >= 500:
                packet_rate_display = f"{int(packet_rate)}+"
            elif packet_rate >= 100:
                packet_rate_display = f"{int(packet_rate)}"
            else:
                packet_rate_display = f"{packet_rate:.1f}"
        
        # Print formatted attack alert to terminal (matching requested format)
        print("\n" + "=" * 80)
        print(f"🚨 [ATTACK #{self.attack_count}] {attack_type} detected!")
        print("=" * 80)
        print(f"Source: {src_ip}")
        
        # Display packet information if available
        if packet_count_display and packet_rate_display:
            print(f"Packets: {packet_count_display} | Rate: {packet_rate_display} PPS")
        elif packet_count_display:
            print(f"Packets: {packet_count_display}")
        elif packet_rate_display:
            print(f"Rate: {packet_rate_display} PPS")
        
        # Display additional attack-specific details
        if attack_type == "Port Scanning":
            port_count = attack_info.get("port_count", 0)
            if port_count:
                print(f"Ports Scanned: {port_count}")
            scanned_ports = attack_info.get("scanned_ports", [])
            if scanned_ports and len(scanned_ports) <= 20:
                ports_str = ", ".join(map(str, scanned_ports))
                print(f"Scanned Ports: {ports_str}")
        
        elif attack_type == "Ping Flood Attack":
            icmp_count = attack_info.get("packet_count", 0)
            if icmp_count:
                print(f"ICMP Packets: {int(icmp_count)}")
        
        elif attack_type == "Brute Force Login":
            attempt_count = attack_info.get("attempt_count", 0)
            if attempt_count:
                print(f"Failed Attempts: {attempt_count}")
            usernames = attack_info.get("usernames_attempted", [])
            if usernames:
                print(f"Targeted Users: {', '.join(usernames[:5])}")
        
        print(f"Severity: {severity}")
        if attack_subtype:
            print(f"Subtype: {attack_subtype}")
        if protocol and protocol != "Unknown":
            print(f"Protocol: {protocol}")
        
        # Display Shodan threat intelligence if available
        if shodan_data:
            print("\n" + "-" * 80)
            print("🔍 SHODAN THREAT INTELLIGENCE")
            print("-" * 80)
            ip_info = shodan_data.get("ip_info", {})
            
            if ip_info.get("org") and ip_info.get("org") != "Unknown":
                print(f"Organization:    {ip_info.get('org')}")
            if ip_info.get("isp") and ip_info.get("isp") != "Unknown":
                print(f"ISP:            {ip_info.get('isp')}")
            if ip_info.get("location", {}).get("country") and ip_info.get("location", {}).get("country") != "Unknown":
                location = ip_info.get("location", {})
                loc_str = location.get("country", "")
                if location.get("city") and location.get("city") != "Unknown":
                    loc_str += f", {location.get('city')}"
                print(f"Location:       {loc_str}")
            
            open_ports = ip_info.get("open_ports", [])
            if open_ports:
                ports_str = ", ".join(map(str, open_ports[:10]))  # Show first 10 ports
                if len(open_ports) > 10:
                    ports_str += f" (+{len(open_ports) - 10} more)"
                print(f"Open Ports:     {ports_str}")
            
            vulnerabilities = ip_info.get("vulnerabilities", [])
            if vulnerabilities:
                cves_str = ", ".join(vulnerabilities[:5])  # Show first 5 CVEs
                if len(vulnerabilities) > 5:
                    cves_str += f" (+{len(vulnerabilities) - 5} more)"
                print(f"Vulnerabilities: {cves_str}")
            
            tags = ip_info.get("tags", [])
            if tags:
                print(f"Tags:           {', '.join(tags[:5])}")
            
            threat_level = shodan_data.get("threat_level", "UNKNOWN")
            print(f"Threat Level:   {threat_level}")
            
            honeypot = shodan_data.get("honeypot")
            if honeypot and honeypot.get("honeypot_score") is not None:
                score = honeypot.get("honeypot_score", 0)
                print(f"Honeypot Score: {score:.2f} ({'Likely Real' if score < 0.3 else 'Possible Honeypot' if score < 0.7 else 'Likely Honeypot'})")
            
            exploits = shodan_data.get("exploits", [])
            if exploits:
                print(f"Available Exploits: {len(exploits)} found")
        
        print(f"Timestamp:       {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}")
        print("=" * 80 + "\n")
        
        # Also print simplified format for quick reference
        print(f"🚨 [ATTACK #{self.attack_count}] {attack_type} detected!")
        print(f"Source: {src_ip}")
        if packet_count_display and packet_rate_display:
            print(f"Packets: {packet_count_display} | Rate: {packet_rate_display} PPS")
        elif packet_count_display:
            print(f"Packets: {packet_count_display}")
        elif packet_rate_display:
            print(f"Rate: {packet_rate_display} PPS")
        print()  # Empty line for readability
        
        # Also log to file (include Shodan data if available)
        log_message = f"[ATTACK #{self.attack_count}] {attack_type} detected from {src_ip} (Severity: {severity}) {details_str}"
        if shodan_data:
            ip_info = shodan_data.get("ip_info", {})
            shodan_details = []
            if ip_info.get("org") and ip_info.get("org") != "Unknown":
                shodan_details.append(f"Org: {ip_info.get('org')}")
            if ip_info.get("open_ports"):
                shodan_details.append(f"Ports: {len(ip_info.get('open_ports', []))}")
            if ip_info.get("vulnerabilities"):
                shodan_details.append(f"CVEs: {len(ip_info.get('vulnerabilities', []))}")
            if shodan_details:
                log_message += f" | Shodan: {', '.join(shodan_details)}"
        logger.critical(log_message)
        
        # Log attack to database for dashboard
        if self.attack_logger:
            try:
                attack_details = {
                    "packet_count": packet_count,
                    "packet_rate": packet_rate,
                    "protocol": protocol,
                    "attack_subtype": attack_subtype,
                    "shodan_data": shodan_data
                }
                # Remove None values
                attack_details = {k: v for k, v in attack_details.items() if v is not None}
                
                self.attack_logger.log_attack(
                    attack_type=attack_type,
                    source_ip=src_ip,
                    severity=severity,
                    details=attack_details
                )
            except Exception as e:
                logger.error(f"Error logging attack to database: {e}")
        
        # Check rate limiting before sending notifications
        should_notify = True
        if self.notification_manager:
            should_notify = self.notification_manager.should_send_notification(src_ip, attack_info)
            if should_notify:
                self.notification_manager.record_notification(src_ip, attack_info)
            else:
                # Update attack status even if not notifying
                self.notification_manager.update_attack_status(src_ip, attack_info)
        
        # Send alerts only if rate limit allows
        if should_notify:
            # Send desktop alert
            self.desktop_alert.send_alert(attack_info)
            
            # Send Telegram alert
            self.telegram_alert.send_alert(attack_info)
            
            # Send Discord alert
            self.discord_alert.send_alert(attack_info)
        else:
            logger.debug(f"Notification rate-limited for {src_ip} ({attack_type})")
        
        # Auto-respond to attack (IPS - Active Defense)
        # This always runs regardless of notification rate limiting
        self.active_defense.handle_attack(attack_info)
    
    def _packet_handler(self, packet_info: dict):
        """
        Handle network packet from sniffer.
        
        Args:
            packet_info: Dictionary containing packet information
        """
        # Send to relevant detectors
        if self.ddos_detector.enabled:
            self.ddos_detector.analyze_packet(packet_info)
        
        if self.portscan_detector.enabled:
            self.portscan_detector.analyze_packet(packet_info)
        
        # Send to CPS detectors
        if self.cps_detector.enabled:
            self.cps_detector.analyze_packet(packet_info)
        
        if self.modbus_detector.enabled:
            self.modbus_detector.analyze_packet(packet_info)
    
    def _log_handler(self, log_line: str, log_source: str):
        """
        Handle log entry from log monitor.
        
        Args:
            log_line: Log line text
            log_source: Source of the log
        """
        # Send to relevant detectors
        if self.brute_force_detector.enabled:
            self.brute_force_detector.analyze_log_entry(log_line, log_source)
        
        if self.intrusion_detector.enabled:
            self.intrusion_detector.analyze_log_entry(log_line, log_source)
    
    def _process_handler(self, process_info: dict):
        """
        Handle process information from process monitor.
        
        Args:
            process_info: Dictionary containing process information
        """
        # Send to intrusion detector
        if self.intrusion_detector.enabled:
            self.intrusion_detector.analyze_process(process_info)
    
    def start(self):
        """Start all monitoring and detection systems."""
        if self.running:
            logger.warning("System is already running")
            return
        
        logger.info("=" * 60)
        logger.info("Starting RealTimeAttackDetection System")
        logger.info("=" * 60)
        
        self.running = True
        self.start_time = time.time()
        
        try:
            # Start network sniffer
            try:
                self.network_sniffer = NetworkSniffer(self._packet_handler)
                self.network_sniffer.start()
                logger.info("[OK] Network sniffer started")
                logger.info("[INFO] If you don't see packets being captured, check:")
                logger.info("   1. Running as Administrator?")
                logger.info("   2. Npcap installed? (Windows)")
                logger.info("   3. Network interface correct?")
            except Exception as e:
                logger.error(f"[ERROR] Failed to start network sniffer: {e}")
                logger.error("This is CRITICAL - attacks cannot be detected without packet capture!")
                import traceback
                logger.error(traceback.format_exc())
            
            # Start log monitor
            try:
                self.log_monitor = LogMonitor(self._log_handler)
                self.log_monitor.start()
                logger.info("[OK] Log monitor started")
            except Exception as e:
                logger.error(f"[ERROR] Failed to start log monitor: {e}")
            
            # Start process monitor
            try:
                self.process_monitor = ProcessMonitor(self._process_handler)
                self.process_monitor.start()
                logger.info("[OK] Process monitor started")
            except Exception as e:
                logger.error(f"[ERROR] Failed to start process monitor: {e}")
            
            # Print detector status
            logger.info("\nDetector Status:")
            logger.info(f"  - DDoS Detector: {'[ENABLED]' if self.ddos_detector.enabled else '[DISABLED]'}")
            logger.info(f"  - Port Scan Detector: {'[ENABLED]' if self.portscan_detector.enabled else '[DISABLED]'}")
            logger.info(f"  - Brute Force Detector: {'[ENABLED]' if self.brute_force_detector.enabled else '[DISABLED]'}")
            logger.info(f"  - Intrusion Detector: {'[ENABLED]' if self.intrusion_detector.enabled else '[DISABLED]'}")
            logger.info(f"  - CPS Detector: {'[ENABLED]' if self.cps_detector.enabled else '[DISABLED]'}")
            logger.info(f"  - Modbus Detector: {'[ENABLED]' if self.modbus_detector.enabled else '[DISABLED]'}")
            
            # Print alert status
            logger.info("\nAlert Status:")
            logger.info(f"  - Desktop Alerts: {'[ENABLED]' if self.desktop_alert.enabled else '[DISABLED]'}")
            logger.info(f"  - Telegram Alerts: {'[ENABLED]' if self.telegram_alert.enabled else '[DISABLED]'}")
            logger.info(f"  - Discord Alerts: {'[ENABLED]' if self.discord_alert.enabled else '[DISABLED]'}")
            
            # Print active defense status
            logger.info("\nActive Defense (IPS) Status:")
            logger.info(f"  - Auto-Response: {'[ENABLED]' if self.active_defense.enabled else '[DISABLED]'}")
            logger.info(f"  - Auto-Block IPs: {'[ENABLED]' if self.active_defense.auto_block_ips else '[DISABLED]'}")
            logger.info(f"  - Auto-Kill Processes: {'[ENABLED]' if self.active_defense.auto_kill_processes else '[DISABLED]'}")
            
            logger.info("\n" + "=" * 60)
            logger.info("System is running. Press Ctrl+C to stop.")
            logger.info("=" * 60 + "\n")
        
        except Exception as e:
            logger.error(f"Error starting system: {e}")
            self.stop()
            raise
    
    def stop(self):
        """Stop all monitoring and detection systems."""
        if not self.running:
            return
        
        logger.info("\nShutting down RealTimeAttackDetection System...")
        
        self.running = False
        
        # Stop monitors
        if self.network_sniffer:
            self.network_sniffer.stop()
            logger.info("[OK] Network sniffer stopped")
        
        if self.log_monitor:
            self.log_monitor.stop()
            logger.info("[OK] Log monitor stopped")
        
        if self.process_monitor:
            self.process_monitor.stop()
            logger.info("[OK] Process monitor stopped")
        
        # Print statistics
        elapsed = time.time() - self.start_time if self.start_time else 0
        logger.info(f"\nStatistics:")
        logger.info(f"  - Total attacks detected: {self.attack_count}")
        logger.info(f"  - Runtime: {elapsed:.2f} seconds")
        
        logger.info("System stopped.")
    
    def get_statistics(self) -> dict:
        """
        Get system statistics.
        
        Returns:
            Dictionary with system statistics
        """
        elapsed = time.time() - self.start_time if self.start_time else 0
        
        stats = {
            "running": self.running,
            "runtime_seconds": elapsed,
            "attacks_detected": self.attack_count,
            "detectors": {
                "ddos": self.ddos_detector.get_statistics(),
                "port_scan": self.portscan_detector.get_statistics(),
                "brute_force": self.brute_force_detector.get_statistics(),
                "intrusion": self.intrusion_detector.get_statistics()
            }
        }
        
        if self.network_sniffer:
            stats["network_sniffer"] = self.network_sniffer.get_statistics()
        
        if self.process_monitor:
            stats["process_monitor"] = self.process_monitor.get_system_stats()
        
        return stats


def signal_handler(sig, frame):
    """Handle interrupt signal (Ctrl+C)."""
    logger.info("\nReceived interrupt signal. Shutting down...")
    if 'system' in globals():
        system.stop()
    sys.exit(0)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="RealTimeAttackDetection - Real-time cyber attack detection system"
    )
    parser.add_argument(
        "-c", "--config",
        default="config.json",
        help="Path to configuration file (default: config.json)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging (DEBUG level)"
    )
    parser.add_argument(
        "--test-alerts",
        action="store_true",
        help="Test alert systems and exit"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = "DEBUG" if args.verbose else "INFO"
    try:
        config = load_config(args.config)
        log_level = config.get("general", {}).get("log_level", log_level)
        log_file = config.get("general", {}).get("log_file")
    except:
        log_file = None
    
    setup_logging(log_level, log_file)
    
    # Test alerts if requested
    if args.test_alerts:
        logger.info("Testing alert systems...")
        desktop_alert = DesktopAlert()
        telegram_alert = TelegramAlert()
        discord_alert = DiscordAlert()
        
        desktop_alert.test_notification()
        logger.info("Desktop alert test sent")
        
        if telegram_alert.enabled:
            telegram_alert.test_notification()
            logger.info("Telegram alert test sent")
        else:
            logger.info("Telegram alerts not configured")
        
        if discord_alert.enabled:
            discord_alert.test_notification()
            logger.info("Discord alert test sent")
        else:
            logger.info("Discord alerts not configured")
        
        return
    
    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create and start system
    global system
    system = AttackDetectionSystem(args.config)
    
    try:
        system.start()
        
        # Keep main thread alive and perform periodic cleanup
        while system.running:
            time.sleep(1)
            # Clean up inactive attacks every 5 minutes
            current_time = time.time()
            if current_time - system._last_cleanup_time > 300:  # 5 minutes
                if system.notification_manager:
                    system.notification_manager.clear_inactive_attacks()
                system._last_cleanup_time = current_time
    
    except KeyboardInterrupt:
        logger.info("\nReceived keyboard interrupt")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
    finally:
        system.stop()


if __name__ == "__main__":
    main()

