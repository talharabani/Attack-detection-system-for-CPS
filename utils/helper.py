"""
Helper utilities for RealTimeAttackDetection system.
Provides common functions for logging, configuration loading, and IP validation.
"""

import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional, Tuple


def load_config(config_path: str = "config.json") -> Dict[str, Any]:
    """
    Load configuration from JSON file.
    
    Args:
        config_path: Path to the configuration file
        
    Returns:
        Dictionary containing configuration settings
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        json.JSONDecodeError: If config file is invalid JSON
    """
    config_file = Path(config_path)
    
    if not config_file.exists():
        # Try to find config in parent directory
        parent_config = Path(__file__).parent.parent / config_path
        if parent_config.exists():
            config_file = parent_config
        else:
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_file, 'r') as f:
        config = json.load(f)
    
    return config


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """
    Setup logging configuration for the application.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file
        
    Returns:
        Configured logger instance
    """
    # Create logs directory if it doesn't exist
    if log_file:
        log_dir = Path(log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)
    
    # Configure logging format
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    
    # Fix Windows console encoding for Unicode characters
    if sys.platform == 'win32':
        try:
            # Try to set console to UTF-8 (Windows 10+)
            import os
            os.system('chcp 65001 >nul 2>&1')  # Set console to UTF-8
        except:
            pass  # If it fails, continue without UTF-8
    
    # Create stream handler with UTF-8 encoding
    stream_handler = logging.StreamHandler(sys.stdout)
    if sys.platform == 'win32':
        try:
            # Try to set encoding on the handler
            stream_handler.setStream(sys.stdout)
        except:
            pass
    
    handlers = [stream_handler]
    
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding='utf-8'))
    
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format=log_format,
        datefmt=date_format,
        handlers=handlers
    )
    
    return logging.getLogger(__name__)


def is_valid_ip(ip: str) -> bool:
    """
    Validate IPv4 address format.
    
    Args:
        ip: IP address string to validate
        
    Returns:
        True if valid IPv4, False otherwise
    """
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True
    except (ValueError, AttributeError):
        return False


def is_private_ip(ip: str) -> bool:
    """
    Check if IP address is in private range.
    
    Args:
        ip: IP address string
        
    Returns:
        True if IP is private, False otherwise
    """
    if not is_valid_ip(ip):
        return False
    
    parts = [int(x) for x in ip.split('.')]
    
    # Private IP ranges:
    # 10.0.0.0/8
    # 172.16.0.0/12
    # 192.168.0.0/16
    # 127.0.0.0/8 (loopback)
    
    if parts[0] == 10:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    if parts[0] == 127:
        return True
    
    return False


def get_project_root() -> Path:
    """
    Get the project root directory.
    
    Returns:
        Path object pointing to project root
    """
    return Path(__file__).parent.parent


def format_bytes(bytes_value: int) -> str:
    """
    Format bytes to human-readable string.
    
    Args:
        bytes_value: Number of bytes
        
    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"


def save_config(config: Dict[str, Any], config_path: str = "config.json") -> None:
    """
    Save configuration to JSON file.
    
    Args:
        config: Dictionary containing configuration settings
        config_path: Path to the configuration file
        
    Raises:
        IOError: If config file cannot be written
    """
    config_file = Path(config_path)
    
    # Try to find config in parent directory if not found
    if not config_file.exists():
        parent_config = Path(__file__).parent.parent / config_path
        if parent_config.exists():
            config_file = parent_config
        else:
            # Create in current directory
            config_file = Path(config_path)
    
    # Create backup before saving
    if config_file.exists():
        backup_path = config_file.with_suffix('.json.bak')
        try:
            import shutil
            shutil.copy2(config_file, backup_path)
        except:
            pass  # If backup fails, continue anyway
    
    # Write config with proper formatting
    with open(config_file, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


def validate_attack_entry(attack: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Validate an attack entry dictionary.
    
    Args:
        attack: Attack entry dictionary to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(attack, dict):
        return False, "Attack entry must be a dictionary"
    
    # Check required fields
    required_fields = ["attack_type", "src_ip", "timestamp"]
    for field in required_fields:
        if field not in attack:
            return False, f"Missing required field: {field}"
    
    # Validate timestamp
    timestamp = attack.get("timestamp")
    if timestamp is None:
        return False, "Timestamp cannot be None"
    
    # Validate IP address
    src_ip = attack.get("src_ip")
    if src_ip and src_ip != "Unknown":
        if not is_valid_ip(str(src_ip)):
            return False, f"Invalid IP address: {src_ip}"
    
    # Validate severity
    severity = attack.get("severity", "MEDIUM")
    valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    if severity not in valid_severities:
        return False, f"Invalid severity: {severity}. Must be one of {valid_severities}"
    
    # Validate numeric fields
    numeric_fields = ["packet_count", "packet_rate", "packet_rate_pps"]
    for field in numeric_fields:
        value = attack.get(field)
        if value is not None and not isinstance(value, (int, float)):
            try:
                float(value)  # Try to convert
            except (ValueError, TypeError):
                return False, f"Invalid {field}: must be numeric"
    
    return True, None


def validate_timestamp(timestamp: Any) -> bool:
    """
    Validate timestamp value.
    
    Args:
        timestamp: Timestamp to validate (datetime, string, or None)
        
    Returns:
        True if valid, False otherwise
    """
    if timestamp is None:
        return False
    
    from datetime import datetime
    
    if isinstance(timestamp, datetime):
        return True
    
    if isinstance(timestamp, str):
        try:
            datetime.fromisoformat(timestamp)
            return True
        except (ValueError, AttributeError):
            return False
    
    return False


def safe_get(dictionary: Dict, *keys, default=None):
    """
    Safely get nested dictionary values.
    
    Args:
        dictionary: Dictionary to search
        *keys: Keys to traverse (e.g., safe_get(d, 'a', 'b', 'c'))
        default: Default value if key not found
        
    Returns:
        Value at nested key or default
    """
    try:
        result = dictionary
        for key in keys:
            if not isinstance(result, dict):
                return default
            result = result.get(key)
            if result is None:
                return default
        return result
    except (KeyError, TypeError, AttributeError):
        return default


def validate_config(config: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Validate configuration dictionary.
    
    Args:
        config: Configuration dictionary to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(config, dict):
        return False, "Configuration must be a dictionary"
    
    # Check for required top-level sections
    required_sections = ["detection", "alerts", "dashboard"]
    for section in required_sections:
        if section not in config:
            return False, f"Missing required configuration section: {section}"
    
    # Validate detection thresholds
    detection = config.get("detection", {})
    ddos_config = detection.get("ddos", {})
    
    if "packet_threshold" in ddos_config:
        threshold = ddos_config["packet_threshold"]
        if not isinstance(threshold, (int, float)) or threshold < 0:
            return False, "DDoS packet_threshold must be a non-negative number"
    
    if "time_window_seconds" in ddos_config:
        window = ddos_config["time_window_seconds"]
        if not isinstance(window, (int, float)) or window <= 0:
            return False, "DDoS time_window_seconds must be a positive number"
    
    # Validate dashboard port
    dashboard = config.get("dashboard", {})
    if "port" in dashboard:
        port = dashboard["port"]
        if not isinstance(port, int) or port < 1 or port > 65535:
            return False, "Dashboard port must be between 1 and 65535"
    
    return True, None