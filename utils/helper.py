"""
Helper utilities for RealTimeAttackDetection system.
Provides common functions for logging, configuration loading, and IP validation.
"""

import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional


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

