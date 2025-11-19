"""
Export utilities for attack logs.
Supports CSV, JSON, ElasticSearch, and Grafana exports.
"""

import json
import csv
import io
from datetime import datetime
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)


def export_to_csv(attacks: List[Dict]) -> str:
    """
    Export attacks to CSV format.
    
    Args:
        attacks: List of attack dictionaries
        
    Returns:
        CSV string
    """
    if not attacks:
        return ""
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        "ID", "Timestamp", "Attack Type", "Source IP", "Severity",
        "Packet Count", "Packet Rate (PPS)", "Protocol", "Country", "ISP", "Organization"
    ])
    
    # Write data
    for attack in attacks:
        shodan_data = attack.get("shodan_data", {})
        ip_info = shodan_data.get("ip_info", {}) if shodan_data else {}
        location = ip_info.get("location", {}) if ip_info else {}
        
        writer.writerow([
            attack.get("id", ""),
            attack.get("timestamp", "").isoformat() if hasattr(attack.get("timestamp", ""), "isoformat") else str(attack.get("timestamp", "")),
            attack.get("attack_type", ""),
            attack.get("src_ip", ""),
            attack.get("severity", ""),
            attack.get("packet_count", ""),
            attack.get("packet_rate", attack.get("packet_rate_pps", "")),
            attack.get("protocol", ""),
            location.get("country", "") if location else "",
            ip_info.get("isp", "") if ip_info else "",
            ip_info.get("org", "") if ip_info else ""
        ])
    
    return output.getvalue()


def export_to_json(attacks: List[Dict]) -> str:
    """
    Export attacks to JSON format.
    
    Args:
        attacks: List of attack dictionaries
        
    Returns:
        JSON string
    """
    # Convert datetime objects to strings
    export_data = []
    for attack in attacks:
        attack_copy = attack.copy()
        if "timestamp" in attack_copy:
            timestamp = attack_copy["timestamp"]
            if hasattr(timestamp, "isoformat"):
                attack_copy["timestamp"] = timestamp.isoformat()
            else:
                attack_copy["timestamp"] = str(timestamp)
        export_data.append(attack_copy)
    
    return json.dumps(export_data, indent=2, ensure_ascii=False)


def export_to_elasticsearch_format(attacks: List[Dict], index_name: str = "attack-detection") -> List[Dict]:
    """
    Export attacks to ElasticSearch bulk format.
    
    Args:
        attacks: List of attack dictionaries
        index_name: ElasticSearch index name
        
    Returns:
        List of ElasticSearch bulk operation dictionaries
    """
    bulk_operations = []
    
    for attack in attacks:
        # Index operation
        bulk_operations.append({
            "index": {
                "_index": index_name,
                "_id": attack.get("id", f"attack-{len(bulk_operations)}")
            }
        })
        
        # Document
        doc = attack.copy()
        if "timestamp" in doc:
            timestamp = doc["timestamp"]
            if hasattr(timestamp, "isoformat"):
                doc["timestamp"] = timestamp.isoformat()
            else:
                doc["timestamp"] = str(timestamp)
        
        bulk_operations.append(doc)
    
    return bulk_operations


def export_to_grafana_format(attacks: List[Dict]) -> List[Dict]:
    """
    Export attacks to Grafana time series format.
    
    Args:
        attacks: List of attack dictionaries
        
    Returns:
        List of Grafana time series data points
    """
    time_series = []
    
    for attack in attacks:
        timestamp = attack.get("timestamp")
        if hasattr(timestamp, "timestamp"):
            ts = int(timestamp.timestamp() * 1000)  # Convert to milliseconds
        else:
            ts = int(datetime.now().timestamp() * 1000)
        
        time_series.append({
            "time": ts,
            "value": 1,
            "metric": "attacks",
            "tags": {
                "attack_type": attack.get("attack_type", "unknown"),
                "severity": attack.get("severity", "unknown"),
                "source_ip": attack.get("src_ip", "unknown"),
                "protocol": attack.get("protocol", "unknown")
            }
        })
    
    return time_series


def save_elasticsearch_bulk(attacks: List[Dict], filename: str, index_name: str = "attack-detection"):
    """
    Save attacks in ElasticSearch bulk format to file.
    
    Args:
        attacks: List of attack dictionaries
        filename: Output filename
        index_name: ElasticSearch index name
    """
    bulk_ops = export_to_elasticsearch_format(attacks, index_name)
    
    with open(filename, 'w', encoding='utf-8') as f:
        for op in bulk_ops:
            f.write(json.dumps(op, ensure_ascii=False) + '\n')
    
    logger.info(f"Exported {len(attacks)} attacks to ElasticSearch format: {filename}")


def save_grafana_json(attacks: List[Dict], filename: str):
    """
    Save attacks in Grafana format to file.
    
    Args:
        attacks: List of attack dictionaries
        filename: Output filename
    """
    time_series = export_to_grafana_format(attacks)
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(time_series, f, indent=2, ensure_ascii=False)
    
    logger.info(f"Exported {len(attacks)} attacks to Grafana format: {filename}")

