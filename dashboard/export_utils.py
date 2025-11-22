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
    Export attacks to CSV format with complete details.
    
    Args:
        attacks: List of attack dictionaries
        
    Returns:
        CSV string
    """
    if not attacks:
        return ""
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write comprehensive header with all attack details
    writer.writerow([
        "ID", "Timestamp", "Attack Type", "Attack Subtype", "Source IP", "Destination IP",
        "Severity", "Protocol", "Packet Count", "Packet Rate (PPS)", "Packet Rate (pps)",
        "Time Window (seconds)", "Port Count", "Scan Rate", "Scanned Ports",
        "Threshold PPS", "Baseline PPS", "Country", "City", "ISP", "Organization", "ASN",
        "Threat Level", "Open Ports", "Vulnerabilities Count", "Honeypot Score"
    ])
    
    # Write data with all fields
    for attack in attacks:
        shodan_data = attack.get("shodan_data", {})
        ip_info = shodan_data.get("ip_info", {}) if shodan_data else {}
        location = ip_info.get("location", {}) if ip_info else {}
        
        # Format timestamp
        timestamp = attack.get("timestamp", "")
        if hasattr(timestamp, "isoformat"):
            timestamp_str = timestamp.isoformat()
        else:
            timestamp_str = str(timestamp)
        
        # Format scanned ports
        scanned_ports = attack.get("scanned_ports", [])
        if scanned_ports:
            ports_str = ", ".join(map(str, scanned_ports[:100]))  # Limit to 100 ports
            if len(scanned_ports) > 100:
                ports_str += f" (+{len(scanned_ports) - 100} more)"
        else:
            ports_str = ""
        
        # Format open ports
        open_ports = ip_info.get("open_ports", []) if ip_info else []
        open_ports_str = ", ".join(map(str, open_ports[:50])) if open_ports else ""
        
        # Format vulnerabilities
        vulnerabilities = ip_info.get("vulnerabilities", []) if ip_info else []
        vuln_count = len(vulnerabilities)
        
        # Honeypot score
        honeypot = shodan_data.get("honeypot", {}) if shodan_data else {}
        honeypot_score = honeypot.get("honeypot_score", "") if honeypot else ""
        
        writer.writerow([
            attack.get("id", ""),
            timestamp_str,
            attack.get("attack_type", ""),
            attack.get("attack_subtype", ""),
            attack.get("src_ip", ""),
            attack.get("dst_ip", ""),
            attack.get("severity", ""),
            attack.get("protocol", ""),
            attack.get("packet_count", ""),
            attack.get("packet_rate", ""),
            attack.get("packet_rate_pps", ""),
            attack.get("time_window", ""),
            attack.get("port_count", ""),
            attack.get("scan_rate", ""),
            ports_str,
            attack.get("threshold_pps", ""),
            attack.get("baseline_pps", ""),
            location.get("country", "") if location else "",
            location.get("city", "") if location else "",
            ip_info.get("isp", "") if ip_info else "",
            ip_info.get("org", "") if ip_info else "",
            ip_info.get("asn", "") if ip_info else "",
            shodan_data.get("threat_level", "") if shodan_data else "",
            open_ports_str,
            vuln_count,
            honeypot_score
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
    Export attacks to ElasticSearch bulk format with complete details.
    
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
                "_id": attack.get("id", f"attack-{len(bulk_operations) // 2}")
            }
        })
        
        # Enhanced document with all fields properly formatted
        doc = attack.copy()
        
        # Format timestamp
        if "timestamp" in doc:
            timestamp = doc["timestamp"]
            if hasattr(timestamp, "isoformat"):
                doc["timestamp"] = timestamp.isoformat()
                doc["@timestamp"] = timestamp.isoformat()  # ElasticSearch standard field
            else:
                doc["timestamp"] = str(timestamp)
                doc["@timestamp"] = str(timestamp)
        
        # Add computed fields for better searching
        shodan_data = doc.get("shodan_data", {})
        ip_info = shodan_data.get("ip_info", {}) if shodan_data else {}
        location = ip_info.get("location", {}) if ip_info else {}
        
        # Flatten Shodan data for easier querying
        doc["geoip"] = {
            "country": location.get("country", ""),
            "city": location.get("city", ""),
            "latitude": location.get("latitude"),
            "longitude": location.get("longitude")
        } if location else {}
        
        doc["network"] = {
            "isp": ip_info.get("isp", ""),
            "organization": ip_info.get("org", ""),
            "asn": ip_info.get("asn", "")
        } if ip_info else {}
        
        doc["threat_intel"] = {
            "threat_level": shodan_data.get("threat_level", "UNKNOWN"),
            "honeypot_score": shodan_data.get("honeypot", {}).get("honeypot_score") if shodan_data.get("honeypot") else None,
            "vulnerabilities_count": len(ip_info.get("vulnerabilities", [])) if ip_info else 0,
            "open_ports_count": len(ip_info.get("open_ports", [])) if ip_info else 0
        } if shodan_data else {}
        
        # Ensure numeric fields are properly typed
        if "packet_count" in doc and doc["packet_count"] is not None:
            try:
                doc["packet_count"] = int(doc["packet_count"])
            except (ValueError, TypeError):
                pass
        
        if "packet_rate" in doc and doc["packet_rate"] is not None:
            try:
                doc["packet_rate"] = float(doc["packet_rate"])
            except (ValueError, TypeError):
                pass
        
        if "packet_rate_pps" in doc and doc["packet_rate_pps"] is not None:
            try:
                doc["packet_rate_pps"] = float(doc["packet_rate_pps"])
            except (ValueError, TypeError):
                pass
        
        bulk_operations.append(doc)
    
    return bulk_operations


def export_to_grafana_format(attacks: List[Dict]) -> List[Dict]:
    """
    Export attacks to Grafana time series format with complete details.
    
    Args:
        attacks: List of attack dictionaries
        
    Returns:
        List of Grafana time series data points with multiple metrics
    """
    time_series = []
    
    for attack in attacks:
        timestamp = attack.get("timestamp")
        if hasattr(timestamp, "timestamp"):
            ts = int(timestamp.timestamp() * 1000)  # Convert to milliseconds
        else:
            ts = int(datetime.now().timestamp() * 1000)
        
        shodan_data = attack.get("shodan_data", {})
        ip_info = shodan_data.get("ip_info", {}) if shodan_data else {}
        location = ip_info.get("location", {}) if ip_info else {}
        
        # Base tags with all attack information
        base_tags = {
            "attack_type": attack.get("attack_type", "unknown"),
            "attack_subtype": attack.get("attack_subtype", "unknown"),
            "severity": attack.get("severity", "unknown"),
            "source_ip": attack.get("src_ip", "unknown"),
            "destination_ip": attack.get("dst_ip", "unknown"),
            "protocol": attack.get("protocol", "unknown"),
            "country": location.get("country", "unknown") if location else "unknown",
            "isp": ip_info.get("isp", "unknown") if ip_info else "unknown",
            "organization": ip_info.get("org", "unknown") if ip_info else "unknown",
            "threat_level": shodan_data.get("threat_level", "UNKNOWN") if shodan_data else "UNKNOWN"
        }
        
        # Attack count metric
        time_series.append({
            "time": ts,
            "value": 1,
            "metric": "attacks.count",
            "tags": base_tags
        })
        
        # Packet count metric
        if attack.get("packet_count"):
            time_series.append({
                "time": ts,
                "value": int(attack["packet_count"]),
                "metric": "attacks.packets",
                "tags": base_tags
            })
        
        # Packet rate metric
        packet_rate = attack.get("packet_rate") or attack.get("packet_rate_pps")
        if packet_rate:
            time_series.append({
                "time": ts,
                "value": float(packet_rate),
                "metric": "attacks.packet_rate",
                "tags": base_tags
            })
        
        # Port count metric (for port scans)
        if attack.get("port_count"):
            time_series.append({
                "time": ts,
                "value": int(attack["port_count"]),
                "metric": "attacks.ports_scanned",
                "tags": base_tags
            })
        
        # Severity score metric (for visualization)
        severity_scores = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        severity = attack.get("severity", "MEDIUM")
        time_series.append({
            "time": ts,
            "value": severity_scores.get(severity, 2),
            "metric": "attacks.severity_score",
            "tags": base_tags
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

