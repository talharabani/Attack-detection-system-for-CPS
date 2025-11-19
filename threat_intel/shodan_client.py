"""
Shodan Threat Intelligence Integration
Provides comprehensive Shodan API integration for threat enrichment.
"""

import os
import logging
from typing import Dict, List, Optional, Any

# Try to load from environment variables
try:
    from dotenv import load_dotenv
    try:
        load_dotenv()
    except UnicodeDecodeError:
        # Handle encoding issues with .env file
        env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
        if os.path.exists(env_path):
            try:
                # Try to read with different encodings
                with open(env_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except UnicodeDecodeError:
                try:
                    with open(env_path, 'r', encoding='utf-16') as f:
                        content = f.read()
                    # Recreate with UTF-8 encoding
                    with open(env_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                except Exception:
                    pass
        # Try loading again
        load_dotenv()
except ImportError:
    pass
except Exception:
    # Silently fail if dotenv has issues - we'll use fallback API key
    pass

# Try to import official Shodan library, fallback to requests if not available
try:
    import shodan
    SHODAN_LIB_AVAILABLE = True
except ImportError:
    SHODAN_LIB_AVAILABLE = False
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class ShodanClient:
    """
    Shodan API client for threat intelligence enrichment.
    Provides comprehensive Shodan functionality for IP lookup, search, exploits, and more.
    """
    
    BASE_URL = "https://api.shodan.io"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Shodan client.
        
        Args:
            api_key: Shodan API key. If not provided, will try to get from environment.
        """
        # Get API key from parameter, environment variable, or use default
        if api_key:
            self.api_key = api_key
        else:
            self.api_key = os.getenv("SHODAN_API_KEY", "OrRrvs0GIH8cuxQToeunr8Z76Ld7FYIG")
        
        if not self.api_key or self.api_key == "":
            logger.warning("Shodan API key not found. Shodan features will be disabled.")
            self.enabled = False
            return
        
        self.enabled = True
        
        # Initialize Shodan API client
        if SHODAN_LIB_AVAILABLE:
            try:
                self.shodan_api = shodan.Shodan(self.api_key)
                logger.info("Shodan client initialized (using official library)")
            except Exception as e:
                logger.error(f"Failed to initialize Shodan API: {e}")
                self.enabled = False
                return
        else:
            # Fallback to requests if official library not available
            self.shodan_api = None
            self.session = requests.Session()
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504]
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
            logger.info("Shodan client initialized (using requests fallback)")
    
    def _make_request(self, endpoint: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """
        Make a request to Shodan API with error handling (fallback method).
        
        Args:
            endpoint: API endpoint
            params: Request parameters
            
        Returns:
            JSON response or None if error
        """
        if not self.enabled or SHODAN_LIB_AVAILABLE:
            return None
        
        try:
            url = f"{self.BASE_URL}{endpoint}"
            request_params = {"key": self.api_key}
            if params:
                request_params.update(params)
            
            response = self.session.get(url, params=request_params, timeout=10)
            response.raise_for_status()
            return response.json()
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Shodan API request failed: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in Shodan request: {e}")
            return None
    
    def get_ip_info(self, ip: str) -> Optional[Dict]:
        """
        Get comprehensive information about an IP address.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            Dictionary with IP information including:
            - open_ports: List of open ports
            - vulnerabilities: List of CVEs
            - isp: ISP information
            - org: Organization
            - os: Operating system
            - hostnames: List of hostnames
            - device_type: Device type
            - location: Geographic location
            - tags: List of tags (e.g., "ICS", "database", "router")
            - services: Service banners
        """
        if not self.enabled:
            return None
        
        try:
            # Use official Shodan library if available
            if SHODAN_LIB_AVAILABLE and self.shodan_api:
                try:
                    result = self.shodan_api.host(ip)
                except shodan.APIError as e:
                    if "No information available" in str(e) or "not found" in str(e).lower():
                        logger.debug(f"No Shodan data available for IP {ip}")
                        return None
                    raise
            else:
                result = self._make_request(f"/shodan/host/{ip}")
            
            if not result:
                return None
            
            # Extract and format relevant information
            ip_info = {
                "ip": ip,
                "open_ports": result.get("ports", []),
                "vulnerabilities": [],
                "isp": result.get("isp", "Unknown"),
                "org": result.get("org", "Unknown"),
                "os": result.get("os", "Unknown"),
                "hostnames": result.get("hostnames", []),
                "device_type": result.get("device_type", "Unknown"),
                "location": {
                    "country": result.get("country_name", "Unknown"),
                    "city": result.get("city", "Unknown"),
                    "latitude": result.get("latitude"),
                    "longitude": result.get("longitude")
                },
                "tags": result.get("tags", []),
                "services": [],
                "last_update": result.get("last_update", "Unknown")
            }
            
            # Extract vulnerabilities from data
            if "vulns" in result:
                ip_info["vulnerabilities"] = list(result["vulns"].keys())
            
            # Extract service information
            if "data" in result:
                for service in result["data"]:
                    service_info = {
                        "port": service.get("port"),
                        "protocol": service.get("transport", "tcp"),
                        "product": service.get("product", "Unknown"),
                        "version": service.get("version", ""),
                        "banner": service.get("data", "")[:200]  # First 200 chars
                    }
                    ip_info["services"].append(service_info)
            
            return ip_info
        
        except Exception as e:
            logger.error(f"Error getting IP info for {ip}: {e}")
            return None
    
    def search(self, query: str, facets: Optional[List[str]] = None) -> Optional[Dict]:
        """
        Search the Shodan database.
        
        Args:
            query: Shodan search query (e.g., "port:502 org:Microsoft")
            facets: Optional facets to include in results
            
        Returns:
            Dictionary with search results
        """
        if not self.enabled:
            return None
        
        try:
            if SHODAN_LIB_AVAILABLE and self.shodan_api:
                result = self.shodan_api.search(query, facets=facets)
                return result
            else:
                params = {"query": query}
                if facets:
                    params["facets"] = ",".join(facets)
                result = self._make_request("/shodan/host/search", params)
                return result
        
        except Exception as e:
            logger.error(f"Error searching Shodan: {e}")
            return None
    
    def get_exploits(self, query: str) -> Optional[Dict]:
        """
        Search Shodan Exploits database.
        
        Args:
            query: Search query (CVE, port, product, etc.)
            
        Returns:
            Dictionary with exploit information
        """
        if not self.enabled:
            return None
        
        try:
            if SHODAN_LIB_AVAILABLE and self.shodan_api:
                result = self.shodan_api.exploits.search(query)
                return result
            else:
                params = {"query": query}
                result = self._make_request("/shodan/exploits/search", params)
                return result
        
        except Exception as e:
            logger.error(f"Error getting exploits: {e}")
            return None
    
    def dns_lookup(self, domain: str) -> Optional[Dict]:
        """
        DNS lookup for a domain.
        
        Args:
            domain: Domain name to lookup
            
        Returns:
            Dictionary with DNS information
        """
        if not self.enabled:
            return None
        
        try:
            if SHODAN_LIB_AVAILABLE and self.shodan_api:
                result = self.shodan_api.dns.lookup(domain)
                return result
            else:
                params = {"hostname": domain}
                result = self._make_request("/dns/lookup", params)
                return result
        
        except Exception as e:
            logger.error(f"Error doing DNS lookup for {domain}: {e}")
            return None
    
    def reverse_dns(self, ip: str) -> Optional[Dict]:
        """
        Reverse DNS lookup for an IP address.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            Dictionary with reverse DNS information
        """
        if not self.enabled:
            return None
        
        try:
            if SHODAN_LIB_AVAILABLE and self.shodan_api:
                result = self.shodan_api.dns.reverse(ip)
                return result
            else:
                params = {"ip": ip}
                result = self._make_request("/dns/reverse", params)
                return result
        
        except Exception as e:
            logger.error(f"Error doing reverse DNS for {ip}: {e}")
            return None
    
    def get_honeypot_score(self, ip: str) -> Optional[Dict]:
        """
        Get honeypot probability score for an IP.
        
        Args:
            ip: IP address to check
            
        Returns:
            Dictionary with honeypot score and probability
        """
        if not self.enabled:
            return None
        
        try:
            if SHODAN_LIB_AVAILABLE and self.shodan_api:
                try:
                    score = self.shodan_api.labs.honeyscore(ip)
                    return {
                        "ip": ip,
                        "honeypot_score": score,
                        "probability": score
                    }
                except Exception:
                    return None
            else:
                result = self._make_request(f"/labs/honeyscore/{ip}")
                if result:
                    return {
                        "ip": ip,
                        "honeypot_score": result.get("score", 0),
                        "probability": result.get("probability", 0)
                    }
                return None
        
        except Exception as e:
            logger.error(f"Error getting honeypot score for {ip}: {e}")
            return None
    
    def scan_host(self, ip: str) -> Optional[Dict]:
        """
        Request Shodan to scan a host.
        
        Args:
            ip: IP address to scan
            
        Returns:
            Dictionary with scan request information
        """
        if not self.enabled:
            return None
        
        try:
            if SHODAN_LIB_AVAILABLE and self.shodan_api:
                result = self.shodan_api.scan(ip)
                return result
            else:
                params = {"ip": ip}
                result = self._make_request("/shodan/scan", params)
                return result
        
        except Exception as e:
            logger.error(f"Error requesting scan for {ip}: {e}")
            return None
    
    def get_alert_info(self) -> Optional[Dict]:
        """
        Get information about Shodan alerts.
        
        Returns:
            Dictionary with alert information
        """
        if not self.enabled:
            return None
        
        try:
            if SHODAN_LIB_AVAILABLE and self.shodan_api:
                result = self.shodan_api.alerts()
                return result
            else:
                result = self._make_request("/shodan/alert/info")
                return result
        
        except Exception as e:
            logger.error(f"Error getting alert info: {e}")
            return None
    
    def enrich_attack_info(self, ip: str) -> Optional[Dict]:
        """
        Enrich attack information with Shodan threat intelligence.
        This is the main method called when an attack is detected.
        
        Args:
            ip: Attacking IP address
            
        Returns:
            Dictionary with enriched threat intelligence data
        """
        if not self.enabled:
            return None
        
        try:
            logger.info(f"Enriching attack info with Shodan for IP: {ip}")
            
            # Get IP information
            ip_info = self.get_ip_info(ip)
            if not ip_info:
                return None
            
            # Get exploits if vulnerabilities found
            exploits = []
            if ip_info.get("vulnerabilities"):
                for cve in ip_info["vulnerabilities"][:5]:  # Limit to 5 CVEs
                    exploit_data = self.get_exploits(cve)
                    if exploit_data:
                        # Handle both official library format and raw API format
                        if "matches" in exploit_data:
                            exploits.extend(exploit_data["matches"][:3])  # Limit to 3 exploits per CVE
                        elif isinstance(exploit_data, list):
                            exploits.extend(exploit_data[:3])
                        elif "data" in exploit_data:
                            exploits.extend(exploit_data["data"][:3])
            
            # Get honeypot score
            honeypot = self.get_honeypot_score(ip)
            
            # Combine all information
            enriched_data = {
                "shodan_enriched": True,
                "ip_info": ip_info,
                "exploits": exploits[:10] if exploits else [],  # Limit to 10 total exploits
                "honeypot": honeypot,
                "threat_level": self._calculate_threat_level(ip_info, exploits, honeypot)
            }
            
            return enriched_data
        
        except Exception as e:
            logger.error(f"Error enriching attack info: {e}")
            return None
    
    def _calculate_threat_level(self, ip_info: Dict, exploits: List, honeypot: Optional[Dict]) -> str:
        """
        Calculate threat level based on Shodan data.
        
        Args:
            ip_info: IP information from Shodan
            exploits: List of exploits
            honeypot: Honeypot score information
            
        Returns:
            Threat level string (LOW, MEDIUM, HIGH, CRITICAL)
        """
        threat_score = 0
        
        # Check for vulnerabilities
        if ip_info.get("vulnerabilities"):
            threat_score += len(ip_info["vulnerabilities"]) * 2
        
        # Check for exploits
        if exploits:
            threat_score += len(exploits) * 3
        
        # Check for ICS/SCADA tags
        tags = ip_info.get("tags", [])
        if any(tag.lower() in ["ics", "scada", "plc", "hmi"] for tag in tags):
            threat_score += 5
        
        # Check for open ports (more ports = more attack surface)
        if len(ip_info.get("open_ports", [])) > 10:
            threat_score += 2
        
        # Honeypot score (low score = more likely real threat)
        if honeypot and honeypot.get("honeypot_score", 1) < 0.3:
            threat_score += 3
        
        # Determine threat level
        if threat_score >= 15:
            return "CRITICAL"
        elif threat_score >= 10:
            return "HIGH"
        elif threat_score >= 5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def test_connection(self) -> Dict[str, Any]:
        """
        Test Shodan API connection and API key validity.
        
        Returns:
            Dictionary with test results including:
            - success: Boolean indicating if all tests passed
            - api_key_valid: Boolean indicating if API key is valid
            - network_accessible: Boolean indicating if Shodan API is reachable
            - account_info: Dictionary with account information (credits, etc.)
            - test_ip_lookup: Boolean indicating if IP lookup works
            - errors: List of error messages
        """
        results = {
            "success": False,
            "api_key_valid": False,
            "network_accessible": False,
            "account_info": None,
            "test_ip_lookup": False,
            "errors": []
        }
        
        if not self.enabled:
            results["errors"].append("Shodan client is not enabled (no API key or initialization failed)")
            return results
        
        # Test 1: Check API key validity by getting account info
        try:
            logger.info("Testing Shodan API key validity...")
            if SHODAN_LIB_AVAILABLE and self.shodan_api:
                try:
                    account_info = self.shodan_api.info()
                    results["api_key_valid"] = True
                    results["network_accessible"] = True
                    results["account_info"] = {
                        "plan": account_info.get("plan", "Unknown"),
                        "credits": account_info.get("credits", 0),
                        "monitored_ips": account_info.get("monitored_ips", 0),
                        "unlocked": account_info.get("unlocked", False),
                        "unlocked_left": account_info.get("unlocked_left", 0)
                    }
                    logger.info(f"✅ API key is valid. Plan: {account_info.get('plan')}, Credits: {account_info.get('credits')}")
                except shodan.APIError as e:
                    if "Invalid API key" in str(e) or "401" in str(e):
                        results["errors"].append(f"Invalid API key: {e}")
                        logger.error(f"❌ Invalid API key: {e}")
                    else:
                        results["errors"].append(f"API error: {e}")
                        logger.error(f"❌ API error: {e}")
            else:
                # Fallback: Test with account info endpoint
                account_info = self._make_request("/account/profile")
                if account_info:
                    results["api_key_valid"] = True
                    results["network_accessible"] = True
                    results["account_info"] = account_info
                    logger.info("✅ API key is valid (using fallback method)")
                else:
                    results["errors"].append("Failed to get account info - API key may be invalid")
                    logger.error("❌ Failed to get account info")
        except Exception as e:
            results["errors"].append(f"Error testing API key: {e}")
            logger.error(f"❌ Error testing API key: {e}")
        
        # Test 2: Test network connectivity with a simple IP lookup
        if results["api_key_valid"]:
            try:
                logger.info("Testing IP lookup functionality...")
                # Test with Google DNS (8.8.8.8) - should always have data
                test_ip = "8.8.8.8"
                ip_info = self.get_ip_info(test_ip)
                
                if ip_info:
                    results["test_ip_lookup"] = True
                    logger.info(f"✅ IP lookup test successful for {test_ip}")
                    logger.info(f"   Found: {len(ip_info.get('open_ports', []))} open ports, "
                              f"ISP: {ip_info.get('isp', 'Unknown')}")
                else:
                    results["errors"].append(f"IP lookup returned no data for {test_ip} (this may be normal)")
                    logger.warning(f"⚠️ IP lookup returned no data for {test_ip}")
            except Exception as e:
                results["errors"].append(f"Error testing IP lookup: {e}")
                logger.error(f"❌ Error testing IP lookup: {e}")
        
        # Test 3: Test network connectivity (if API key test failed, try basic connectivity)
        if not results["network_accessible"]:
            try:
                import requests
                response = requests.get("https://api.shodan.io", timeout=5)
                results["network_accessible"] = True
                logger.info("✅ Network connectivity to Shodan API is OK")
            except Exception as e:
                results["errors"].append(f"Network connectivity test failed: {e}")
                logger.error(f"❌ Cannot reach Shodan API: {e}")
        
        # Determine overall success
        results["success"] = (
            results["api_key_valid"] and 
            results["network_accessible"] and 
            (results["test_ip_lookup"] or len(results["errors"]) == 0)
        )
        
        return results

