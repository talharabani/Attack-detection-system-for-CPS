#!/usr/bin/env python3
"""
Test script to verify Shodan API connectivity and functionality.
Run this to check if Shodan integration is working properly.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from threat_intel.shodan_client import ShodanClient
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def print_test_results(results: dict):
    """Print test results in a formatted way."""
    print("\n" + "=" * 70)
    print("🔍 SHODAN API CONNECTION TEST RESULTS")
    print("=" * 70)
    
    # Overall status
    if results["success"]:
        print("\n✅ OVERALL STATUS: SUCCESS - Shodan is working correctly!")
    else:
        print("\n❌ OVERALL STATUS: FAILED - Shodan has issues")
    
    print("\n" + "-" * 70)
    print("DETAILED TEST RESULTS:")
    print("-" * 70)
    
    # API Key Status
    if results["api_key_valid"]:
        print("✅ API Key: VALID")
    else:
        print("❌ API Key: INVALID or NOT WORKING")
    
    # Network Status
    if results["network_accessible"]:
        print("✅ Network: ACCESSIBLE (can reach Shodan API)")
    else:
        print("❌ Network: NOT ACCESSIBLE (cannot reach Shodan API)")
    
    # IP Lookup Test
    if results["test_ip_lookup"]:
        print("✅ IP Lookup: WORKING")
    else:
        print("⚠️  IP Lookup: NOT TESTED or NO DATA")
    
    # Account Information
    if results["account_info"]:
        print("\n📊 ACCOUNT INFORMATION:")
        account = results["account_info"]
        print(f"   Plan: {account.get('plan', 'Unknown')}")
        print(f"   Credits: {account.get('credits', 0):,}")
        print(f"   Monitored IPs: {account.get('monitored_ips', 0)}")
        if account.get('unlocked'):
            print(f"   Unlocked: Yes ({account.get('unlocked_left', 0)} left)")
        else:
            print("   Unlocked: No")
    else:
        print("\n⚠️  Account Information: NOT AVAILABLE")
    
    # Errors
    if results["errors"]:
        print("\n❌ ERRORS ENCOUNTERED:")
        for i, error in enumerate(results["errors"], 1):
            print(f"   {i}. {error}")
    else:
        print("\n✅ No errors encountered")
    
    print("\n" + "=" * 70)
    
    # Recommendations
    print("\n💡 RECOMMENDATIONS:")
    if not results["api_key_valid"]:
        print("   1. Check your API key in .env file or shodan_client.py")
        print("   2. Verify the API key is correct at https://account.shodan.io/")
        print("   3. Make sure the API key has not expired")
    
    if not results["network_accessible"]:
        print("   1. Check your internet connection")
        print("   2. Verify firewall is not blocking api.shodan.io")
        print("   3. Check if you're behind a proxy that needs configuration")
    
    if results["account_info"] and results["account_info"].get("credits", 0) == 0:
        print("   ⚠️  WARNING: You have 0 credits remaining!")
        print("      Some Shodan features may not work without credits")
    
    if results["success"]:
        print("\n✅ All tests passed! Shodan integration is ready to use.")
    else:
        print("\n❌ Some tests failed. Please fix the issues above.")
    
    print("=" * 70 + "\n")


def main():
    """Main test function."""
    print("\n" + "=" * 70)
    print("🔍 SHODAN API CONNECTION TEST")
    print("=" * 70)
    print("\nThis script will test:")
    print("  1. API key validity")
    print("  2. Network connectivity to Shodan")
    print("  3. IP lookup functionality")
    print("  4. Account information")
    print("\nStarting tests...\n")
    
    try:
        # Initialize Shodan client
        client = ShodanClient()
        
        if not client.enabled:
            print("❌ ERROR: Shodan client is not enabled!")
            print("   Possible reasons:")
            print("   1. No API key found")
            print("   2. Failed to initialize Shodan library")
            print("   3. Missing dependencies (shodan package)")
            return False
        
        # Run tests
        results = client.test_connection()
        
        # Print results
        print_test_results(results)
        
        # Return success status
        return results["success"]
        
    except Exception as e:
        print(f"\n❌ FATAL ERROR: {e}")
        import traceback
        print("\nFull error traceback:")
        print(traceback.format_exc())
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

