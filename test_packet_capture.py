#!/usr/bin/env python3
"""
Quick test script to verify packet capture is working.
Run this as Administrator to test if Scapy can capture packets.
"""

import sys
from scapy.all import sniff, IP, ICMP, get_if_list
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_packet_capture():
    """Test if we can capture packets."""
    logger.info("=" * 60)
    logger.info("PACKET CAPTURE TEST")
    logger.info("=" * 60)
    
    # List available interfaces
    logger.info("\n📡 Available network interfaces:")
    interfaces = get_if_list()
    for i, iface in enumerate(interfaces, 1):
        logger.info(f"   {i}. {iface}")
    
    logger.info("\n🔍 Starting packet capture test...")
    logger.info("   Send some pings from another machine to test ICMP capture")
    logger.info("   Press Ctrl+C to stop after 30 seconds or when you see packets\n")
    
    packet_count = 0
    icmp_count = 0
    
    def packet_handler(packet):
        nonlocal packet_count, icmp_count
        packet_count += 1
        
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.proto
            
            if packet.haslayer(ICMP):
                icmp_count += 1
                icmp_layer = packet[ICMP]
                logger.info(f"✅ ICMP packet #{icmp_count}: type={icmp_layer.type}, from {src_ip} -> {dst_ip}")
            else:
                if packet_count % 50 == 0:  # Log every 50th non-ICMP packet
                    logger.info(f"📦 Packet #{packet_count}: {protocol} from {src_ip} -> {dst_ip}")
        else:
            if packet_count % 100 == 0:
                logger.info(f"📦 Non-IP packet #{packet_count}")
    
    try:
        # Capture for 30 seconds or until interrupted
        sniff(
            prn=packet_handler,
            timeout=30,
            store=False
        )
        
        logger.info("\n" + "=" * 60)
        logger.info(f"📊 Test Results:")
        logger.info(f"   Total packets captured: {packet_count}")
        logger.info(f"   ICMP packets captured: {icmp_count}")
        logger.info("=" * 60)
        
        if packet_count == 0:
            logger.error("\n❌ NO PACKETS CAPTURED!")
            logger.error("   Possible issues:")
            logger.error("   1. Not running as Administrator")
            logger.error("   2. Npcap not installed (Windows)")
            logger.error("   3. No network traffic")
            logger.error("   4. Firewall blocking packet capture")
            return False
        elif icmp_count == 0:
            logger.warning("\n⚠️  Packets captured but NO ICMP packets!")
            logger.warning("   Try sending pings from another machine:")
            logger.warning("   ping <target_ip>")
            return False
        else:
            logger.info("\n✅ SUCCESS! Packet capture is working!")
            logger.info(f"   Captured {icmp_count} ICMP packets")
            return True
            
    except KeyboardInterrupt:
        logger.info("\n\n⏹️  Test stopped by user")
        logger.info(f"   Total packets: {packet_count}")
        logger.info(f"   ICMP packets: {icmp_count}")
        return icmp_count > 0
    except Exception as e:
        logger.error(f"\n❌ ERROR: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

if __name__ == "__main__":
    success = test_packet_capture()
    sys.exit(0 if success else 1)

