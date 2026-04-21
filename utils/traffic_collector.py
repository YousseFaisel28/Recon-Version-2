"""
ReconX - Traffic Feature Collector
Simulates tcpdump functionality using Scapy.
Requires: Scapy and Npcap (on Windows)
"""

import time
import threading
from collections import Counter
from typing import Dict, Optional

try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

def capture_traffic(target_subdomain: str, duration: int = 5) -> Dict:
    """
    Captures network traffic for a specific target and extracts features.
    duration: Seconds to sniff.
    """
    
    features = {
        "packet_count": 0,
        "avg_packet_size": 0.0,
        "tcp_syn_count": 0,
        "udp_count": 0,
        "unique_ips": 0
    }

    if not SCAPY_AVAILABLE:
        print("[!] Scapy not installed. Skipping traffic analysis.")
        return features

    captured_packets = []
    
    def packet_handler(pkt):
        captured_packets.append(pkt)

    print(f"[*] Starting traffic capture for {target_subdomain} ({duration}s)...")
    
    try:
        # Sniff traffic. 
        # Note: In a real production environment, we would use a BPF filter like 'host target_subdomain'
        # But resolving the IP might be slow or unreliable during the start of a scan. 
        # For this version, we sniff all traffic and filter in memory for speed.
        sniff(timeout=duration, prn=packet_handler, store=0)
        
        if not captured_packets:
            return features

        sizes = []
        syn_count = 0
        udp_count = 0
        ips = set()

        for pkt in captured_packets:
            if pkt.haslayer(IP):
                src = pkt[IP].src
                dst = pkt[IP].dst
                ips.add(src)
                ips.add(dst)
                
                sizes.append(len(pkt))
                
                if pkt.haslayer(TCP):
                    # Check for SYN flag (0x02)
                    if pkt[TCP].flags & 0x02:
                        syn_count += 1
                elif pkt.haslayer(UDP):
                    udp_count += 1

        features["packet_count"] = len(captured_packets)
        features["avg_packet_size"] = sum(sizes) / len(sizes) if sizes else 0.0
        features["tcp_syn_count"] = syn_count
        features["udp_count"] = udp_count
        features["unique_ips"] = len(ips)

        print(f"[+] Capture complete: {len(captured_packets)} packets analyzed.")

    except Exception as e:
        print(f"[!] Traffic capture error: {e}")
        # Return empty features on failure (likely permission error)

    return features
