import time
import scapy.all as scapy

scapy.conf.L3socket = scapy.L3RawSocket
print("Trying to sniff...")
try:
    scapy.sniff(timeout=3, store=0, count=2)
    print("Sniffing worked!")
except Exception as e:
    print(f"Failed: {e}")
