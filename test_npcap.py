import time
import requests
import threading
from utils.traffic_collector import capture_traffic

def test_capture():
    print("[*] Starting sniffer...")
    # This will block for 3 seconds
    result = capture_traffic('example.com', duration=3)
    print("Result:", result)

t = threading.Thread(target=test_capture)
t.start()

# Wait 1 second to let sniffer initialize
time.sleep(1)

print("[*] Firing HTTP request...")
try:
    requests.get('http://example.com')
except Exception as e:
    print("Request failed:", e)

t.join()
