import time
import requests
from concurrent.futures import ThreadPoolExecutor
from utils.traffic_collector import capture_traffic
from utils.http_collector import collect_http_features

def simulate_scan(subdomain):
    url = f"http://{subdomain}"
    print(f"[*] Simulating scan for {url}")
    with ThreadPoolExecutor(max_workers=2) as coll_exec:
        traffic_future = coll_exec.submit(capture_traffic, subdomain, duration=3)
        time.sleep(1)
        http_future = coll_exec.submit(collect_http_features, url)
        
        features = http_future.result()
        traffic_features = traffic_future.result()
        
        print("HTTP Features:", features)
        print("Traffic Features:", traffic_features)

simulate_scan("vulnweb.com")
