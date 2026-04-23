import time
from utils.traffic_collector import capture_traffic

print(capture_traffic('example.com', duration=3))
