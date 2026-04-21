"""
Model 4 Credibility Test
========================
This script verifies the credibility of the HTTP/Traffic Anomaly Detection model.
It tests real-world normal traffic vs synthetic abnormal traffic.
"""

import sys
import os
import joblib
import numpy as np

# Ensure project root is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from models.model4 import HTTPAnomalyModel
from utils.http_collector import collect_http_features
from utils.traffic_collector import capture_traffic

def run_test():
    print("="*60)
    print("RECON-X: MODEL 4 CREDIBILITY TEST (Isolation Forest)")
    print("="*60)

    # 1. Load Model
    try:
        model = HTTPAnomalyModel()
        model.load()
    except Exception as e:
        print(f"[X] Failed to load Model 4: {e}")
        return

    # 2. Collect Normal Samples
    normal_targets = [
        ("https://google.com", "google.com"),
        ("https://github.com", "github.com")
    ]
    
    normal_results = []
    print("\n[Phase 1] Collecting Normal Traffic Samples...")
    
    for url, domain in normal_targets:
        for i in range(3):
            print(f"[*] [{domain}] Run {i+1}/3...")
            try:
                # Capture features
                http_feat = collect_http_features(url)
                traffic_feat = capture_traffic(domain, duration=2)
                
                # Merge
                combined = {**http_feat, **traffic_feat}
                
                # Predict
                prediction = model.predict(combined)
                normal_results.append(prediction)
                
                print(f"    -> Score: {prediction['anomaly_score']} | Status: {prediction['status']}")
            except Exception as e:
                print(f"    [!] Error: {e}")

    # 3. Synthetic Abnormal Samples
    print("\n[Phase 2] Generating Synthetic Abnormal Traffic...")
    
    abnormal_samples = [
        {
            "name": "DDoS/Flood Attack Simulation",
            "features": {
                "missing_headers": 4,
                "cors_wildcard": True,
                "server_exposed": True,
                "insecure_cookies": 5,
                "response_size_kb": 500.0,
                "error_rate": 0.8,
                "status_entropy": 2.5,
                "packet_count": 5000,
                "avg_packet_size": 1500.0,
                "tcp_syn_count": 2000,
                "udp_count": 1000,
                "unique_ips": 500
            }
        },
        {
            "name": "Insecure/Exposed Configuration",
            "features": {
                "missing_headers": 4,
                "cors_wildcard": True,
                "server_exposed": True,
                "insecure_cookies": 10,
                "response_size_kb": 1.5,
                "error_rate": 0.0,
                "status_entropy": 0.0,
                "packet_count": 10,
                "avg_packet_size": 60.0,
                "tcp_syn_count": 1,
                "udp_count": 0,
                "unique_ips": 1
            }
        }
    ]

    abnormal_results = []
    for sample in abnormal_samples:
        print(f"[*] Testing {sample['name']}...")
        prediction = model.predict(sample['features'])
        abnormal_results.append(prediction)
        print(f"    -> Score: {prediction['anomaly_score']} | Status: {prediction['status']}")
        for signal in prediction.get("signals", []):
            print(f"    [!] Signal: {signal}")

    # 4. Final Summary
    print("\n" + "="*60)
    print("CREDIBILITY SUMMARY")
    print("="*60)
    
    normal_ok = all(r['status'] == 'normal' for r in normal_results)
    abnormal_ok = all(r['status'] == 'suspicious' for r in abnormal_results)
    
    # Check score separation
    avg_normal_score = np.mean([r['anomaly_score'] for r in normal_results])
    avg_abnormal_score = np.mean([r['anomaly_score'] for r in abnormal_results])
    
    print(f"- Normal Traffic Consistency:    {'PASS' if normal_ok else 'FAIL'}")
    print(f"- Abnormal Traffic Detection:    {'PASS' if abnormal_ok else 'FAIL'}")
    print(f"- Score Separation:              {'PASS' if avg_normal_score > avg_abnormal_score else 'FAIL'}")
    print(f"  (Avg Normal: {avg_normal_score:.4f} vs Avg Abnormal: {avg_abnormal_score:.4f})")
    print("-" * 60)
    
    if normal_ok and abnormal_ok:
        print("RESULT: Model 4 is CREDIBLE for production use.")
    else:
        print("RESULT: Model 4 requires retraining or threshold adjustment.")
    print("="*60)

if __name__ == "__main__":
    run_test()
