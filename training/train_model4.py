"""
Training Script for Model 4 (HTTP Anomaly Detection)
=====================================================

Design:
- Features: HTTP Headers, Traffic Patterns
- Model: Isolation Forest (Unsupervised)
- Output: models/artifacts/model4/model4_iforest.pkl
"""
import sys
import os
import numpy as np

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.model4 import HTTPAnomalyModel
from utils.http_collector import collect_http_features
from utils.traffic_collector import capture_traffic

def train_model4():
    print("[*] Initializing Model 4 Training...")
    # Update path to new artifact location
    model_path = os.path.join("models", "artifacts", "model4", "model4_iforest.pkl")
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    
    model = HTTPAnomalyModel(model_path=model_path)

    # Educational dataset (Safe baseline)
    urls = [
        ("https://google.com", "google.com"),
        ("https://github.com", "github.com"),
        ("https://microsoft.com", "microsoft.com"),
        ("https://amazon.com", "amazon.com"),
        ("https://cloudflare.com", "cloudflare.com")
    ]

    dataset = []
    for url, domain in urls:
        print(f"[*] Capturing baseline features for {domain}...")
        try:
            f = collect_http_features(url)
            t = capture_traffic(domain, duration=2)
            f.update(t)
            dataset.append(f)
        except Exception as e:
            print(f"  [!] Error on {domain}: {e}")

    if dataset:
        print(f"[*] Training on {len(dataset)} samples...")
        model.train(dataset)
        print(f"[OK] Model 4 artifact saved to {model_path}")
    else:
        print("[Error] No training data collected.")

if __name__ == "__main__":
    train_model4()
