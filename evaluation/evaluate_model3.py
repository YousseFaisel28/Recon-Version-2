"""
Evaluation Script for Model 3 (Supervised ML)
==============================================

Evaluates the new refactored Model 3 which uses Logistic Regression
and NVD ground truth.
"""

import sys
import os
import json
import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.model3 import classify_vulnerability_status, load_artifacts

def evaluate_model3():
    print("\n" + "="*80)
    print("MODEL 3 EVALUATION (SUPERVISED ML)")
    print("="*80)
    
    # 1. Load Pre-computed Metrics (from training phase)
    try:
        metrics_path = os.path.join("models", "artifacts", "model3", "model3_metrics.json")
        with open(metrics_path, 'r') as f:
            metrics = json.load(f)
            
        print("\n[Training Metrics] (20% Holdout Test Set)")
        lr = metrics['logistic_regression']
        print(f"  Accuracy:  {lr['accuracy']:.4f}")
        print(f"  Precision: {lr['precision']:.4f}")
        print(f"  Recall:    {lr['recall']:.4f}")
        print(f"  F1-Score:  {lr['f1']:.4f}")
        print(f"  Dataset:   {metrics['dataset_size']} samples")
        
    except FileNotFoundError:
        print("[!] Training metrics not found.")

    # 2. Functional Test
    print("\n[Functional Test] Inference Pipeline")
    
    # Mock CVE data for testing
    test_cases = [
        {
            "tech": "Apache", "ver": "2.4.49",
            "cves": [{"cvss": 9.8}, {"cvss": 7.5}],
            "expected": "vulnerable"
        },
        {
            "tech": "jQuery", "ver": "3.7.0",
            "cves": [],
            "expected": "safe"
        },
        {
            "tech": "Log4j", "ver": "2.14.1",
            "cves": [{"cvss": 10.0}],
            "expected": "vulnerable"
        }
    ]
    
    for case in test_cases:
        result = classify_vulnerability_status(case["tech"], case["ver"], case["cves"])
        status = result["status"]
        conf = result["confidence"]
        match = "[OK]" if status == case["expected"] else "[FAIL]"
        
        print(f"  {case['tech']} {case['ver']} -> Prediction: {status} ({conf:.4f}) {match}")

    print("\n" + "="*80)
    print("EVALUATION COMPLETE")
    print("="*80)

if __name__ == "__main__":
    evaluate_model3()
