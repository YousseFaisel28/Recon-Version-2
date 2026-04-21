import sys
import os

# Add root to sys path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(BASE_DIR, "models"))
sys.path.insert(0, os.path.join(BASE_DIR, "utils"))

from models.ai_port_service.model_inference import get_predict_service

def run_tests():
    fingerprints = [
        {"port": 80, "protocol": "tcp", "state": "open", "banner": "Apache 2.4.40 ubuntu"},
        {"port": 3306, "protocol": "tcp", "state": "open", "banner": "mysql_native_password caching_sha2_password"},
        {"port": 12345, "protocol": "tcp", "state": "open", "banner": "ssh openssh protocol 2.0 dropbear"},
    ]
    
    print("[*] Testing Inference AI with Random Forest...")
    rf_results = get_predict_service(fingerprints, model_type="rf")
    
    print("\n--- RF Results ---")
    for r in rf_results:
        print(f"Port {r['port']}: {r['service']} v{r['version']} (Confidence: {r['confidence']})")
        
    print("\n[*] Testing Inference AI with SVM...")
    svm_results = get_predict_service(fingerprints, model_type="svm")
    
    print("\n--- SVM Results ---")
    for r in svm_results:
        print(f"Port {r['port']}: {r['service']} v{r['version']} (Confidence: {r['confidence']})")

if __name__ == "__main__":
    run_tests()
