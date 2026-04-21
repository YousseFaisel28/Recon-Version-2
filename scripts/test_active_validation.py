import sys
import os
import json

# Add the project root to sys.path to import models
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.active_validator import validate_cve

def main():
    if len(sys.argv) < 3:
        print("Usage: python test_active_validation.py <CVE_ID> <TARGET_URL>")
        print("Example: python test_active_validation.py CVE-2021-44228 https://example.com")
        sys.exit(1)

    cve_id = sys.argv[1]
    target_url = sys.argv[2]

    print(f"[*] Starting active validation for {cve_id} on {target_url}...")
    
    result = validate_cve(cve_id, target_url)
    
    print("\n[+] Validation Results:")
    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    main()
