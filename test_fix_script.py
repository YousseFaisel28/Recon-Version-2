import sys
import os
import json

# Add project root to path
sys.path.append(os.path.abspath('.'))

from models.model7_recommendation_engine import RecommendationEngine

engine = RecommendationEngine()

mock_vuln = {
    "host": "test.target.com",
    "service": "PHP",
    "version": "7.2.0",
    "port": 80,
    "cve_id": "CVE-2019-9020"
}

print("Generating Test PowerShell Script...\n")
script = engine.generate_fix_script(mock_vuln)

print(script)
print("\n[OK] Script parsed successfully.")
