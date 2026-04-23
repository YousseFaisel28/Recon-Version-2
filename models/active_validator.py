import requests
import subprocess
import json
import logging
import urllib.parse
from typing import Dict, Any

logger = logging.getLogger(__name__)

def check_waf_presence(target_url: str) -> Dict[str, Any]:
    """
    Infers the presence of a WAF by sending a benign XSS payload.
    Returns a dictionary containing the WAF status and HTTP response code.
    """
    payload = "<script>alert('ReconX_WAF_Test')</script>"
    # Ensure URL ends with / if there is no path or query
    parsed_url = urllib.parse.urlparse(target_url)
    if not parsed_url.path:
        target_url = target_url.rstrip('/') + '/'
        
    test_url = f"{target_url}?q={urllib.parse.quote(payload)}"
    
    headers = {
        "User-Agent": "ReconX-Validator/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
    
    try:
        response = requests.get(test_url, headers=headers, timeout=10, allow_redirects=True)
        status_code = response.status_code
        
        # Check common WAF block codes
        if status_code in [403, 406]:
            return {"is_blocked": True, "status_code": status_code, "reason": f"HTTP {status_code}"}
        
        # Check for CAPTCHA or common WAF block page signatures
        text_lower = response.text.lower()
        waf_signatures = ["captcha", "cloudflare", "imperva", "access denied", "security policy"]
        if any(sig in text_lower for sig in waf_signatures):
             return {"is_blocked": True, "status_code": status_code, "reason": "WAF Signature Detected"}
             
        return {"is_blocked": False, "status_code": status_code, "reason": "OK"}
        
    except requests.exceptions.RequestException as e:
        logger.warning(f"[Active Validator] WAF check failed for {target_url}: {e}")
        return {"is_blocked": False, "status_code": 0, "reason": "Connection Error"}

def run_nuclei_validation(cve_id: str, target_url: str) -> bool:
    """
    Runs Nuclei against the target URL for the specific CVE.
    Returns True if the vulnerability is exploitable, False otherwise.
    """
    command = [
        "nuclei",
        "-target", target_url,
        "-tags", cve_id.lower(),
        "-json-export", "-", # Output JSON to stdout
        "-silent", # Only show findings
        "-no-interact",
        "-t", "cves" # Focus on CVE templates to speed up and avoid intrusive attacks
    ]
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        
        if result.returncode != 0 and not result.stdout:
            logger.warning(f"[Active Validator] Nuclei command failed: {result.stderr}")
            return False
            
        # Parse JSON output. Each finding is a JSON line.
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            try:
                finding = json.loads(line)
                if finding.get("info", {}).get("classification", {}).get("cve-id", []) or cve_id.lower() in line.lower():
                    # Finding matched the CVE
                    return True
            except json.JSONDecodeError:
                continue
                
        return False
        
    except subprocess.TimeoutExpired:
        logger.warning(f"[Active Validator] Nuclei timeout for {cve_id} on {target_url}")
        return False
    except FileNotFoundError:
        logger.error("[Active Validator] Nuclei executable not found in PATH.")
        return False
    except Exception as e:
        logger.error(f"[Active Validator] Unexpected error running Nuclei: {e}")
        return False

def validate_cve(cve_id: str, target_url: str) -> Dict[str, Any]:
    """
    Orchestrates the active validation of a CVE on a target URL.
    Returns a structured JSON object suitable for Model 7.
    """
    logger.info(f"[Active Validator] Starting validation for {cve_id} on {target_url}")
    
    # 1. WAF Inference Check
    waf_result = check_waf_presence(target_url)
    
    if waf_result["is_blocked"]:
        logger.info(f"[Active Validator] {target_url} blocked by WAF. Skipping Nuclei.")
        return {
            "cve_id": cve_id,
            "validation_status": "Blocked by WAF",
            "http_response_code": waf_result["status_code"]
        }
        
    # 2. Nuclei Active Validation
    is_exploitable = run_nuclei_validation(cve_id, target_url)
    
    if is_exploitable:
        status = "Exploitable"
    else:
        status = "Patched"
        
    return {
        "cve_id": cve_id,
        "validation_status": status,
        "http_response_code": waf_result["status_code"]
    }
