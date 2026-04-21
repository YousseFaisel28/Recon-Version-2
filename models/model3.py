"""
Model 3: Technology Fingerprinting & Vulnerability Detection (Supervised ML)

Input: Nmap output, Web banners
Output: Detected technologies, CVE mappings, Vulnerability Prediction
"""
import numpy as np
import os
import re
import logging
import joblib
from scipy.sparse import hstack
from typing import Dict, List, Optional
from utils.tech_fingerprint_tool import fingerprint_technologies

# Global variables for model artifacts
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "models", "artifacts", "model3")
LR_MODEL_PATH = os.path.join(MODEL_DIR, "model3_lr.pkl")
TFIDF_PATH = os.path.join(MODEL_DIR, "model3_tfidf.pkl")

# Cache for loaded models
_artifacts = {
    "model": None,
    "tfidf": None
}

logger = logging.getLogger(__name__)


def create_technology_fingerprint(tech_name, version=""):
    """
    Create a fingerprint string from technology name and version.
    Used for TF-IDF vectorization.
    """
    fingerprint = f"{tech_name.lower()} {version.lower()}"
    # Add version components separately for better matching
    if version:
        version_parts = re.findall(r'\d+', version)
        fingerprint += " " + " ".join(version_parts)
    return fingerprint.strip()


def load_artifacts():
    """Load model artifacts with caching"""
    if _artifacts["model"] is not None and _artifacts["tfidf"] is not None:
        return _artifacts["model"], _artifacts["tfidf"]
    
    try:
        if os.path.exists(LR_MODEL_PATH) and os.path.exists(TFIDF_PATH):
            _artifacts["model"] = joblib.load(LR_MODEL_PATH)
            _artifacts["tfidf"] = joblib.load(TFIDF_PATH)
            # print(f"[Model 3] Loaded ML models from {MODEL_DIR}")
        else:
            print(f"[Model 3] Warning: Model artifacts not found. Run scripts/train_model3.py")
    except Exception as e:
        print(f"[Model 3] Error loading models: {e}")
        
    return _artifacts["model"], _artifacts["tfidf"]


from packaging.version import Version, InvalidVersion

def is_version_in_range(v_str: str, range_info: dict) -> tuple:
    """
    Programmatic comparison of detected version against NVD range definitions.
    Returns: (bool, status_label, range_str)
    """
    try:
        v = Version(v_str)
        
        start_inc = range_info.get("start_inc")
        start_exc = range_info.get("start_exc")
        end_inc = range_info.get("end_inc")
        end_exc = range_info.get("end_exc")
        
        # Build range string for justification
        s = start_inc or start_exc or "0"
        e = end_inc or end_exc or "latest"
        range_str = f"{s} – {e}"
        
        # Check boundaries first (Task 1 Rule 2 in Master Prompt)
        is_boundary = False
        if start_inc and v == Version(start_inc): is_boundary = True
        if start_exc and v == Version(start_exc): is_boundary = True
        if end_inc and v == Version(end_inc): is_boundary = True
        if end_exc and v == Version(end_exc): is_boundary = True
        
        if is_boundary:
            return True, "UNCERTAIN (BOUNDARY CASE)", range_str

        in_start = True
        if start_inc: in_start = (v >= Version(start_inc))
        elif start_exc: in_start = (v > Version(start_exc))
        
        in_end = True
        if end_inc: in_end = (v <= Version(end_inc))
        elif end_exc: in_end = (v < Version(end_exc))
        
        if in_start and in_end:
            return True, "CONFIRMED VULNERABILITY", range_str
            
        return False, "NOT AFFECTED", range_str
        
    except (InvalidVersion, ValueError, TypeError):
        return False, "INSUFFICIENT EVIDENCE", "Unclear"

def lookup_cve(tech_name, version=""):
    """
    Lookup CVE information using NVD API.
    """
    cves = []
    try:
        from utils.nvd_api_tool import get_nvd_client
        from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
        
        client = get_nvd_client()
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(client.lookup_technology_vulnerabilities, tech_name, version)
        
        try:
            df = future.result(timeout=25)  # NVD API can be slow; 25 s gives it enough time
            if df is not None and not df.empty:
                for _, row in df.head(10).iterrows():
                    cves.append({
                        "cve": row["cve_id"],
                        "cvss": float(row["cvss_score"]),
                        "description": row["description"][:200],
                        "severity": row["severity"],
                        "published_date": row["published_date"],
                        "affected_versions": row.get("affected_versions", []),
                        "cwe": row.get("cwe", "N/A")
                    })
        except FutureTimeoutError:
            logger.warning(f"[Model 3] NVD lookup timed out for {tech_name} {version} — CVEs may be incomplete")
        except Exception as _e:
            logger.warning(f"[Model 3] NVD API error for {tech_name} {version}: {_e}")
            
    except Exception as e:
        # Fallback to empty context if NVD tool fails drastically
        print(f"[Model 3] NVD lookup error: {e}")
    
    return cves


def classify_vulnerability_status(tech_name, version, cves):
    """
    STRICT MODE: Programmatic justification replaces supervised ML.
    """
    # Reject if missing data (Task 1 Rule 4)
    if not version:
        return {
            "status": "safe",
            "confidence": 0.0,
            "reason": "INSUFFICIENT EVIDENCE: Version missing",
            "cves": []
        }

    valid_cves = []
    
    for cve in cves:
        affected_ranges = cve.get("affected_versions", [])
        
        if not affected_ranges:
            continue
            
        final_justification = "NOT AFFECTED"
        final_range = "N/A"
        matched = False
        
        for r_info in affected_ranges:
            is_match, status, r_str = is_version_in_range(version, r_info)
            if is_match:
                matched = True
                final_range = r_str
                if status == "CONFIRMED VULNERABILITY":
                    final_justification = f"Version {version} is within affected range {r_str}"
                    break
                else:
                    final_justification = status # e.g. UNCERTAIN (BOUNDARY CASE)
                    # Keep looking for a confirmed match in other ranges
        
        if matched:
            cve["justification"] = final_justification
            cve["affected_version_range"] = final_range
            valid_cves.append(cve)
            
    if not valid_cves:
        return {
            "status": "safe",
            "confidence": 1.0,
            "reason": "No confirmed vulnerabilities for this version",
            "cves": []
        }
        
    return {
        "status": "vulnerable",
        "confidence": 1.0,
        "reason": f"Confirmed {len(valid_cves)} matches",
        "cves": valid_cves
    }


def run_technology_fingerprinting(urls_data):
    """
    Main function for Model 3: Technology Fingerprinting & Vulnerability Detection.
    """
    results = []
    
    # Pre-load models once
    load_artifacts()
    
    for url_info in urls_data:
        url = url_info.get("url")
        is_root = url_info.get("is_root", False)
        nmap_data = url_info.get("nmap_data")
        whatweb_result = url_info.get("whatweb_result")
        
        if not url:
            continue
        
        # Step 1: Fingerprint technologies
        technologies = fingerprint_technologies(url, nmap_data, whatweb_result)
        
        # Step 2: Process each technology
        tech_results = []
        for tech in technologies:
            tech_name = tech.get("name", "")
            version = tech.get("version", "")
            
            # Step 2a: Lookup CVEs (Required for features)
            cves = lookup_cve(tech_name, version)
            
            # Step 2b: Strict Classification (Task 1)
            vuln_status = classify_vulnerability_status(tech_name, version, cves)
            
            # Extract filtered CVEs from status result
            filtered_cves = vuln_status.get("cves", [])
            
            tech_result = {
                "technology": tech_name,
                "version": version,
                "category": tech.get("category", "Unknown"),
                # Task 1 Rule 2: Extract ONLY CVEs where version range matches
                "cves": filtered_cves,
                "vulnerability_status": vuln_status["status"],
                "confidence": vuln_status["confidence"],
                "max_cvss": max([c.get("cvss", 0) for c in filtered_cves]) if filtered_cves else 0.0,
                "source": tech.get("source", ""),
                "similarity_score": None,
                "metadata": {
                    "port": tech.get("port"),
                    "raw_data": tech.get("raw_data", {})
                }
            }
            
            tech_results.append(tech_result)
        
        results.append({
            "url": url,
            "is_root": is_root,
            "technologies": tech_results,
            "vulnerable_count": sum(1 for t in tech_results if t["vulnerability_status"] == "vulnerable"),
            "safe_count": sum(1 for t in tech_results if t["vulnerability_status"] == "safe")
        })
    
    return results


def run_technology_fingerprinting_for_subdomains(subdomains_data):
    """
    Run technology fingerprinting for multiple subdomains.
    """
    urls_data = []
    for sub_data in subdomains_data:
        url = sub_data.get("url") or f"http://{sub_data.get('subdomain', '')}"
        urls_data.append({
            "url": url,
            "is_root": sub_data.get("is_root", False),
            "nmap_data": sub_data.get("nmap_data"),
            "whatweb_result": None
        })
    
    return run_technology_fingerprinting(urls_data)

