import os
import json
import uuid
import time
import logging
import urllib.request
import urllib.error
import networkx as nx
import concurrent.futures
from datetime import datetime
from typing import List, Dict, Tuple, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ==========================================
# 1 & 2. EPSS Reliability & Safe Caching
# ==========================================
EPSS_CACHE_FILE = "epss_cache.json"

def _load_epss_cache() -> Dict[str, float]:
    """Safely loads the EPSS cache, handling missing or corrupt files."""
    if not os.path.exists(EPSS_CACHE_FILE):
        return {}
    try:
        with open(EPSS_CACHE_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logging.warning(f"Failed to read EPSS cache, creating new one. Error: {e}")
        return {}

def _save_epss_cache(cache_data: Dict[str, float]) -> None:
    """Safely saves the EPSS cache using a temporary file to prevent corruption during crash."""
    tmp_file = f"{EPSS_CACHE_FILE}.tmp"
    try:
        with open(tmp_file, 'w') as f:
            json.dump(cache_data, f)
        os.replace(tmp_file, EPSS_CACHE_FILE) # Atomic replacement on POSIX, nearly atomic on Windows
    except OSError as e:
        logging.error(f"Failed to save EPSS cache: {e}")

def fetch_epss_score_reliable(cve_id: str, cvss_fallback: float = 0.0, max_retries: int = 3) -> float:
    """
    Fetches EPSS score with exponential backoff, timeouts, and safe caching.
    """
    if not cve_id or not cve_id.upper().startswith("CVE-"):
        return cvss_fallback / 10.0
        
    cache = _load_epss_cache()
    if cve_id in cache:
        return cache[cve_id]
    
    url = f"https://api.first.org/epss/api/v1/cve/{cve_id}"
    
    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'ReconX-Pipeline/1.0'})
            # 5-second timeout to prevent indefinite hanging
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                if data.get("data") and len(data["data"]) > 0:
                    score = float(data["data"][0].get("epss", 0.0))
                    cache[cve_id] = score
                    _save_epss_cache(cache)
                    return score
                break # Successful request but no data, don't retry
                
        except urllib.error.URLError as e:
            logging.warning(f"EPSS API network error for {cve_id} (Attempt {attempt+1}/{max_retries}): {e}")
            time.sleep(2 ** attempt) # Exponential backoff: 1s, 2s, 4s
        except json.JSONDecodeError:
            logging.error(f"Malformed JSON from EPSS API for {cve_id}.")
            break # Bad API response, don't retry
        except Exception as e:
            logging.error(f"Unexpected error fetching EPSS for {cve_id}: {e}")
            break
            
    # Fallback to CVSS approximation if all retries fail
    return cvss_fallback / 10.0

def fetch_epss_scores_concurrently(cve_data: List[Tuple[str, float]], max_workers: int = 10) -> Dict[str, float]:
    """
    Fetches multiple EPSS scores concurrently while avoiding duplicate API calls for the same CVE.
    """
    # Deduplicate the requested CVEs to prevent redundant API calls
    unique_requests = {cve: fallback for cve, fallback in cve_data}
    
    epss_results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_cve = {
            executor.submit(fetch_epss_score_reliable, cve, fallback): cve 
            for cve, fallback in unique_requests.items()
        }
        
        for future in concurrent.futures.as_completed(future_to_cve):
            cve = future_to_cve[future]
            try:
                epss_results[cve] = future.result()
            except Exception:
                epss_results[cve] = unique_requests[cve] / 10.0
                
    return epss_results

# ==========================================
# 3. Masscan Output Normalization
# ==========================================
def normalize_masscan_output(masscan_json_path: str) -> Dict[str, List[int]]:
    """
    Cleans and validates Masscan JSON output.
    Returns: Dict mapping IP/Domain -> sorted list of unique integer ports.
    """
    normalized_ports = {}
    if not os.path.exists(masscan_json_path):
        logging.warning(f"Masscan output file {masscan_json_path} not found.")
        return normalized_ports
        
    try:
        with open(masscan_json_path, 'r') as f:
            data = json.load(f)
            
        for entry in data:
            ip = entry.get('ip')
            if not ip:
                continue
                
            if ip not in normalized_ports:
                normalized_ports[ip] = set()
                
            for pinfo in entry.get('ports', []):
                port = pinfo.get('port')
                # Validate port is an integer
                if port and str(port).isdigit():
                    normalized_ports[ip].add(int(port))
                    
    except json.JSONDecodeError:
        logging.error("Masscan output is malformed or empty.")
    except Exception as e:
        logging.error(f"Error normalizing Masscan output: {e}")
        
    # Convert sets to sorted lists
    return {ip: sorted(list(ports)) for ip, ports in normalized_ports.items()}

# ==========================================
# 4. Nuclei Results Normalization & Deduplication
# ==========================================
def normalize_nuclei_results(raw_vulns: List[Dict]) -> List[Dict]:
    """
    Normalizes Nuclei records and deduplicates using a stable composite key.
    """
    unique_vulns = {}
    
    for v in raw_vulns:
        cve_id = v.get("template-id", "unknown-id")
        host = v.get("host", "unknown-host")
        port = str(v.get("port", "80"))
        matched_at = v.get("matched-at", "unknown-path")
        
        # Stable unique key for deduplication
        composite_key = f"{cve_id}::{host}::{port}::{matched_at}"
        
        # If duplicate exists, we keep the one already stored to prevent thrashing
        if composite_key not in unique_vulns:
            severity = v.get("info", {}).get("severity", "info")
            cvss_score = v.get("info", {}).get("classification", {}).get("cvss-score", 0.0)
            
            normalized_record = {
                "cve_id": cve_id,
                "host": host,
                "port": int(port) if port.isdigit() else 80,
                "matched_path": matched_at,
                "severity": severity,
                "cvss_score": float(cvss_score),
                "raw_data": v # Keep raw data for downstream processing if needed
            }
            unique_vulns[composite_key] = normalized_record
            
    return list(unique_vulns.values())

# ==========================================
# 5. Graph Construction Cleanup (NetworkX)
# ==========================================
def build_robust_attack_graph(target_domain: str, normalized_vulns: List[Dict], epss_scores: Dict[str, float]) -> nx.DiGraph:
    """
    Builds a NetworkX graph enforcing explicit node types and safe edge weight derivation.
    """
    graph = nx.DiGraph()
    
    # Explicit Node Types
    NODE_INTERNET = "internet"
    NODE_DOMAIN = "domain"
    NODE_VULN = "vulnerability"
    NODE_INTERNAL = "internal_asset"
    
    # Setup base graph
    graph.add_node("Internet", type=NODE_INTERNET, category="entry_point")
    graph.add_node(target_domain, type=NODE_DOMAIN, category="target")
    graph.add_edge("Internet", target_domain, weight=1.0)
    
    internal_target = "Internal_Network"
    graph.add_node(internal_target, type=NODE_INTERNAL, category="infrastructure")
    
    for vuln in normalized_vulns:
        cve_id = vuln.get("cve_id")
        host = vuln.get("host")
        
        # Safe EPSS retrieval (defaults to 0.0 if missing)
        epss_prob = epss_scores.get(cve_id, 0.0)
        
        # Derived Edge Weight: Low weight = High probability
        edge_weight = max(1.0, 10.0 - (epss_prob * 10.0))
        
        vuln_node_id = f"Vuln::{cve_id}::{host}"
        
        # Safe Node Addition
        if not graph.has_node(vuln_node_id):
            graph.add_node(
                vuln_node_id, 
                type=NODE_VULN, 
                category="web_service", # Default, can be expanded based on tech stack
                cve_id=cve_id,
                epss_score=epss_prob
            )
            
        # Safe Edge Addition (Internet -> Host -> Vuln -> Internal)
        if not graph.has_node(host):
            graph.add_node(host, type="subdomain", category="target")
            graph.add_edge(target_domain, host, weight=1.0)
            
        graph.add_edge(host, vuln_node_id, weight=edge_weight, label="Exploitable_Service")
        graph.add_edge(vuln_node_id, internal_target, weight=1.0, label="Pivot_Path")
        
    return graph

# ==========================================
# 6. Delta Tracking Stability
# ==========================================
def robust_delta_tracking(current_records: List[Dict], history_file: str = "scan_history.json", resolve_threshold: int = 2) -> Tuple[List[Dict], List[Dict]]:
    """
    Improves Delta Tracking by preventing false 'RESOLVED' statuses.
    A vulnerability must be absent for 'N' consecutive scans before being marked RESOLVED.
    """
    previous_state = {}
    if os.path.exists(history_file):
        try:
            with open(history_file, 'r') as f:
                previous_state = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logging.error(f"Failed to read scan history cleanly: {e}. Starting fresh state.")
            
    scan_id = f"scan-{uuid.uuid4().hex[:8]}"
    current_time = datetime.now().isoformat()
    
    new_state = {}
    resolved_records = []
    
    # 1. Process Current Records (Mark NEW or EXISTING)
    current_keys = set()
    for rec in current_records:
        key = f"{rec.get('cve_id', 'unknown')}_{rec.get('host', 'unknown')}"
        current_keys.add(key)
        
        if key not in previous_state:
            rec["delta_status"] = "NEW"
            rec["first_seen"] = current_time
            rec["absent_count"] = 0
        else:
            rec["delta_status"] = "EXISTING"
            rec["first_seen"] = previous_state[key].get("first_seen", current_time)
            rec["absent_count"] = 0 # Reset absence counter since it was found
            
        rec["last_seen"] = current_time
        rec["scan_id"] = scan_id
        new_state[key] = rec
        
    # 2. Process Missing Records (Increment absent_count, check resolve_threshold)
    for key, old_rec in previous_state.items():
        if key not in current_keys:
            absent_count = old_rec.get("absent_count", 0) + 1
            old_rec["absent_count"] = absent_count
            
            if absent_count >= resolve_threshold:
                # Mark as truly resolved
                old_rec["delta_status"] = "RESOLVED"
                old_rec["resolved_at"] = current_time
                resolved_records.append(old_rec)
            else:
                # Not resolved yet, carry over to new state but mark as MISSING
                old_rec["delta_status"] = "MISSING_PENDING_VERIFICATION"
                new_state[key] = old_rec
                
    # 3. Safe Save
    tmp_file = f"{history_file}.tmp"
    try:
        with open(tmp_file, 'w') as f:
            json.dump(new_state, f, indent=4)
        os.replace(tmp_file, history_file)
    except OSError as e:
        logging.error(f"Failed to save robust scan history: {e}")
        
    return list(new_state.values()), resolved_records
