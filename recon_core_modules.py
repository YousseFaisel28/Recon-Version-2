import os
import json
import uuid
import logging
import urllib.request
import concurrent.futures
import networkx as nx
from datetime import datetime
from typing import List, Dict, Tuple, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ==========================================
# 1. EPSS Integration & Concurrency
# ==========================================
EPSS_CACHE_FILE = "epss_cache.json"

def fetch_single_epss_score(cve_id: str, cvss_fallback: float = 0.0) -> float:
    """
    Fetches a single EPSS score with local JSON caching and CVSS fallback.
    """
    if not cve_id or not cve_id.upper().startswith("CVE-"):
        return cvss_fallback / 10.0
        
    # Check local cache
    cache = {}
    if os.path.exists(EPSS_CACHE_FILE):
        try:
            with open(EPSS_CACHE_FILE, 'r') as f:
                cache = json.load(f)
        except Exception:
            pass
            
    if cve_id in cache:
        return cache[cve_id]
    
    # Fetch from API
    url = f"https://api.first.org/epss/api/v1/cve/{cve_id}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'ReconX/1.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data.get("data") and len(data["data"]) > 0:
                score = float(data["data"][0].get("epss", 0.0))
                # Update Cache
                cache[cve_id] = score
                try:
                    with open(EPSS_CACHE_FILE, 'w') as f:
                        json.dump(cache, f)
                except Exception:
                    pass
                return score
    except Exception as e:
        logging.warning(f"EPSS API failed for {cve_id}. Using CVSS fallback. ({e})")
        
    return cvss_fallback / 10.0

def fetch_epss_scores_concurrently(cve_data: List[Tuple[str, float]], max_workers: int = 10) -> Dict[str, float]:
    """
    Uses ThreadPoolExecutor to fetch multiple EPSS scores concurrently.
    Accepts a list of tuples: (cve_id, cvss_fallback).
    """
    epss_results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_cve = {executor.submit(fetch_single_epss_score, cve, fallback): cve for cve, fallback in cve_data}
        
        for future in concurrent.futures.as_completed(future_to_cve):
            cve = future_to_cve[future]
            try:
                epss_results[cve] = future.result()
            except Exception:
                epss_results[cve] = 0.0
                
    return epss_results

# ==========================================
# 2. Risk Scoring (CVSS x EPSS)
# ==========================================
def calculate_risk_score(cvss_score: float, epss_probability: float) -> float:
    """
    Calculates the defensible Risk Score. Risk = Impact (CVSS) * Likelihood (EPSS).
    Returns a score between 0.0 and 10.0.
    """
    # Ensure values are within expected ranges
    cvss = max(0.0, min(10.0, float(cvss_score)))
    epss = max(0.0, min(1.0, float(epss_probability)))
    
    return round(cvss * epss, 2)

# ==========================================
# 3. Heuristic Confidence Scoring
# ==========================================
def calculate_heuristic_confidence(severity: str, exploit_available: bool, is_public_port: bool) -> float:
    """
    Transparent, rule-based point deduction system for determining finding confidence.
    Replaces "black-box" AI claims with easily explainable logic.
    Returns a confidence score between 0.0 and 1.0.
    """
    confidence = 1.0 # Base confidence is 100%
    severity = severity.lower()
    
    # Rule 1: Severity Impact
    if severity == "info":
        confidence -= 0.4
    elif severity == "low":
        confidence -= 0.2
        
    # Rule 2: Exploitability
    if not exploit_available:
        confidence -= 0.15
        
    # Rule 3: Exposure
    if not is_public_port:
        confidence -= 0.2
        
    # Floor at 0.0
    return max(0.0, round(confidence, 2))

# ==========================================
# 4. Graph Analysis Enhancement
# ==========================================
def build_and_analyze_attack_graph(target_domain: str, vulnerabilities: List[Dict]) -> Dict[str, Any]:
    """
    Builds a NetworkX graph using node types and EPSS-derived edge weights,
    then calculates the shortest path using Dijkstra's algorithm.
    """
    graph = nx.DiGraph()
    
    # Add Internet root node
    graph.add_node("Internet", type="external", category="entry_point")
    graph.add_node(target_domain, type="domain", category="target")
    graph.add_edge("Internet", target_domain, weight=1.0, label="Target_Scope")
    
    # Internal target we want to reach
    graph.add_node("Internal_Asset_X", type="internal", category="database")
    
    for vuln in vulnerabilities:
        host = vuln.get("subdomain", target_domain)
        cve_id = vuln.get("cve_id", "Unknown-CVE")
        epss_prob = vuln.get("epss_score", 0.0)
        service_name = vuln.get("service_name", "").lower()
        
        # 1. Determine Node Category based on service name
        category = "web_service"
        if "sql" in service_name or "db" in service_name:
            category = "database"
        elif "ssh" in service_name or "ftp" in service_name:
            category = "infrastructure"
            
        # Add Vulnerability Node
        vuln_node = f"Vuln_{cve_id}_{host}"
        graph.add_node(vuln_node, type="vulnerability", category=category)
        
        # 2. Determine Edge Weight (Dijkstra seeks lowest weight. High EPSS = Low Weight)
        weight = max(1.0, 10.0 - (epss_prob * 10.0))
        
        # 3. Contextual Edge Label
        edge_label = "Exploitable_Service"
        if epss_prob >= 0.5:
            edge_label = "High_Probability_Exploit"
        elif "privilege" in str(vuln).lower():
            edge_label = "Privilege_Escalation"
            
        graph.add_edge(host, vuln_node, weight=weight, label=edge_label)
        
        # Link vulnerability to internal asset
        graph.add_edge(vuln_node, "Internal_Asset_X", weight=1.0, label="Pivot_Path")

    # Calculate Path of Least Resistance (Dijkstra)
    paths = {}
    try:
        shortest_path = nx.dijkstra_path(graph, source="Internet", target="Internal_Asset_X")
        paths["path_of_least_resistance"] = shortest_path
    except nx.NetworkXNoPath:
        paths["path_of_least_resistance"] = []
        
    return paths

# ==========================================
# 5. Delta Scan Tracking (Enterprise Auditing)
# ==========================================
def track_scan_deltas(current_scan_records: List[Dict], history_file: str = "scan_history.json") -> Tuple[List[Dict], List[Dict]]:
    """
    Compares current scan records against the local history to track state changes over time.
    Injects UUID scan_ids and ISO timestamps. Returns (Updated_Current_Records, Resolved_Records).
    """
    previous_state = {}
    if os.path.exists(history_file):
        try:
            with open(history_file, 'r') as f:
                previous_state = json.load(f)
        except Exception:
            logging.error("Failed to read scan history. Starting fresh.")
            
    scan_id = f"scan-{uuid.uuid4().hex[:8]}"
    current_time = datetime.now().isoformat()
    
    new_state = {}
    resolved_records = []
    
    # 1. Process Current Records (Determine NEW or EXISTING)
    for rec in current_scan_records:
        # Create a unique key for the vulnerability instance
        key = f"{rec.get('cve_id', 'unknown')}_{rec.get('subdomain', 'unknown')}"
        
        if key not in previous_state:
            rec["delta_status"] = "NEW"
            rec["first_seen"] = current_time
        else:
            rec["delta_status"] = "EXISTING"
            rec["first_seen"] = previous_state[key].get("first_seen", current_time)
            
        rec["last_seen"] = current_time
        rec["scan_id"] = scan_id
        new_state[key] = rec
        
    # 2. Find Resolved Records (In previous state, but not in current)
    for key, old_rec in previous_state.items():
        if key not in new_state:
            old_rec["delta_status"] = "RESOLVED"
            old_rec["last_seen"] = current_time # Time it was verified resolved
            resolved_records.append(old_rec)
            
    # 3. Save New State
    try:
        with open(history_file, 'w') as f:
            json.dump(new_state, f, indent=4)
    except Exception as e:
        logging.error(f"Failed to save scan history: {e}")
        
    return list(new_state.values()), resolved_records
