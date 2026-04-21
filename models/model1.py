"""
Model 1: Subdomain & Asset Discovery (Rule-Based + Unsupervised Clustering)

Input: Domain name
Output: Discovered subdomains, clustering analysis, and liveness status.

NOTE: This model is strictly Rule-Based (Discovery) and Unsupervised (Clustering).
It does NOT perform supervised classification or risk scoring.
"""
import numpy as np
import socket
import requests
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.sublist3r_tool import run_sublist3r, get_sublist3r_result
from models.model2 import scan_ports_parallel


def _resolve_single_subdomain(subdomain):
    """Resolve a single subdomain to IP address."""
    try:
        ip = socket.gethostbyname(subdomain)
        return (subdomain, ip)
    except socket.gaierror:
        return (subdomain, None)

def resolve_subdomains(subdomains, max_workers=50):
    """Resolve subdomains to IP addresses in parallel."""
    resolved = {}
    if not subdomains:
        return resolved
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_resolve_single_subdomain, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            subdomain, ip = future.result()
            if ip:
                resolved[subdomain] = ip
    return resolved

def _check_single_http(subdomain):
    """Check if a single subdomain has live HTTP service."""
    try:
        response = requests.get(f"http://{subdomain}", timeout=15)
        if response.status_code < 400:
            return subdomain
    except requests.RequestException:
        pass
    return None

def check_live_http(subdomains, max_workers=50):
    """Check which subdomains have live HTTP services in parallel."""
    live = []
    if not subdomains:
        return live
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_check_single_http, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            result = future.result()
            if result:
                live.append(result)
    return live


def cluster_subdomains(subdomains):
    """Cluster subdomains based on their structure (unsupervised learning with KMeans)."""
    # Lazy import to avoid slow startup
    from sklearn.cluster import KMeans
    
    if not subdomains:
        return []

    # Simple clustering based on subdomain length and number of dots
    features = []
    for sub in subdomains:
        parts = sub.split('.')
        features.append([len(sub), len(parts)])

    features = np.array(features)
    if len(features) < 2:
        return [{"cluster_id": 0, "size": len(subdomains), "examples": subdomains}]

    kmeans = KMeans(n_clusters=min(3, len(subdomains)), random_state=42)
    labels = kmeans.fit_predict(features)

    clusters = {}
    for i, label in enumerate(labels):
        if label not in clusters:
            clusters[label] = []
        clusters[label].append(subdomains[i])

    result = []
    for cluster_id, subs in clusters.items():
        result.append({
            "cluster_id": int(cluster_id),  # Convert numpy int32 to int
            "size": len(subs),
            "examples": subs[:5]  # Show up to 5 examples
        })

    return result


def _check_single_dead(subdomain):
    """Check if a single subdomain is dead or unreachable."""
    try:
        ip = socket.gethostbyname(subdomain)
    except socket.gaierror:
        return (subdomain, True)  # Unresolved -> dead

    # Try HTTP and HTTPS
    urls = [f"http://{subdomain}", f"https://{subdomain}"]
    for url in urls:
        try:
            r = requests.get(url, timeout=15)
            if r.status_code < 400:
                return (subdomain, False)  # Alive
        except:
            pass

    return (subdomain, True)  # No valid response -> dead

def check_dead_subdomains(subdomains, max_workers=50):
    """Check which subdomains are dead in parallel."""
    dead_subdomains = []
    if not subdomains:
        return dead_subdomains
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_check_single_dead, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            subdomain, is_dead = future.result()
            if is_dead:
                dead_subdomains.append(subdomain)
    return dead_subdomains


def run_subdomain_discovery(domain):
    """
    Main orchestrator function for Model 1: Subdomain Discovery.
    Performs deterministic discovery and unsupervised clustering.
    """
    start_time = time.time()

    # Step 1: Start sublist3r in background (non-blocking - returns immediately!)
    sublist3r_future = run_sublist3r(domain)
    
    # Get the result when ready (this will wait, but sublist3r is already running)
    sublist3r_result = get_sublist3r_result(sublist3r_future, timeout=300)
    
    if sublist3r_result.get("status") == "success":
        subdomains = sublist3r_result.get("subdomains", [])
    else:
        print(f"Sublist3r status: {sublist3r_result.get('status')}")
        if sublist3r_result.get("status") == "error":
            print(f"Error: {sublist3r_result.get('error')}")
        subdomains = []

    # ── ROOT DOMAIN INJECTION ──
    if domain not in subdomains:
        subdomains.insert(0, domain)
    # ───────────────────────────

    if not subdomains:
        return {
            "total_candidates": 0,
            "resolved": 0,
            "live_http": 0,
            "elapsed_seconds": time.time() - start_time,
            "clusters": [],
            "examples": [],
            "raw_docs": [],
            "ports_summary": {}
        }

    # Step 2-4: Run all checks in parallel for maximum efficiency!
    with ThreadPoolExecutor(max_workers=3) as executor:
        # Submit all parallel tasks
        resolve_future = executor.submit(resolve_subdomains, subdomains)
        live_http_future = executor.submit(check_live_http, subdomains)
        dead_future = executor.submit(check_dead_subdomains, subdomains)
        
        # Wait for all to complete
        resolved = resolve_future.result()
        live_http = live_http_future.result()
        dead_subdomains = dead_future.result()

    # Step 5: Scan ports in parallel for all resolved IPs (Data collection only)
    ip_subdomain_pairs = [(sub, ip) for sub, ip in resolved.items()]
    ports_results = scan_ports_parallel(ip_subdomain_pairs)

    # Step 6: Cluster subdomains (unsupervised learning with KMeans)
    clusters = cluster_subdomains(subdomains)

    for cluster in clusters:
        cluster["examples"] = [s for s in cluster["examples"] if s not in dead_subdomains]
        cluster["size"] = len(cluster["examples"])
    # Add a cluster for dead / invalid subdomains
    clusters.append({
        "cluster_id": "dead",
        "size": len(dead_subdomains),
        "examples": dead_subdomains[:5]
    })

    elapsed = time.time() - start_time

    # Create raw docs for MongoDB storage
    raw_docs = []
    for sub in subdomains:
        sub_ip = resolved.get(sub)
        # Get ports for this subdomain (ports are scanned per IP, stored per subdomain)
        sub_ports = ports_results.get(sub, [])
        
        doc = {
            "subdomain": sub,
            "is_root": (sub == domain),
            "open_ports": sub_ports,  # Ports scanned from this subdomain's IP
            "ip": sub_ip if sub_ip else "Unresolved",
            "live_http": sub in live_http,
            "cluster_id": None,  # Will be set based on clustering
            "status": "dead" if sub in dead_subdomains else "alive",
        }
        raw_docs.append(doc)

    # Assign cluster IDs to raw docs
    for cluster in clusters:
        for example in cluster["examples"]:
            for doc in raw_docs:
                if doc["subdomain"] == example:
                    doc["cluster_id"] = cluster["cluster_id"]

    result = {
        "total_candidates": len(subdomains),
        "resolved": len(resolved),
        "live_http": len(live_http),
        "elapsed_seconds": elapsed,
        "clusters": clusters,
        "examples": subdomains[:10],  # Show first 10 examples
        "raw_docs": raw_docs,  # For MongoDB storage
        "ports_summary": ports_results
    }

    return result
