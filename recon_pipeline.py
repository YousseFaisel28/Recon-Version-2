import os
import subprocess
import json
import logging
import socket
import time
import urllib.request
import urllib.error
import concurrent.futures
import uuid
from datetime import datetime
from typing import List, Dict, Any
from recon_ml_enhancements import (
    run_subdomain_clustering,
    ServiceClassifier,
    MLHeuristicFilter,
    LSTMAnomalyDetector,
    MLRiskScorer
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Model1_Discovery:
    """
    Model 1: Discovery
    Uses subfinder and amass to find subdomains.
    """
    def __init__(self):
        self.subfinder_path = os.path.expanduser('~\\go\\bin\\subfinder.exe')
        self.amass_path = os.path.expanduser('~\\go\\bin\\amass.exe')

    def run(self, target: str) -> List[str]:
        logging.info(f"Running Model 1 (Discovery) on {target}")
        subdomains = set()

        # Run Subfinder
        try:
            logging.info("Executing Subfinder...")
            result = subprocess.run(
                [self.subfinder_path, '-d', target, '-json', '-silent'],
                capture_output=True, text=True, check=True
            )
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        if 'host' in data:
                            subdomains.add(data['host'])
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            logging.error(f"Subfinder failed: {e}")

        # Run Amass
        try:
            logging.info("Executing Amass...")
            # Amass json output
            result = subprocess.run(
                [self.amass_path, 'enum', '-d', target, '-json', 'amass_out.json'],
                capture_output=True, text=True
            )
            if os.path.exists('amass_out.json'):
                with open('amass_out.json', 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                data = json.loads(line)
                                if 'name' in data:
                                    subdomains.add(data['name'])
                            except json.JSONDecodeError:
                                pass
        except Exception as e:
            logging.error(f"Amass failed: {e}")

        # Adding the root domain itself just in case
        subdomains.add(target)
        
        sub_list = list(subdomains)
        logging.info(f"Model 1 found {len(sub_list)} unique subdomains.")
        
        # ML Integration: Clustering & Anomaly Detection
        cluster_results = run_subdomain_clustering(sub_list)
        anomalies = cluster_results.get("anomalies", [])
        if anomalies:
            logging.warning(f"ML Model 1 flagged {len(anomalies)} anomalous subdomains (outliers): {anomalies}")
            
        return sub_list


class Model2_PortScanning:
    """
    Model 2: High-Speed Port Scanning
    Uses masscan exclusively to find open ports (RustScan removed to eliminate redundancy).
    """
    def __init__(self):
        self.masscan_path = os.path.abspath('masscan.exe')

    def run(self, targets: List[str]) -> Dict[str, List[int]]:
        logging.info(f"Running Model 2 (Port Scanning) on {len(targets)} targets")
        open_ports = {}

        for target in targets:
            ports = set()
            scan_target = target
            
            # DNS Resolution Fallback
            try:
                scan_target = socket.gethostbyname(target)
                logging.info(f"Resolved {target} to {scan_target}")
            except socket.gaierror:
                logging.warning(f"Could not resolve IP for {target}, using hostname directly.")

            # Run Masscan if it exists
            if os.path.exists(self.masscan_path) and os.access(self.masscan_path, os.X_OK):
                try:
                    # Masscan: masscan.exe {target} -p1-65535 --rate 1000 -oJ masscan.json
                    logging.info(f"Running Masscan on {scan_target} (Requires Admin)")
                    # Added shell=True for raw socket requirements on Windows
                    subprocess.run(
                        f"{self.masscan_path} {scan_target} -p1-65535 --rate 1000 -oJ masscan.json",
                        capture_output=True, text=True, shell=True
                    )
                    if os.path.exists('masscan.json'):
                        try:
                            with open('masscan.json', 'r') as f:
                                data = json.load(f)
                            for entry in data:
                                if 'ports' in entry:
                                    for pinfo in entry['ports']:
                                        port_val = pinfo.get('port')
                                        if port_val and str(port_val).isdigit():
                                            ports.add(int(port_val))
                        except (json.JSONDecodeError, OSError) as e:
                            logging.error(f"Failed to read/parse masscan.json: {e}")
                except Exception as e:
                    logging.error(f"Masscan failed on {scan_target}: {e}")
            else:
                logging.warning(f"Masscan not found or not executable at {self.masscan_path}. Skipping.")

            if ports:
                open_ports[target] = list(ports)
                
        return open_ports


class Model3_FingerprintingAndVulns:
    """
    Model 3: Fingerprinting & Vulns
    Uses httpx, katana, and nuclei.
    """
    def __init__(self):
        self.httpx_path = os.path.expanduser('~\\go\\bin\\httpx.exe')
        self.katana_path = os.path.expanduser('~\\go\\bin\\katana.exe')
        self.nuclei_path = os.path.expanduser('~\\go\\bin\\nuclei.exe')
        self.ffuf_path = os.path.expanduser('~\\go\\bin\\ffuf.exe')
        self.ml_filter = MLHeuristicFilter()

    def heuristic_confidence_scorer(self, vulns: List[Dict]) -> List[Dict]:
        """
        ML Integration: Uses Decision Tree to filter out false positives.
        """
        filtered = []
        for v in vulns:
            prediction = self.ml_filter.predict_validity(v)
            if prediction == 1:
                v["heuristic_confidence_score"] = 1.0
                filtered.append(v)
            else:
                logging.info(f"ML Filtered False Positive: {v.get('template-id')}")
                
        return filtered

    def run(self, scanned_targets: Dict[str, List[int]]) -> Dict[str, Any]:
        logging.info("Running Model 3 (Fingerprinting & Vulns)")
        results = {
            "tech_stack": [],
            "endpoints": [],
            "vulnerabilities": []
        }
        
        # Build URLs
        urls = []
        for target, ports in scanned_targets.items():
            for port in ports:
                if port == 80:
                    urls.append(f"http://{target}")
                elif port == 443:
                    urls.append(f"https://{target}")
                else:
                    urls.append(f"http://{target}:{port}")
                    urls.append(f"https://{target}:{port}")

        if not urls:
            logging.info("No URLs to scan.")
            return results

        # Write URLs to a file for tools
        with open("urls.txt", "w") as f:
            for url in urls:
                f.write(url + "\n")

        # httpx
        try:
            logging.info("Executing httpx...")
            result = subprocess.run(
                [self.httpx_path, '-l', 'urls.txt', '-json', '-silent', '-tech-detect'],
                capture_output=True, text=True
            )
            
            # Implementation of httpx retry mechanism
            if not result.stdout.strip():
                logging.warning("No httpx output received. Retrying with a slower rate limit to bypass potential firewalls...")
                time.sleep(2)
                result = subprocess.run(
                    [self.httpx_path, '-l', 'urls.txt', '-json', '-silent', '-tech-detect', '-rl', '50'],
                    capture_output=True, text=True
                )

            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        results["tech_stack"].append(json.loads(line))
                    except:
                        pass
        except Exception as e:
            logging.error(f"httpx failed: {e}")

        # katana (With JS Analysis)
        try:
            logging.info("Executing katana (with JS extraction)...")
            result = subprocess.run(
                [self.katana_path, '-list', 'urls.txt', '-jc', '-jsline', '-em', 'js,json', '-jsonl', '-silent'],
                capture_output=True, text=True
            )
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        results["endpoints"].append(json.loads(line))
                    except:
                        pass
        except Exception as e:
            logging.error(f"katana failed: {e}")

        # ffuf (Directory Brute Forcing)
        if os.path.exists(self.ffuf_path):
            try:
                logging.info("Executing ffuf for directory brute-forcing...")
                # Assuming standard wordlist location; if not present, ffuf will quickly exit.
                wordlist = "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt"
                if os.path.exists(wordlist):
                    for url in urls[:3]: # Limit to top 3 for speed in pipeline
                        subprocess.run(
                            [self.ffuf_path, '-w', wordlist, '-u', f'{url}/FUZZ', '-mc', '200,301', '-o', 'ffuf_out.json', '-of', 'json', '-silent'],
                            capture_output=True, text=True
                        )
                        if os.path.exists('ffuf_out.json'):
                            with open('ffuf_out.json', 'r') as f:
                                try:
                                    data = json.load(f)
                                    for entry in data.get('results', []):
                                        results["endpoints"].append({"url": entry.get("url"), "status": entry.get("status")})
                                except:
                                    pass
                else:
                    logging.info("ffuf skipped: Wordlist not found.")
            except Exception as e:
                logging.error(f"ffuf failed: {e}")

        # nuclei
        try:
            logging.info("Executing nuclei...")
            result = subprocess.run(
                [self.nuclei_path, '-l', 'urls.txt', '-json-export', 'nuclei_out.json', '-silent'],
                capture_output=True, text=True
            )
            if os.path.exists('nuclei_out.json'):
                unique_vulns = {}
                with open('nuclei_out.json', 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                v = json.loads(line)
                                # Deduplication using stable composite key
                                cve = v.get("template-id", "unknown")
                                host = v.get("host", "unknown")
                                port = str(v.get("port", "80"))
                                path = v.get("matched-at", "unknown")
                                key = f"{cve}::{host}::{port}::{path}"
                                if key not in unique_vulns:
                                    unique_vulns[key] = v
                            except Exception:
                                pass
                results["vulnerabilities"] = list(unique_vulns.values())
                
                # Apply Phase 2 Heuristic Filtering
                results["vulnerabilities"] = self.heuristic_confidence_scorer(results["vulnerabilities"])
                
        except Exception as e:
            logging.error(f"nuclei failed: {e}")

        return results


class Model4_AnomalyDetection:
    """
    Model 4: Anomaly Detection
    Analyzes HTTP traffic logs captured by Katana/httpx.
    """
    def __init__(self):
        self.lstm = LSTMAnomalyDetector()

    def run(self, fingerprint_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        logging.info("Running Model 4 (Anomaly Detection)")
        
        features = []
        logs = fingerprint_data.get("endpoints", [])
        
        # Extract features from live traffic endpoints
        for log in logs:
            status = log.get("response", {}).get("status_code", 200)
            length = log.get("response", {}).get("content_length", 0)
            features.append((status, length))
            
        if not features:
            logging.info("No live endpoints captured. Falling back to historical HTTP header data (tech_stack) for anomaly ingestion.")
            fallback_logs = fingerprint_data.get("tech_stack", [])
            for tech in fallback_logs:
                status = tech.get("status_code", 200)
                length = tech.get("content_length", 0)
                features.append((status, length))
                logs.append(tech)

        if not features:
            logging.info("No logs or tech stack data for anomaly detection.")
            return []
            
        # ML Integration: LSTM Fit & Predict
        anomaly_flags = self.lstm.fit_predict(features)
        
        anomalies = []
        for i, is_anomaly in enumerate(anomaly_flags):
            if is_anomaly == 1:
                logs[i]["anomaly_score"] = 1.0 # Flagged
                anomalies.append(logs[i])
                
        logging.info(f"Detected {len(anomalies)} anomalies.")
        return anomalies

import networkx as nx
from neo4j import GraphDatabase

EPSS_CACHE_FILE = "epss_cache.json"

def _load_epss_cache() -> Dict[str, float]:
    """Safely loads the EPSS cache."""
    if not os.path.exists(EPSS_CACHE_FILE): return {}
    try:
        with open(EPSS_CACHE_FILE, 'r') as f: return json.load(f)
    except Exception: return {}

def _save_epss_cache(cache_data: Dict[str, float]) -> None:
    """Safely saves the EPSS cache using a temporary file."""
    tmp_file = f"{EPSS_CACHE_FILE}.tmp"
    try:
        with open(tmp_file, 'w') as f: json.dump(cache_data, f)
        os.replace(tmp_file, EPSS_CACHE_FILE)
    except Exception as e:
        logging.error(f"Failed to save EPSS cache: {e}")

def fetch_epss_score_reliable(cve_id: str, cvss_fallback: float = 0.0, max_retries: int = 3) -> float:
    """Fetches EPSS score with exponential backoff and safe caching."""
    if not cve_id or not cve_id.upper().startswith("CVE-"):
        return cvss_fallback / 10.0
        
    cache = _load_epss_cache()
    if cve_id in cache: return cache[cve_id]
    
    url = f"https://api.first.org/epss/api/v1/cve/{cve_id}"
    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'ReconX-Pipeline/1.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                if data.get("data") and len(data["data"]) > 0:
                    score = float(data["data"][0].get("epss", 0.0))
                    cache[cve_id] = score
                    _save_epss_cache(cache)
                    return score
                break
        except urllib.error.URLError as e:
            logging.warning(f"EPSS API error for {cve_id} (Attempt {attempt+1}/{max_retries}): {e}")
            time.sleep(2 ** attempt)
        except Exception:
            break
            
    return cvss_fallback / 10.0

class Model5_ExploitationStrategy:
    """
    Model 5: Exploitation Strategy
    Maps the network as a graph. Uses Dijkstra’s.
    """
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="password"):
        self.uri = uri
        self.user = user
        self.password = password
        self.graph = nx.DiGraph()

    def run(self, target: str, subdomains: List[str], ports: Dict[str, List[int]], vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        logging.info("Running Model 5 (Exploitation Strategy)")
        
        # Explicit Node Types
        NODE_INTERNET = "internet"
        NODE_DOMAIN = "domain"
        NODE_VULN = "vulnerability"
        NODE_INTERNAL = "internal_asset"
        
        # Build local NetworkX graph safely
        self.graph.add_node("Internet", type=NODE_INTERNET, category="entry_point")
        self.graph.add_node(target, type=NODE_DOMAIN, category="target")
        if not self.graph.has_edge("Internet", target):
            self.graph.add_edge("Internet", target, weight=1.0)
        
        for sub in subdomains:
            self.graph.add_node(sub, type="subdomain")
            self.graph.add_edge(target, sub, weight=1)
            
            # Link open ports
            if sub in ports:
                for p in ports[sub]:
                    port_node = f"{sub}:{p}"
                    self.graph.add_node(port_node, type="port", number=p)
                    self.graph.add_edge(sub, port_node, weight=1, label="Service Edge")

        # Fetch EPSS scores concurrently to avoid network bottleneck
        cve_ids_with_cvss = []
        for vuln in vulnerabilities:
            if "template-id" in vuln:
                cve_id = vuln.get("template-id")
                severity = vuln.get("info", {}).get("severity", "info")
                cvss_fallback = 0.0
                if severity == "critical": cvss_fallback = 9.5
                elif severity == "high": cvss_fallback = 7.5
                elif severity == "medium": cvss_fallback = 5.0
                elif severity == "low": cvss_fallback = 2.5
                cve_ids_with_cvss.append((cve_id, cvss_fallback))
                
        epss_results = {}
        if cve_ids_with_cvss:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_to_cve = {executor.submit(fetch_epss_score_reliable, cve, fallback): cve for cve, fallback in cve_ids_with_cvss}
                for future in concurrent.futures.as_completed(future_to_cve):
                    cve = future_to_cve[future]
                    try:
                        epss_results[cve] = future.result()
                    except Exception:
                        epss_results[cve] = 0.0

        # Add vulnerabilities as paths or weights
        for vuln in vulnerabilities:
            host = vuln.get("host", "")
            if host:
                cve_id = vuln.get("template-id", "")
                
                # Fetch Real EPSS Score from cached concurrent results
                epss_prob = epss_results.get(cve_id, 0.0)
                vuln["epss_score"] = epss_prob # Save for later aggregation
                
                # Weight based on real EPSS threat intelligence (High probability = Low weight/Easy Path)
                weight = max(1.0, 10.0 - (epss_prob * 10.0))
                
                vuln_node = f"Vuln_{cve_id}_{host}"
                
                # Assign Contextual Node Category
                service_name = vuln.get("info", {}).get("name", "Unknown Service").lower()
                category = "web_service"
                if "sql" in service_name: category = "database"
                elif "ssh" in service_name: category = "remote_admin"
                
                if not self.graph.has_node(vuln_node):
                    self.graph.add_node(vuln_node, type=NODE_VULN, category=category)
                
                # Contextual Edge Definition
                edge_label = "Exploitable_Service"
                if epss_prob > 0.5:
                    edge_label = "High_Probability_Exploit_Path"
                
                if not self.graph.has_edge(host, vuln_node):
                    self.graph.add_edge(host, vuln_node, weight=weight, label=edge_label)
                
                # Assume vuln leads to internal asset
                internal_asset = "Internal_Asset_X"
                if not self.graph.has_node(internal_asset):
                    self.graph.add_node(internal_asset, type=NODE_INTERNAL)
                if not self.graph.has_edge(vuln_node, internal_asset):
                    self.graph.add_edge(vuln_node, internal_asset, weight=1.0)

        # Find shortest path using Dijkstra
        paths = {}
        if "Internal_Asset_X" in self.graph.nodes:
            try:
                shortest_path = nx.dijkstra_path(self.graph, "Internet", "Internal_Asset_X")
                paths["path_of_least_resistance"] = shortest_path
            except nx.NetworkXNoPath:
                pass

        # Sync to Neo4j
        try:
            driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            with driver.session() as session:
                # Simplified Neo4j sync
                session.run("MATCH (n) DETACH DELETE n") # Clear db
                for node, attrs in self.graph.nodes(data=True):
                    session.run("CREATE (n:Node {id: $id, type: $type})", id=str(node), type=attrs.get('type', 'unknown'))
                for u, v, attrs in self.graph.edges(data=True):
                    session.run("MATCH (a:Node {id: $u}), (b:Node {id: $v}) CREATE (a)-[r:LINK {weight: $w}]->(b)", u=str(u), v=str(v), w=attrs.get('weight', 1))
            driver.close()
        except Exception as e:
            logging.error(f"Neo4j connection failed: {e}")

        return paths


class ReconPipeline:
    def __init__(self):
        self.m1 = Model1_Discovery()
        self.m2 = Model2_PortScanning()
        self.m3 = Model3_FingerprintingAndVulns()
        self.m4 = Model4_AnomalyDetection()
        self.m5 = Model5_ExploitationStrategy()
        self.ml_svc_classifier = ServiceClassifier()
        self.ml_risk_scorer = MLRiskScorer()
        
    def generate_actionable_report(self, m6_records: List[Dict], resolved: List[Dict], attack_paths: Dict) -> Dict:
            """
            Phase 4: Elevating System Value
            Generates a Nessus-style actionable report mapping to MITRE ATT&CK.
            """
            report = {
                "Executive_Summary": {
                    "Total_Vulnerabilities": len(m6_records),
                    "New_Findings": sum(1 for r in m6_records if r.get("delta_status") == "[NEW]"),
                    "Resolved_Findings": len(resolved),
                    "Average_EPSS_Risk_Score": round(sum(r.get("epss_risk_score", 0) for r in m6_records) / max(1, len(m6_records)), 4)
                },
                "Vulnerabilities": [],
                "Attack_Paths": attack_paths
            }
            
            for rec in m6_records:
                # Simulate MITRE mapping based on common CVE types
                mitre_id = "T1190" # Exploit Public-Facing Application (Default)
                if "sql" in rec.get("cve_id", "").lower(): mitre_id = "T1190"
                elif "xss" in rec.get("cve_id", "").lower(): mitre_id = "T1059"
                
                report["Vulnerabilities"].append({
                    "Target": rec["subdomain"],
                    "CVE": rec["cve_id"],
                    "EPSS_Risk_Score": rec.get("epss_risk_score", 0),
                    "Delta_Status": rec.get("delta_status", "[EXISTING]"),
                    "MITRE_ATT&CK": f"{mitre_id}",
                    "Actionable_Remediation": f"Review {mitre_id} mitigation strategies. Isolate port {rec['port_number']} and apply vendor patches for {rec['cve_id']}."
                })
            return report

    def run_all(self, target: str):
        logging.info(f"--- Starting ReconPipeline for {target} ---")
        
        subdomains = self.m1.run(target)
        ports = self.m2.run(subdomains)
        fingerprints_and_vulns = self.m3.run(ports)
        anomalies = self.m4.run(fingerprints_and_vulns)
        attack_paths = self.m5.run(target, subdomains, ports, fingerprints_and_vulns.get("vulnerabilities", []))
        
        # Prepare data for Model 6 (With EPSS Risk Scoring)
        m6_records = []
        vulns = fingerprints_and_vulns.get("vulnerabilities", [])
        for v in vulns:
            # Map Nuclei severity to CVSS approximation if missing
            severity = v.get("info", {}).get("severity", "info")
            cvss = 0.0
            if severity == "critical": cvss = 9.5
            elif severity == "high": cvss = 7.5
            elif severity == "medium": cvss = 5.0
            elif severity == "low": cvss = 2.5
            
            exploit_available = 1 if "exploit" in str(v).lower() else 0
            port_number = 80 # Simplified fallback
            
            # Use the real EPSS score fetched during the graph generation, default to 0.0
            epss_prob = v.get("epss_score", 0.0)
            
            # ML Integration: Linear Regression for Risk Scoring
            real_risk_score = self.ml_risk_scorer.predict_risk(cvss, epss_prob, exploit_available)
            
            # ML Integration: Random Forest for Service Classification
            predicted_service = self.ml_svc_classifier.predict_service(port_number, "HTTP")
            
            record = {
                "domain": target,
                "subdomain": v.get("host", target),
                "cve_id": v.get("template-id", "N/A"),
                "service_name": predicted_service,
                "port_number": port_number,
                "cvss_score": v.get("info", {}).get("classification", {}).get("cvss-score", cvss),
                "epss_risk_score": real_risk_score, # Mathematically sound risk score
                "exploit_available": exploit_available,
                "subdomain_count": len(subdomains),
                "exposed_service_count": sum(len(p) for p in ports.values()),
                "is_public_port": 1,
                "anomaly_flag": 1 if any(a.get('host') == v.get('host') for a in anomalies) else 0,
                "traffic_anomaly_score": 0.5,
                "misconfiguration_flag": 0
            }
            m6_records.append(record)

        # Phase 4: State Tracking (Delta Scans with Auditability & Robustness)
        history_file = "scan_history.json"
        resolve_threshold = 2
        
        previous_state = {}
        if os.path.exists(history_file):
            try:
                with open(history_file, 'r') as f:
                    previous_state = json.load(f)
            except Exception as e:
                logging.error(f"Failed to read scan history cleanly: {e}")
                
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"
        current_time = datetime.now().isoformat()
                
        current_state = {}
        current_keys = set()
        
        for rec in m6_records:
            key = f"{rec['cve_id']}_{rec['subdomain']}"
            current_keys.add(key)
            
            if key not in previous_state:
                rec["delta_status"] = "[NEW]"
                rec["first_seen"] = current_time
                rec["absent_count"] = 0
            else:
                rec["delta_status"] = "[EXISTING]"
                rec["first_seen"] = previous_state[key].get("first_seen", current_time)
                rec["absent_count"] = 0
                
            rec["last_seen"] = current_time
            rec["scan_id"] = scan_id
            current_state[key] = rec
        
        resolved_records = []
        for key, old_rec in previous_state.items():
            if key not in current_keys:
                absent_count = old_rec.get("absent_count", 0) + 1
                old_rec["absent_count"] = absent_count
                
                if absent_count >= resolve_threshold:
                    old_rec["delta_status"] = "[RESOLVED]"
                    old_rec["last_seen"] = current_time
                    resolved_records.append(old_rec)
                else:
                    old_rec["delta_status"] = "[MISSING_PENDING_VERIFICATION]"
                    current_state[key] = old_rec
                
        # Save new state safely
        tmp_file = f"{history_file}.tmp"
        try:
            with open(tmp_file, 'w') as f:
                json.dump(current_state, f, indent=4)
            os.replace(tmp_file, history_file)
        except Exception as e:
            logging.error(f"Failed to save robust scan history: {e}")

        # Phase 4: Generate Actionable Report
        actionable_report = self.generate_actionable_report(m6_records, resolved_records, attack_paths)
        
        logging.info("Pipeline Models 1-5 Complete.")
        
        # Return context that can be fed to Model 6 and 7
        return {
            "target": target,
            "subdomains": subdomains,
            "open_ports": ports,
            "fingerprints_and_vulns": fingerprints_and_vulns,
            "anomalies": anomalies,
            "attack_paths": attack_paths,
            "m6_ready_records": m6_records,
            "actionable_report": actionable_report,
            "resolved_findings": resolved_records
        }

if __name__ == "__main__":
    pipeline = ReconPipeline()
    # pipeline.run_all("example.com") # Uncomment to test natively
