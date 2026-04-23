import os
import subprocess
import json
import logging
import socket
import time
from typing import List, Dict, Any

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
        
        logging.info(f"Model 1 found {len(subdomains)} unique subdomains.")
        return list(subdomains)


class Model2_PortScanning:
    """
    Model 2: High-Speed Port Scanning
    Uses rustscan and masscan to find open ports.
    """
    def __init__(self):
        self.rustscan_path = os.path.abspath('rustscan.exe')
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

            # Run RustScan if it exists
            if os.path.exists(self.rustscan_path) and os.access(self.rustscan_path, os.X_OK):
                try:
                    # RustScan: rustscan.exe -a {target} -r 1-65535 -g (for grepable/easy parsing)
                    logging.info(f"Running RustScan on {scan_target}")
                    result = subprocess.run(
                        [self.rustscan_path, '-a', scan_target, '-r', '1-65535', '-g'],
                        capture_output=True, text=True
                    )
                    
                    # Output might look like: Open 127.0.0.1:80 or json if supported
                    # We do simple parsing
                    if result.stdout:
                        for line in result.stdout.split('\n'):
                            if '->' in line and '[' in line:
                                # Typical rustscan grepable output parsing
                                parts = line.split('[')
                                if len(parts) > 1:
                                    port_str = parts[1].replace(']', '')
                                    for p in port_str.split(','):
                                        if p.strip().isdigit():
                                            ports.add(int(p.strip()))
                            elif "Open" in line:
                                # parse "Open 127.0.0.1:80"
                                parts = line.split(':')
                                if len(parts) > 1 and parts[-1].strip().isdigit():
                                    ports.add(int(parts[-1].strip()))
                except Exception as e:
                    logging.error(f"RustScan failed on {scan_target}: {e}")
            else:
                logging.warning(f"RustScan not found or not executable at {self.rustscan_path}. Skipping.")

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
                        with open('masscan.json', 'r') as f:
                            try:
                                data = json.load(f)
                                for entry in data:
                                    if 'ports' in entry:
                                        for pinfo in entry['ports']:
                                            if 'port' in pinfo:
                                                ports.add(int(pinfo['port']))
                            except json.JSONDecodeError:
                                pass
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

        # katana
        try:
            logging.info("Executing katana...")
            result = subprocess.run(
                [self.katana_path, '-list', 'urls.txt', '-jsonl', '-silent'],
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

        # nuclei
        try:
            logging.info("Executing nuclei...")
            result = subprocess.run(
                [self.nuclei_path, '-l', 'urls.txt', '-json-export', 'nuclei_out.json', '-silent'],
                capture_output=True, text=True
            )
            if os.path.exists('nuclei_out.json'):
                with open('nuclei_out.json', 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                results["vulnerabilities"].append(json.loads(line))
                            except:
                                pass
        except Exception as e:
            logging.error(f"nuclei failed: {e}")

        return results


import numpy as np
try:
    from tensorflow.keras.models import Sequential, Model
    from tensorflow.keras.layers import LSTM, Dense, Input
except ImportError:
    pass # Will be handled if missing at runtime

class Model4_AnomalyDetection:
    """
    Model 4: Anomaly Detection
    Analyzes HTTP traffic logs captured by Katana/httpx.
    """
    def __init__(self):
        self.model = None

    def build_model(self, input_dim: int):
        # Autoencoder using LSTM
        inputs = Input(shape=(1, input_dim))
        encoded = LSTM(16, activation='relu', return_sequences=False)(inputs)
        decoded = Dense(input_dim, activation='sigmoid')(encoded)
        self.model = Model(inputs, decoded)
        self.model.compile(optimizer='adam', loss='mse')

    def run(self, fingerprint_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        logging.info("Running Model 4 (Anomaly Detection)")
        
        features = []
        logs = fingerprint_data.get("endpoints", [])
        
        # Extract features from live traffic endpoints
        for log in logs:
            status = log.get("response", {}).get("status_code", 200)
            length = log.get("response", {}).get("content_length", 0)
            features.append([status, length])
            
        # FIX 4: If no live traffic data (endpoints) is available, use historical header data from tech_stack
        if not features:
            logging.info("No live endpoints captured. Falling back to historical HTTP header data (tech_stack) for anomaly ingestion.")
            fallback_logs = fingerprint_data.get("tech_stack", [])
            for tech in fallback_logs:
                # Httpx tech stack data contains 'status_code' and sometimes 'content_length'
                status = tech.get("status_code", 200)
                length = tech.get("content_length", 0)
                features.append([status, length])
                # Wrap it to mimic endpoint structure for downstream processing
                logs.append(tech)

        if not features:
            logging.info("No logs or tech stack data for anomaly detection.")
            return []
            
        data = np.array(features, dtype=np.float32)
        # Normalize
        data = data / np.max(data, axis=0) if np.max(data) > 0 else data
        data = data.reshape((data.shape[0], 1, data.shape[1]))
        
        if self.model is None:
            self.build_model(input_dim=2)
            # Dummy train on itself
            self.model.fit(data, data.reshape(data.shape[0], 2), epochs=5, verbose=0)
            
        predictions = self.model.predict(data)
        mse = np.mean(np.power(data.reshape(data.shape[0], 2) - predictions, 2), axis=1)
        
        threshold = np.percentile(mse, 95) # Top 5% are anomalies
        
        anomalies = []
        for i, loss in enumerate(mse):
            if loss > threshold:
                logs[i]["anomaly_score"] = float(loss)
                anomalies.append(logs[i])
                
        logging.info(f"Detected {len(anomalies)} anomalies.")
        return anomalies

import networkx as nx
from neo4j import GraphDatabase

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
        
        # Build local NetworkX graph
        self.graph.add_node("Internet", type="external")
        self.graph.add_node(target, type="domain")
        self.graph.add_edge("Internet", target, weight=1)
        
        for sub in subdomains:
            self.graph.add_node(sub, type="subdomain")
            self.graph.add_edge(target, sub, weight=1)
            
            # Link open ports
            if sub in ports:
                for p in ports[sub]:
                    port_node = f"{sub}:{p}"
                    self.graph.add_node(port_node, type="port", number=p)
                    self.graph.add_edge(sub, port_node, weight=1, label="Service Edge")

        # Add vulnerabilities as paths or weights
        for vuln in vulnerabilities:
            host = vuln.get("host", "")
            if host:
                # Lower weight = easier to exploit (Path of least resistance)
                severity = vuln.get("info", {}).get("severity", "low")
                weight = 1 if severity == "critical" else 2 if severity == "high" else 5
                
                vuln_node = f"Vuln_{vuln.get('template-id')}_{host}"
                self.graph.add_node(vuln_node, type="vulnerability")
                
                # Enhanced Graph Mapping: Link critical/high severity vulns as "Active Entry Point"
                if severity in ["critical", "high"]:
                    self.graph.add_edge(host, vuln_node, weight=weight, label="Active Entry Point")
                else:
                    self.graph.add_edge(host, vuln_node, weight=weight)
                
                # Assume vuln leads to internal asset
                internal_asset = "Internal_Asset_X"
                self.graph.add_node(internal_asset, type="internal")
                self.graph.add_edge(vuln_node, internal_asset, weight=1)

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
        
    def run_all(self, target: str):
        logging.info(f"--- Starting ReconPipeline for {target} ---")
        
        subdomains = self.m1.run(target)
        ports = self.m2.run(subdomains)
        fingerprints_and_vulns = self.m3.run(ports)
        anomalies = self.m4.run(fingerprints_and_vulns)
        attack_paths = self.m5.run(target, subdomains, ports, fingerprints_and_vulns.get("vulnerabilities", []))
        
        # Prepare data for Model 6
        # Model 6 expects a list of dictionaries with features like cvss_score, subdomain_count, etc.
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
            
            record = {
                "domain": target,
                "subdomain": v.get("host", target),
                "cve_id": v.get("template-id", "N/A"),
                "service_name": "HTTP", # Simplified
                "port_number": 80, # Simplified
                "cvss_score": v.get("info", {}).get("classification", {}).get("cvss-score", cvss),
                "exploit_available": 1 if "exploit" in str(v).lower() else 0,
                "subdomain_count": len(subdomains),
                "exposed_service_count": sum(len(p) for p in ports.values()),
                "is_public_port": 1,
                "anomaly_flag": 1 if any(a.get('host') == v.get('host') for a in anomalies) else 0,
                "traffic_anomaly_score": 0.5,
                "misconfiguration_flag": 0
            }
            m6_records.append(record)

        logging.info("Pipeline Models 1-5 Complete.")
        
        # Return context that can be fed to Model 6 and 7
        return {
            "target": target,
            "subdomains": subdomains,
            "open_ports": ports,
            "fingerprints_and_vulns": fingerprints_and_vulns,
            "anomalies": anomalies,
            "attack_paths": attack_paths,
            "m6_ready_records": m6_records
        }

if __name__ == "__main__":
    pipeline = ReconPipeline()
    # pipeline.run_all("example.com") # Uncomment to test natively
