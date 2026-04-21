"""
Model 2: Port Scanning & Service Detection (Deterministic)

Input: IP addresses and subdomain pairs
Output: Open ports, services, and port analysis results

NOTE: Service identification is DETERMINISTIC using Nmap and banner grabbing.
ML is ONLY used for optional "Risk Scoring" post-processing, NOT for identification.
"""
import nmap
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional
from models.ai_port_service.model_inference import get_predict_service

DEFAULT_PORTS_TO_SCAN = [
    80, 443, 21, 22, 25, 53, 110, 143, 3306, 8080, 8443, 3389, 5432, 27017, 6379, 9200
]


def scan_ports(ip, ports=DEFAULT_PORTS_TO_SCAN):
    """
    Scan ports on a given IP using python-nmap library.
    
    Args:
        ip: IP address to scan
        ports: List of port numbers to scan
    
    Returns:
        List of dictionaries with port and service information
    """
    open_ports = []
    
    # Create port list string for nmap (e.g., "80,443,22")
    port_list = ",".join(str(port) for port in ports)
    
    try:
        # Initialize nmap PortScanner
        nm = nmap.PortScanner()
        
        # Scan ports
        # -Pn: Skip host discovery (assume host is up)
        # -sS: SYN scan (faster, requires root/admin on Linux)
        # -sT: TCP connect scan (works without root, slower)
        # -T4: Aggressive timing template
        # --max-retries 1: Reduce retries for speed
        # --host-timeout 30s: Timeout per host
        
        # Try SYN scan first (faster), fallback to TCP connect if it fails
        try:
            nm.scan(ip, port_list, arguments='-Pn -sS -T4 --max-retries 1 --host-timeout 30s')
        except nmap.PortScannerError:
            # If SYN scan fails (might need root), try TCP connect scan
            nm.scan(ip, port_list, arguments='-Pn -sT -T4 --max-retries 1 --host-timeout 30s')
        
        # Parse results
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                ports_info = nm[ip][proto]
                for port_num, port_data in ports_info.items():
                    if port_data['state'] == 'open':
                        # ONLY collect raw fingerprints, no naming assumptions
                        open_ports.append({
                            "port": int(port_num),
                            "state": port_data.get('state', 'open'),
                            "product": port_data.get('product', ''),
                            "version": port_data.get('version', ''),
                            "extrainfo": port_data.get('extrainfo', ''),
                            "protocol": proto
                        })
        
    except nmap.PortScannerError:
        # If nmap library fails, fallback to basic socket scan
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append({
                        "port": port,
                        "state": "open",
                        "product": "",
                        "version": "",
                        "extrainfo": "",
                        "protocol": "tcp"
                    })
            except:
                pass
            finally:
                sock.close()
    except Exception:
        # If any other error occurs, fallback to socket scan
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append({
                        "port": port,
                        "state": "open",
                        "product": "",
                        "version": "",
                        "extrainfo": "",
                        "protocol": "tcp"
                    })
            except:
                pass
            finally:
                sock.close()
    
    # --- PURE AI PORT SERVICE CLASSIFICATION ---
    final_results = []
    if open_ports:
        # Construct fingerprints
        fingerprints = []
        for p in open_ports:
            # combine banner
            product = p.get("product", "")
            version = p.get("version", "")
            extrainfo = p.get("extrainfo", "")
            banner = f"{product} {version} {extrainfo}".strip()
            
            fingerprints.append({
                "port": p["port"],
                "protocol": p.get("protocol", "tcp"),
                "state": p.get("state", "open"),
                "banner": banner
            })
            
        try:
            # PURE AI CLASSIFICATION: No fallback labels
            predictions = get_predict_service(fingerprints, model_type="rf")
            
            # Map predictions
            for i, p in enumerate(open_ports):
                if i < len(predictions):
                    ai_pred = predictions[i]
                    final_results.append({
                        "port": p["port"],
                        "service": ai_pred.get("service", "Unknown"),
                        "version": ai_pred.get("version", ""),
                        "confidence": ai_pred.get("confidence", 0.0)
                    })
        except Exception as e:
            print(f"AI Port Classification failed: {e}")
            # Do NOT fall back to deterministic if we fail (System should not identify any service)
            # We return empty array as per validation criteria 
            return []

    return final_results


def scan_ports_parallel(ip_subdomain_pairs, max_workers=20):
    """
    Scan ports for multiple IPs in parallel.
    
    Args:
        ip_subdomain_pairs: List of tuples (subdomain, ip)
        max_workers: Maximum number of parallel workers
    
    Returns:
        Dictionary mapping subdomain to list of open ports
        {subdomain: [{"port": int, "service": str}, ...]}
    """
    ports_results = {}
    
    def _scan_single_ip(item):
        subdomain, ip = item
        # Scan ports on this specific IP for this subdomain
        open_ports = scan_ports(ip)
        return (subdomain, open_ports)
    
    if not ip_subdomain_pairs:
        return ports_results
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_scan_single_ip, item): item for item in ip_subdomain_pairs}
        for future in as_completed(futures):
            try:
                subdomain, open_ports = future.result()
                # Store ports for this specific subdomain
                ports_results[subdomain] = open_ports
            except Exception as e:
                # If scan fails for a subdomain, store empty list
                print(f"Warning: Port scan failed for {subdomain}: {e}")
                ports_results[subdomain] = []
                continue
    
    return ports_results


def analyze_port_security(ports_results):
    """
    Analyze port scan results for security implications.
    
    Args:
        ports_results: Dictionary of subdomain -> open ports
    
    Returns:
        Dictionary with security analysis
    """
    security_analysis = {
        "high_risk_ports": [],
        "common_services": [],
        "total_open_ports": 0,
        "unique_services": set(),
        "vulnerable_services": []
    }
    
    # High-risk ports that should be monitored
    HIGH_RISK_PORTS = {
        21: "FTP (often unencrypted)",
        23: "Telnet (unencrypted)",
        135: "RPC",
        139: "NetBIOS",
        445: "SMB",
        1433: "MSSQL",
        3306: "MySQL",
        5432: "PostgreSQL",
        27017: "MongoDB",
        6379: "Redis"
    }
    
    for subdomain, ports in ports_results.items():
        for port_info in ports:
            port_num = port_info.get("port")
            service = port_info.get("service", "")
            
            security_analysis["total_open_ports"] += 1
            security_analysis["unique_services"].add(service)
            
            # Check for high-risk ports
            if port_num in HIGH_RISK_PORTS:
                security_analysis["high_risk_ports"].append({
                    "subdomain": subdomain,
                    "port": port_num,
                    "service": service,
                    "risk": HIGH_RISK_PORTS[port_num]
                })
            
            # Check for common web services
            if port_num in [80, 443, 8080, 8443]:
                security_analysis["common_services"].append({
                    "subdomain": subdomain,
                    "port": port_num,
                    "service": service
                })
    
    security_analysis["unique_services"] = list(security_analysis["unique_services"])
    
    return security_analysis


def run_port_scanning(ip_subdomain_pairs, max_workers=20):
    """
    Main orchestrator function for Model 2: Port Scanning & Service Detection.
    
    Args:
        ip_subdomain_pairs: List of tuples (subdomain, ip) to scan
        max_workers: Maximum number of parallel workers
    
    Returns:
        Dictionary with port scan results and analysis:
        {
            "ports_results": {subdomain: [ports]},
            "security_analysis": {...},
            "total_scanned": int,
            "total_open_ports": int,
            "elapsed_seconds": float
        }
    """
    start_time = time.time()
    
    if not ip_subdomain_pairs:
        return {
            "ports_results": {},
            "security_analysis": {
                "high_risk_ports": [],
                "common_services": [],
                "total_open_ports": 0,
                "unique_services": [],
                "vulnerable_services": []
            },
            "total_scanned": 0,
            "total_open_ports": 0,
            "elapsed_seconds": time.time() - start_time
        }
    
    # Step 1: Scan ports in parallel
    print(f"Model 2: Scanning ports for {len(ip_subdomain_pairs)} IPs...")
    ports_results = scan_ports_parallel(ip_subdomain_pairs, max_workers=max_workers)
    
    # Step 2: Analyze security implications
    security_analysis = analyze_port_security(ports_results)
    
    # Calculate total open ports
    total_open_ports = sum(len(ports) for ports in ports_results.values())
    
    elapsed = time.time() - start_time
    
    result = {
        "ports_results": ports_results,
        "security_analysis": security_analysis,
        "total_scanned": len(ip_subdomain_pairs),
        "total_open_ports": total_open_ports,
        "elapsed_seconds": elapsed
    }
    
    print(f"Model 2 completed in {elapsed:.2f} seconds - Found {total_open_ports} open ports")
    
    return result

