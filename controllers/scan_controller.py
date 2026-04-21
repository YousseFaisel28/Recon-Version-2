"""
Scan Controller - Handles domain scanning operations
"""

import time
import datetime

from flask import request, jsonify, Blueprint, session
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from bson.objectid import ObjectId
import numpy as np
from middlewares.auth_middleware import login_required
from middlewares.admin_middleware import admin_required

from models.model1 import run_subdomain_discovery
from models.model3 import run_technology_fingerprinting_for_subdomains
from models.model4 import HTTPAnomalyModel
from models.model5 import run_model_5
from models.model6_vulnerability_risk import Model6RiskScorer
from utils.http_collector import collect_http_features
from utils.traffic_collector import capture_traffic
from utils.domain_validator import normalize_domains
from utils.audit_logger import log_audit_event
from utils.json_utils import mongo_to_json
from utils.ssrf_protection import is_safe_target
from utils.logger import get_logger
from utils.extensions import limiter

logger = get_logger(__name__)

from config.database import (
    subdomains_collection,
    reports_collection,
    technologies_collection,
    vulnerabilities_collection,
    anomalies_collection,
    users_collection,
)

scan_bp = Blueprint('scan', __name__)

def sanitize_for_mongo(data):
    if isinstance(data, dict):
        return {k: sanitize_for_mongo(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_for_mongo(v) for v in data]
    elif isinstance(data, (np.bool_, np.bool)):
        return bool(data)
    elif isinstance(data, (np.int64, np.int32, np.int16, np.int8)):
        return int(data)
    elif isinstance(data, (np.float64, np.float32)):
        return float(data)
    return data

# ====================================================
# MODEL 4 & 6 LAZY INITIALIZATION
# ====================================================
_model4_instance = None
_model6_instance = None

def get_model4():
    """Lazy initialization of Model 4"""
    global _model4_instance
    if _model4_instance is None:
        _model4_instance = HTTPAnomalyModel()
        _model4_instance.load()
    return _model4_instance

def get_model6():
    """Lazy initialization of Model 6"""
    global _model6_instance
    if _model6_instance is None:
        _model6_instance = Model6RiskScorer()
        _model6_instance.load_model()
    return _model6_instance


@scan_bp.route("/add_domain", methods=["POST"])
@admin_required
def add_domain():
    from config.database import domains_collection
    data = request.get_json() or {}
    domain_name = (data.get("domain") or "").strip().lower()

    if not domain_name:
        return jsonify({"message": "Domain name is required!"}), 400

    domains_collection.update_one(
        {"domain": domain_name},
        {"$set": {"domain": domain_name, "created_at": datetime.datetime.utcnow()}},
        upsert=True,
    )

    # ── Audit Log ──
    logger.info(f"Domain added: {domain_name}")

    return jsonify({"message": "Domain saved successfully!"}), 201


@scan_bp.route("/scan_domain", methods=["POST"])
@login_required
@limiter.limit("5 per hour") if limiter else lambda f: f
def scan_domain():
    try:

        data = request.get_json()
        domain = data.get("domain", "").strip().lower()
        include_tech_scan = data.get("include_tech_scan", False)

        if not domain:
            return jsonify({"error": "Domain is required"}), 400

        # ----------------------------------------------------
        # SSRF PROTECTION: block internal/private targets
        # ----------------------------------------------------
        is_safe, ssrf_reason = is_safe_target(domain)
        if not is_safe:
            return jsonify({"error": f"Scan target rejected: {ssrf_reason}"}), 403


        start = time.time()
        print(f"Starting scan for domain: {domain} by user {session['user_id']}")

        # ── Audit Log: scan started ──
        log_audit_event(
            action="scan_started",
            domain=domain,
            details={"include_tech_scan": include_tech_scan},
        )

        # ====================================================
        # MODEL 1: SUBDOMAIN DISCOVERY
        # ====================================================
        result = run_subdomain_discovery(domain)
        result = sanitize_for_mongo(result)

        for sub in result.get("raw_docs", []):
            sub["domain"] = domain
            sub["scanned_at"] = datetime.datetime.utcnow()
            # sub = sanitize_for_mongo(sub) # Already sanitized via result
            subdomains_collection.update_one(
                {"domain": domain, "subdomain": sub["subdomain"]},
                {"$set": sub},
                upsert=True
            )

        # ====================================================
        # MODEL 4: HTTP ANOMALY DETECTION
        # ====================================================
        http_anomaly_results = []

        targets = [
            sub for sub in result.get("raw_docs", [])
            if sub.get("subdomain")
        ]
        
        # ── ROOT PRIORITIZATION ──
        # Ensure root domain is ALWAYS at index 0
        targets.sort(key=lambda x: x.get("is_root", False), reverse=True)
        # ─────────────────────────

        for sub in targets[:5]:
            try:
                subdomain = sub.get("subdomain")
                url = f"http://{subdomain}"

                # --- MULTI-MODEL COLLECTION ---
                # Run HTTP Analysis and Traffic Capture in Parallel
                with ThreadPoolExecutor(max_workers=2) as coll_exec:
                    http_future = coll_exec.submit(collect_http_features, url)
                    traffic_future = coll_exec.submit(capture_traffic, subdomain, duration=3)
                    
                    features = http_future.result()
                    traffic_features = traffic_future.result()
                    
                    # Merge features
                    features.update(traffic_features)

                anomaly_result = get_model4().predict(features)

                anomaly_doc = {
                    "domain": domain,
                    "subdomain": subdomain,
                    "is_root": sub.get("is_root", False),
                    "url": url,
                    "status": anomaly_result.get("status"),
                    "anomaly_score": anomaly_result.get("anomaly_score"),
                    "signals": anomaly_result.get("signals", []),
                    "traffic_data": anomaly_result.get("traffic_data", {}),
                    "model": "Model 4 - HTTP & Traffic Anomaly Detection",
                    "scanned_at": datetime.datetime.utcnow()
                }

                anomaly_doc = sanitize_for_mongo(anomaly_doc)
                anomalies_collection.update_one(
                    {"domain": domain, "subdomain": subdomain},
                    {"$set": anomaly_doc},
                    upsert=True
                )

                http_anomaly_results.append({
                    "domain": domain,
                    "subdomain": subdomain,
                    "url": url,
                    "model4_result": anomaly_result,
                    "scanned_at": datetime.datetime.utcnow()
                })

            except Exception as e:
                print(f"[Model4] Error on {subdomain}: {e}")

        # ====================================================
        # MODEL 3: TECHNOLOGY FINGERPRINTING
        # ====================================================
        tech_results = []
        if include_tech_scan:
            try:
                live_subdomains = [
                    sub for sub in result.get("raw_docs", [])
                    if sub.get("live_http")
                ]
                
                # ── ROOT PRIORITIZATION (TECH) ──
                live_subdomains.sort(key=lambda x: x.get("is_root", False), reverse=True)
                # ────────────────────────────────

                # ── Fallback: if HTTP probing found nothing live, use all
                # resolved subdomains so Model 3 still has targets to check.
                if not live_subdomains:
                    live_subdomains = [
                        sub for sub in result.get("raw_docs", [])
                        if sub.get("ip")  # at minimum it resolved to an IP
                    ]
                    if live_subdomains:
                        print(f"[Model 3] No live_http subdomains found — falling back to {len(live_subdomains)} resolved subdomains")

                if live_subdomains:
                    subdomains_data = []
                    for sub_doc in live_subdomains[:5]:
                        # Task 2.1: Hard Gate - No ports = No tech assignment
                        open_ports = sub_doc.get("open_ports", [])
                        if not open_ports:
                            print(f"[Model 3] Skip {sub_doc.get('subdomain')} — Service detection not verified (no open ports)")
                            continue

                        subdomains_data.append({
                            "subdomain": sub_doc.get("subdomain"),
                            "is_root": sub_doc.get("is_root", False),
                            "url": f"http://{sub_doc.get('subdomain')}",
                            "nmap_data": {"ports": open_ports},
                            "ip": sub_doc.get("ip")
                        })

                    executor = ThreadPoolExecutor(max_workers=1)
                    future = executor.submit(
                        run_technology_fingerprinting_for_subdomains,
                        subdomains_data
                    )

                    try:
                        tech_results = future.result(timeout=30)
                    except FutureTimeoutError:
                        tech_results = []

                    for tech_result in tech_results:
                        url = tech_result.get("url")
                        subdomain = url.replace("http://", "").replace("https://", "")

                        for tech in tech_result.get("technologies", []):
                            tech_update = {
                                    "domain": domain,
                                    "subdomain": subdomain,
                                    "is_root": tech_result.get("is_root", False),
                                    "url": url,
                                    "technology": tech.get("technology"),
                                    "version": tech.get("version"),
                                    "category": tech.get("category"),
                                    "source": tech.get("source"),
                                    "vulnerability_status": tech.get("vulnerability_status"),
                                    "confidence": tech.get("confidence"),
                                    "max_cvss": tech.get("max_cvss"),
                                    "similarity_score": tech.get("similarity_score"),
                                    "scanned_at": datetime.datetime.utcnow()
                            }
                            tech_update = sanitize_for_mongo(tech_update)

                            technologies_collection.update_one(
                                {
                                    "domain": domain,
                                    "subdomain": subdomain,
                                    "technology": tech.get("technology"),
                                    "version": tech.get("version")
                                },
                                {"$set": tech_update},
                                upsert=True
                            )

            except Exception as e:
                print(f"Model 3 error: {e}")

        # ====================================================
        # MODEL 5: EXPLOITATION STRATEGY (Sequential: requires Model 3 results)
        # ====================================================
        model5_output = {
            "model": "Model 5 - Exploitation Strategy",
            "strategy_count": 0,
            "strategies": []
        }
        
        # Model 5 requires Model 3 technology fingerprinting results
        # Only run if technology scan was performed and has results
        if include_tech_scan and tech_results:
            try:
                port_scan_results = []
                for sub in result.get("raw_docs", []):
                    for port in sub.get("open_ports", []):
                        port_scan_results.append({
                            "subdomain": sub["subdomain"],
                            "port": port["port"],
                            "service": port["service"]
                        })

                technology_results_for_model5 = []

                for tech_result in tech_results:
                    for tech in tech_result.get("technologies", []):
                        # Only include technologies with CVEs (real data requirement)
                        if tech.get("cves") and len(tech.get("cves", [])) > 0:
                            technology_results_for_model5.append(tech)

                http_anomaly_result_for_model5 = http_anomaly_results[0]["model4_result"] if http_anomaly_results else {}
                
                # Only run Model 5 if we have technologies with CVEs
                if technology_results_for_model5:
                    print(f"[Model 5] Running exploitation strategy engine with {len(technology_results_for_model5)} technologies")
                    model5_output = run_model_5(
                        port_scan_results=port_scan_results,
                        technology_results=technology_results_for_model5,
                        http_anomaly_result=http_anomaly_result_for_model5
                    )
                else:
                    print("[Model 5] No technologies with CVEs found - skipping exploitation strategy generation")
            except Exception as e:
                print(f"[Model5] Error generating strategies: {e}")
                import traceback
                traceback.print_exc()
                model5_output = {
                    "model": "Model 5 - Exploitation Strategy",
                    "strategy_count": 0,
                    "strategies": [],
                    "error": str(e)
                }
        else:
            print("[Model 5] Skipping - technology scan not performed or no results available")

        # ====================================================
        # MODEL 6: VULNERABILITY PRIORITIZATION & RISK SCORING
        # ====================================================
        model6_results = []
        try:
            vulnerabilities_to_score = []
            subdomain_count = len(result.get("raw_docs", []))
            
            # Map anomalies for easier lookup
            anomaly_map = {a["subdomain"]: a["model4_result"] for a in http_anomaly_results}
            
            for tech_res in tech_results:
                url = tech_res.get("url", "")
                subdomain = url.replace("http://", "").replace("https://", "")
                sub_doc = next((s for s in result.get("raw_docs", []) if s.get("subdomain") == subdomain), {})
                
                anomaly_data = anomaly_map.get(subdomain, {})
                
                exposed_service_count = len(sub_doc.get("open_ports", []))
                
                for tech in tech_res.get("technologies", []):
                    # Correctly identify port from tech metadata or URL
                    port = tech.get("metadata", {}).get("port")
                    if not port or port == 0:
                        port = 443 if "https://" in url else 80
                        
                    for cve in tech.get("cves", []):
                        record = {
                            "domain": domain,
                            "subdomain": subdomain,
                            "service_name": tech.get("technology"),
                            "port_number": int(port),
                            "cvss_score": float(cve.get("cvss", 0.0)),
                            "exploit_available": 1 if tech.get("source") == "ExploitDB" else 0,
                            "cve_id": cve.get("cve"),
                            "technology_stack": tech.get("technology"),
                            "is_public_port": 1,
                            "anomaly_flag": 1 if anomaly_data.get("status") == "suspicious" else 0,
                            "traffic_anomaly_score": float(anomaly_data.get("anomaly_score", 0.0)),
                            "misconfiguration_flag": 0,
                            "subdomain_count": subdomain_count,
                            "exposed_service_count": exposed_service_count
                        }
                        vulnerabilities_to_score.append(record)

            if vulnerabilities_to_score:
                print(f"[Model 6] Scoring {len(vulnerabilities_to_score)} vulnerabilities")
                scorer = get_model6()
                model6_results = scorer.predict_batch(vulnerabilities_to_score)
        except Exception as e:
            print(f"[Model 6 Error] {e}")

        # ====================================================
        # ✅ FINAL REPORT (SNAPSHOT)
        # ====================================================
        report = {
            "domain": domain,
            "user_id": session.get("user_id"),
            "scanned_at": datetime.datetime.utcnow(),
            "total_candidates": result.get("total_candidates", 0),
            "result": {
                "domain": domain,
                "total_candidates": result.get("total_candidates", 0),
                "resolved": result.get("resolved", 0),
                "live_http": result.get("live_http", 0),
                "examples": result.get("examples", []),
                "clusters": result.get("clusters", []),
                "raw_docs": result.get("raw_docs", []),
                "elapsed_seconds": time.time() - start,
                "ports_summary": result.get("ports_summary", {}),
                "technology_fingerprints": tech_results,
                "http_anomalies": http_anomaly_results,
                "model5": model5_output,
                "model6": model6_results
            }
        }
        
        # Insert as new document instead of update
        report = sanitize_for_mongo(report)
        insert_result = reports_collection.insert_one(report)
        report_id = str(insert_result.inserted_id)

        # ── Audit Log: scan completed ──
        log_audit_event(
            action="scan_completed",
            domain=domain,
            details={
                "report_id": report_id,
                "elapsed_seconds": round(time.time() - start, 2),
                "total_candidates": result.get("total_candidates", 0),
            },
        )

        return jsonify(mongo_to_json({
            "message": "Scan complete", 
            "report_id": report_id,
            "report": report["result"]
        })), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@scan_bp.route("/get_history", methods=["GET"])
@login_required
def get_history():
    user_id = session["user_id"]
    
    try:
        # Fetch scans only for this user
        cursor = reports_collection.find(
            {"user_id": user_id},
            {"_id": 1, "domain": 1, "scanned_at": 1, "result.total_candidates": 1}
        ).sort("scanned_at", -1)
        
        history = []
        for doc in cursor:
            history.append({
                "report_id": str(doc["_id"]),
                "domain": doc.get("domain", "Unknown"),
                "scanned_at": doc.get("scanned_at").isoformat() if doc.get("scanned_at") else None,
                "candidates": doc.get("result", {}).get("total_candidates", 0)
            })
            
        return jsonify({"history": history}), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
