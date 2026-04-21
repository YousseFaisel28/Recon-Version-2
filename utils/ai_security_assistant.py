"""
AI Security Assistant Utility - Core Analysis Logic
Translates raw scan results into plain-English insights.
"""

def get_cvss_float(val):
    try:
        return float(val)
    except (ValueError, TypeError):
        return 0.0

def generate_summary(scan_results):
    """
    Summarizes scan results (Models 1-6) in plain English.
    """
    if not scan_results:
        return "No scan results available to summarize."

    subdomains_count = len(scan_results.get("raw_docs", []))
    
    ports = []
    for host in scan_results.get("hosts", []):
        for p in host.get("ports", []):
            ports.append(p)
    if not ports:
        for sub in scan_results.get("raw_docs", []):
            for p in sub.get("open_ports", []):
                ports.append(p)
    
    open_ports_count = len(ports)
    
    tech_list = []
    for tech_res in scan_results.get("technology_fingerprints", []):
        for tech in tech_res.get("technologies", []):
            tech_name = tech.get("technology")
            version = tech.get("version")
            if tech_name:
                has_vulns = len(tech.get("cves", [])) > 0
                tech_str = f"{tech_name} ({version})" if version else tech_name
                if has_vulns:
                    tech_list.append(tech_str)
    
    tech_summary = ", ".join(list(set(tech_list))[:5]) if tech_list else "None with known vulnerabilities"

    model6_results = scan_results.get("model6", [])
    total_vulns = len(model6_results)
    
    # RULE 1: If ANY CVE has CVSS >= 9.0: -> MUST be labeled as "Critical Risk Present"
    has_cvss_9_plus = any(get_cvss_float(v.get("cvss")) >= 9.0 for v in model6_results)
    critical_count = len([v for v in model6_results if v.get("risk_level") == "CRITICAL"])
    
    is_critical = has_cvss_9_plus or critical_count > 0

    anomalies = scan_results.get("http_anomalies", [])
    suspicious_count = len([a for a in anomalies if a.get("model4_result", {}).get("status") == "suspicious"])

    summary = "ReconX AI Security Summary\n\n"
    
    if is_critical:
        summary += "🚨 Critical Risk Present\n\n"
        
    summary += f"Your scan discovered {subdomains_count} subdomains related to the target domain.\n\n"
    
    if open_ports_count > 0:
        summary += "One or more hosts expose an HTTP service on open ports. "
    else:
        summary += "No open ports were detected on the identified hosts. "

    summary += f"Technology analysis identified several stacks, with vulnerable components including: {tech_summary}.\n\n"

    # RULE 4: Summary must NEVER say: "no critical vulnerabilities" if critical CVEs exist in data
    if is_critical:
        summary += f"Multiple vulnerabilities were detected in the software stack, including critical CVEs. Addressing these should be your highest priority. "
    elif total_vulns > 0:
        summary += f"Although multiple services are exposed and {total_vulns} vulnerabilities were identified, no critical vulnerabilities were flagged in the current scan. "
    else:
        summary += "No software vulnerabilities were detected in the identified technologies.\n\n"

    if suspicious_count > 0:
        summary += f"Traffic analysis detected configuration issues such as server header disclosure or suspicious patterns affecting {suspicious_count} host(s).\n\n"

    summary += "Overall the attack surface is "
    if is_critical:
        summary += "highly vulnerable and contains critical software weaknesses."
    elif open_ports_count > 5:
        summary += "exposed due to multiple open services."
    else:
        summary += "relatively secure with minimal exposure."
    
    summary += "\n\nBased on:\nModel 1 — Subdomain Discovery\nModel 2 — Port Exposure\nModel 3 — Technology Detection\nModel 4 — HTTP Anomaly Detection\nModel 6 — Risk Prioritization"

    return summary


def calculate_security_score(scan_results):
    """
    Calculates a security score and rating based on scan findings using corrected weights.
    """
    if not scan_results:
        return "No scan data available."

    model6_results = scan_results.get("model6", [])
    critical = len([v for v in model6_results if v.get("risk_level") == "CRITICAL"])
    high = len([v for v in model6_results if v.get("risk_level") == "HIGH"])
    medium = len([v for v in model6_results if v.get("risk_level") == "MEDIUM"])
    
    has_cvss_9_plus = any(get_cvss_float(v.get("cvss")) >= 9.0 for v in model6_results)
    
    ports_count = 0
    for host in scan_results.get("hosts", []):
        ports_count += len(host.get("ports", []))
    if ports_count == 0:
         for sub in scan_results.get("raw_docs", []):
            ports_count += len(sub.get("open_ports", []))

    anomalies = len(scan_results.get("http_anomalies", []))

    # RULE 2: Security score must decrease when Critical vulnerabilities exist, or Multiple high exist.
    score = 100
    
    if critical > 0 or has_cvss_9_plus:
        score -= 30
    
    if high > 1:
        score -= 20
    
    score -= critical * 5
    score -= high * 5
    score -= medium * 2
    score -= min(ports_count, 10) * 1
    score -= anomalies * 2

    score = max(0, min(100, score))

    rating = "F (Critical Risk)"
    if score >= 90: rating = "A (Excellent)"
    elif score >= 80: rating = "B (Low Risk)"
    elif score >= 70: rating = "C (Moderate Risk)"
    elif score >= 60: rating = "D (High Risk)"

    response = "ReconX Security Rating\n\n"
    response += f"Score: {score} / 100\n"
    response += f"Rating: {rating}\n\n"
    
    response += "Key Risk Factors:\n"
    if critical > 0 or has_cvss_9_plus: 
        response += f"- Critical risk vulnerabilities are present in your stack\n"
    if high > 0: response += f"- {high} high-risk flaws found\n"
    
    vuln_tech = []
    for tech_res in scan_results.get("technology_fingerprints", []):
        for tech in tech_res.get("technologies", []):
            if len(tech.get("cves", [])) > 0:
                tech_name = tech.get("technology")
                version = tech.get("version")
                vuln_tech.append(f"{tech_name} {version}" if version else tech_name)
    
    if vuln_tech:
        response += f"- Vulnerable technologies detected: {', '.join(list(set(vuln_tech))[:3])}\n"

    if ports_count > 0:
        response += f"- {ports_count} services exposed to the public internet\n"
    
    if anomalies > 0:
        response += f"- {anomalies} configuration anomalies detected\n"

    response += "\nBased on:\nModel 2 — Port Exposure\nModel 4 — HTTP Anomaly Detection\nModel 6 — Risk Prioritization"

    return response


def generate_fix_priorities(scan_results):
    """
    Returns prioritized remediation steps based on Model 7 results.
    RULE 5: Fix recommendations must prioritize Highest CVSS vulnerabilities first.
    """
    recs = scan_results.get("recommendations", [])
    if not recs:
        recs = scan_results.get("result", {}).get("recommendations", [])

    if not recs:
        return "Top Security Fixes\n\nNo significant vulnerabilities were found that require immediate remediation steps.\n\nBased on:\nModel 7 — Recommendation Engine"

    # Helper to fetch max CVSS linked to a recommendation
    def get_max_cvss_for_rec(rec):
        service = rec.get("service")
        cve_id = rec.get("vulnerability_id")
        max_c = 0.0
        for v in scan_results.get("model6", []):
            if v.get("service_name") == service or v.get("cve_id") == cve_id:
                c = get_cvss_float(v.get("cvss"))
                if c > max_c: max_c = c
        return max_c

    # Sort primarily by CVSS (descending)
    severity_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_recs = sorted(recs, key=lambda x: (get_max_cvss_for_rec(x), -severity_map.get(x.get("severity", "LOW"), 4)), reverse=True)

    response = "Top Security Fixes\n\n"
    
    service_fixes = {}
    for rec in sorted_recs:
        service = rec.get("service", "General")
        if service not in service_fixes:
            service_fixes[service] = {
                "fix": rec.get("recommended_fix"),
                "count": 0,
                "severity": rec.get("severity"),
                "max_cvss": get_max_cvss_for_rec(rec)
            }
        service_fixes[service]["count"] += 1

    count = 1
    for service, data in list(service_fixes.items())[:3]:
        response += f"{count}. Address {service} Vulnerabilities\n"
        response += f"   - Recommended Action: {data['fix']}\n"
        if data['max_cvss'] > 0:
            response += f"   - Highest CVSS: {data['max_cvss']}\n"
        response += f"   - Impact: Fixes {data['count']} {data['severity']} risk(s).\n\n"
        count += 1

    response += "These actions will significantly reduce the attack risk of your organization.\n\n"
    response += "Based on:\nModel 7 — Recommendation Engine"

    return response


def explain_biggest_risk(scan_results):
    """
    Analyzes all models to determine the single most significant risk.
    RULE 3: Risk explanation priority: CVEs (Critical) > Services > Anomalies
    """
    if not scan_results:
        return "No scan results available."

    model6_results = scan_results.get("model6", [])
    critical_vulns = [v for v in model6_results if v.get("risk_level") == "CRITICAL" or get_cvss_float(v.get("cvss")) >= 9.0]
    high_vulns = [v for v in model6_results if v.get("risk_level") == "HIGH"]
    
    anomalies = scan_results.get("http_anomalies", [])
    suspicious = [a for a in anomalies if a.get("model4_result", {}).get("status") == "suspicious"]

    ports_count = 0
    for host in scan_results.get("hosts", []):
        ports_count += len(host.get("ports", []))
    if ports_count == 0:
         for sub in scan_results.get("raw_docs", []):
            ports_count += len(sub.get("open_ports", []))

    response = "ReconX Risk Insight\n\n"

    # PRIORITY 1: Critical CVEs
    if critical_vulns:
        # Sort critical to find the absolute worst
        critical_vulns.sort(key=lambda x: get_cvss_float(x.get('cvss')), reverse=True)
        top_vuln = critical_vulns[0]
        service = top_vuln.get("service_name", "exposed services")
        response += f"The most significant risk identified in this scan is the presence of critical vulnerabilities affecting {service}.\n\n"
        response += f"Specifically, {top_vuln.get('cve_id', 'a known flaw')} (CVSS {get_cvss_float(top_vuln.get('cvss'))}) poses a severe threat as it allows for high-impact exploitation. "
        response += "These vulnerabilities could allow attackers to execute malicious requests against the application.\n\n"
        response += "Addressing these issues should be the highest priority."
        
    # PRIORITY 2: High CVEs
    elif high_vulns:
        high_vulns.sort(key=lambda x: get_cvss_float(x.get('cvss')), reverse=True)
        top_vuln = high_vulns[0]
        response += f"The primary risk is the detection of high-severity vulnerabilities in {top_vuln.get('service_name', 'system dependencies')}.\n\n"
        response += "While no critical flaws were found, these high-risk items provide a clear path for attackers to gain unauthorized access or disrupt services.\n\n"
        response += "You should apply the recommended patches immediately."
        
    # PRIORITY 3: Services (Exposed Ports) > Anomalies
    elif ports_count > 0:
        response += "The most significant concern is the attack surface created by exposed services.\n\n"
        response += f"With {ports_count} open port(s) detected, your infrastructure is susceptible to unauthorized access, brute-force attacks, and zero-day exploitation.\n\n"
        response += "We recommend heavily restricting internet-facing services and closing any non-essential ports to harden your perimeter."
        
    # PRIORITY 4: Anomalies
    elif suspicious:
        response += "The biggest risk identified is related to configuration anomalies and unexpected traffic patterns detected by our AI.\n\n"
        response += "Exposed headers, unusual server responses, or unexpected status codes can leak sensitive information to attackers, facilitating targeted reconnaissance.\n\n"
        response += "Securing these server configurations will drastically reduce your exposure."
        
    else:
        response += "No critical or high-severity risks were identified. The current security posture appears stable, with minimal exposure.\n\n"
        response += "Continue monitoring your assets for any new changes."

    response += "\n\nBased on:\n"
    models = []
    if critical_vulns or high_vulns: models.append("Model 6 — Risk Prioritization")
    if suspicious: models.append("Model 4 — HTTP Anomaly Detection")
    if ports_count: models.append("Model 2 — Port Exposure")
    response += "\n".join(models) if models else "ReconX AI Analysis Engine"

    return response

def answer_custom_question(scan_results, question):
    """
    Searches scan results to answer a simple user query in plain English.
    """
    q = question.lower()
    
    if "php" in q:
        tech_found = False
        vulns = []
        for tech_res in scan_results.get("technology_fingerprints", []):
            for tech in tech_res.get("technologies", []):
                if "php" in tech.get("technology", "").lower():
                    tech_found = True
                    for cve in tech.get("cves", []):
                        vulns.append(cve.get("cve"))
        
        for v in scan_results.get("model6", []):
            if "php" in v.get("service_name", "").lower() or "php" in v.get("technology_stack", "").lower():
                tech_found = True
                vulns.append(v.get("cve_id"))
        
        if tech_found:
            res = "Yes, the scan detected PHP running on your infrastructure. "
            if vulns:
                res += f"Specifically, the following CVEs affect your PHP installation: {', '.join(list(set(filter(None, vulns)))[:3])}. "
            else:
                 res += "No specific vulnerabilities were detected in this technology. "
            res += "I recommend checking the Recommendation section for full details."
            return res + "\n\nBased on:\nModel 3 — Technology Detection\nModel 6 — Risk Prioritization"
    
    if "port" in q or "service" in q:
        ports = []
        for host in scan_results.get("hosts", []):
            for p in host.get("ports", []):
                ports.append(f"{p.get('port')}/{p.get('service')}")
        for sub in scan_results.get("raw_docs", []):
            for p in sub.get("open_ports", []):
                ports.append(f"{p.get('port')}/{p.get('service')}")
                
        if ports:
            return f"The scan identified the following open ports: {', '.join(set(ports))}.\n\nBased on:\nModel 2 — Port Exposure"
        else:
            return "No open ports were identified during this scan.\n\nBased on:\nModel 2 — Port Exposure"

    if "subdomain" in q:
        count = len(scan_results.get("raw_docs", []))
        return f"A total of {count} subdomains were discovered during the reconnaissance phase.\n\nBased on:\nModel 1 — Subdomain Discovery"

    return "I'm sorry, I couldn't find a specific answer to that question in current scan results. Try asking about 'summarize', 'security rating', or 'fixes'.\n\nBased on:\nReconX AI Analysis Engine"
