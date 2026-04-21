import os
import base64
import pdfkit
from jinja2 import Template
from datetime import datetime
from utils.ai_security_assistant import generate_summary, calculate_security_score, generate_fix_priorities, explain_biggest_risk

# Path to wkhtmltopdf executable
def get_pdfkit_config():
    """
    Search for wkhtmltopdf executable and return pdfkit configuration.
    """
    possible_paths = [
        r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe',
        r'C:\Program Files (x86)\wkhtmltopdf\bin\wkhtmltopdf.exe',
        r'C:\wkhtmltopdf\bin\wkhtmltopdf.exe'
    ]
    
    import shutil
    path_in_env = shutil.which("wkhtmltopdf")
    if path_in_env:
        return pdfkit.configuration(wkhtmltopdf=path_in_env)

    for path in possible_paths:
        if os.path.exists(path):
            return pdfkit.configuration(wkhtmltopdf=path)
            
    return None

config = get_pdfkit_config()

def get_base64_logo():
    logo_path = os.path.abspath(r"assets\logo.png")
    if os.path.exists(logo_path):
        try:
            with open(logo_path, "rb") as f:
                b64 = base64.b64encode(f.read()).decode("utf-8")
                return f"data:image/png;base64,{b64}"
        except:
            pass
    return ""

def generate_html_report(scan_results, domain, username, scan_id):
    """
    Generates a high-end, modern dashboard-style HTML report for PDF export.
    Syncs ALL data from the website scan report into the PDF, sequentially ordered.
    """
    # --- 1. DATA EXTRACTION ---
    subdomains = scan_results.get("raw_docs", []) or []
    vulns_m6 = scan_results.get("model6", []) or []
    recommendations = scan_results.get("recommendations", []) or []
    if not recommendations:
        recommendations = scan_results.get("result", {}).get("recommendations", []) or []
    clusters = scan_results.get("clusters", []) or []
    tech_fingerprints = scan_results.get("technology_fingerprints", []) or []
    anomalies = scan_results.get("http_anomalies", []) or []
    model5 = scan_results.get("model5", {}) or {}
    if not isinstance(model5, dict): model5 = {}
    model5_strategies = model5.get("strategies", []) or []

    # Defensive cleaning for nested fields
    for c in clusters:
        if not c.get("examples"): c["examples"] = []
    
    for t in tech_fingerprints:
        if not t.get("technologies"): t["technologies"] = []
        for tech in t["technologies"]:
            if not tech.get("cves"): tech["cves"] = []

    for a in anomalies:
        if not a.get("model4_result"): a["model4_result"] = {"status": "unknown", "traffic_data": {}}
        if not a["model4_result"].get("traffic_data"): a["model4_result"]["traffic_data"] = {}

    for strat in model5_strategies:
        if not strat.get("attack_chain"): strat["attack_chain"] = []
        if not strat.get("exploit_db_reference"): strat["exploit_db_reference"] = []

    # Metrics
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in vulns_m6:
        sev = str(v.get("risk_level", v.get("severity", ""))).upper()
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    total_vulns = len(vulns_m6)
    critical_count = severity_counts["CRITICAL"]
    high_count = severity_counts["HIGH"]
    
    # Risk Score
    risk_score = min(100, (critical_count * 25 + high_count * 10 + severity_counts["MEDIUM"] * 5) / (max(1, len(subdomains) / 2)))
    risk_score = round(risk_score, 1)

    # Ports for dashboard
    ports = []
    for host in scan_results.get("hosts", []) or []:
        for p in host.get("ports", []) or []:
            ports.append(p)

    # Subdomain Mapping
    host_details = {}
    for doc in subdomains:
        sub = doc.get("subdomain")
        h_ports = doc.get("open_ports", [])
        ips = doc.get("ip_addresses", doc.get("resolved_ips", []))
        is_active = doc.get("is_active", len(h_ports) > 0)
        host_details[sub] = {"ports": h_ports, "ips": ips, "is_active": is_active}

    # Recommendations Sort
    recommendations_sorted = sorted(recommendations, key=lambda x: ({"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(str(x.get("severity", x.get("priority", "LOW"))).upper(), 0)), reverse=True)

    # AI Insights
    ai_summary = generate_summary(scan_results).replace("\n", "<br>")
    ai_score = calculate_security_score(scan_results).replace("\n", "<br>")
    ai_priorities = generate_fix_priorities(scan_results).replace("\n", "<br>")
    ai_biggest_risk = explain_biggest_risk(scan_results).replace("\n", "<br>")

    # Logo Data URI
    logo_data_uri = get_base64_logo()

    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <style>
            body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; color: #1e293b; background: #ffffff; margin: 0; padding: 0; line-height: 1.5; font-size: 10pt; }
            .clearfix:after { content: ""; display: table; clear: both; }
            .page-break { page-break-after: always; }
            
            /* Cover Page */
            .cover { height: 950pt; background: #111827; color: white; text-align: center; padding-top: 150pt; box-sizing: border-box; border-left: 20pt solid #10b981; }
            .cover h1 { font-size: 34pt; font-weight: 800; margin: 0; letter-spacing: -1pt; color: #10b981;}
            .cover p { font-size: 14pt; color: #34d399; text-transform: uppercase; letter-spacing: 4pt; font-weight: 600; margin-top: 15pt; }
            .cover-meta { margin-top: 250pt; font-size: 11pt; color: #9ca3af; }
            .cover-meta b { color: white; display: block; font-size: 13pt; margin-top: 5pt; margin-bottom: 20pt; }

            /* Header Section */
            .report-header { background: #111827; color: white; padding: 25pt 40pt; box-sizing: border-box; border-left: 10pt solid #10b981; }
            .report-header h2 { margin: 0; font-size: 18pt; }
            .report-header p { margin: 3pt 0 0 0; color: #34d399; font-size: 9pt; font-weight: 700; text-transform: uppercase; }

            /* Dashboard */
            .dashboard { padding: 30pt 40pt; background: #f9fafb; border-bottom: 1px solid #e5e7eb; }
            .card-wrapper { width: 23%; float: left; margin-right: 2%; box-sizing: border-box; }
            .card-wrapper:last-child { margin-right: 0; }
            .metric-card { background: white; padding: 15pt 10pt; border-radius: 8pt; border: 1px solid #e5e7eb; text-align: center; }
            .metric-card .val { font-size: 22pt; font-weight: 800; display: block; color: #111827; }
            .metric-card .lbl { font-size: 7pt; color: #6b7280; text-transform: uppercase; font-weight: 700; margin-top: 4pt; display: block; }
            .acc-red { border-top: 3pt solid #ef4444; }
            .acc-blue { border-top: 3pt solid #3b82f6; }
            .acc-green { border-top: 3pt solid #10b981; }
            .acc-purple { border-top: 3pt solid #8b5cf6; }

            /* Content Sections */
            .container { padding: 40pt; }
            .section-title { font-size: 18pt; font-weight: 800; color: #111827; margin-bottom: 20pt; border-bottom: 2pt solid #10b981; display: inline-block; padding-bottom: 4pt; }
            
            /* Tables */
            table { width: 100%; border-collapse: collapse; margin-bottom: 20pt; font-size: 9pt; }
            th { text-align: left; background: #f3f4f6; padding: 8pt 12pt; color: #4b5563; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 2px solid #e5e7eb; }
            td { padding: 8pt 12pt; border-bottom: 1px solid #f3f4f6; vertical-align: top; }
            
            /* Badges */
            .badge { padding: 2pt 6pt; border-radius: 4pt; font-size: 8pt; font-weight: 700; color: white; display: inline-block; }
            .bg-red { background: #ef4444; }
            .bg-orange { background: #f97316; }
            .bg-yellow { background: #eab308; }
            .bg-green { background: #10b981; }
            .bg-blue { background: #3b82f6; }
            .bg-purple { background: #8b5cf6; }
            .bg-gray { background: #6b7280; }

            /* Cards */
            .glass-card { background: #ffffff; border: 1px solid #e5e7eb; border-radius: 10pt; padding: 15pt; margin-bottom: 20pt; page-break-inside: avoid; }
            .card-title { font-size: 11pt; font-weight: 700; color: #111827; margin-bottom: 10pt; display: block; }
            
            /* Cluster Items */
            .cluster-item { padding: 8pt 0; border-bottom: 1px dashed #f3f4f6; font-size: 8.5pt; }
            .cluster-item:last-child { border-bottom: 0; }
            .cluster-item-title { font-weight: 700; color: #1f2937; word-break: break-all; }
            .cluster-ips { color: #6b7280; font-family: monospace; font-size: 8pt; margin-top: 2pt; }
            
            /* Anomaly Cards */
            .anomaly-grid { width: 32%; float: left; margin-right: 1.33%; box-sizing: border-box; }
            .anomaly-grid:last-child { margin-right: 0; }

            /* Attack Path Section */
            .path-step { background: #f8fafc; border: 1px solid #e2e8f0; padding: 10pt 15pt; border-radius: 6pt; display: inline-block; font-weight: 700; font-size: 9pt; margin-right: 10pt; margin-bottom: 5pt; }
            .path-arrow { color: #3b82f6; font-weight: bold; margin-right: 10pt; }

            /* AI Section */
            .ai-block { background: #f8fafc; border: 1px solid #e2e8f0; border-left: 4pt solid #8b5cf6; padding: 15pt; margin-bottom: 15pt; border-radius: 6pt; }
            .ai-title { font-weight: 700; color: #4c1d95; font-size: 10pt; margin-bottom: 8pt; display: block; text-transform: uppercase; }
            .ai-content { font-size: 9.5pt; color: #334155; line-height: 1.6; }

            @page { margin: 0; }
        </style>
    </head>
    <body>
        <div class="cover">
            {% if logo_uri %}
            <img src="{{ logo_uri }}" alt="ReconX Logo" style="width: 200pt; margin-bottom: 30pt;">
            {% endif %}
            <h1>ReconX Security Report</h1>
            <p>Intelligence & Vulnerability Audit</p>
            <div class="cover-meta">
                TARGET DOMAIN<b>{{ domain }}</b>
                REPORT REQUESTED BY<b>{{ username }}</b>
                REPORT GENERATED<b>{{ date }}</b>
                AUDIT IDENTIFIER<b>RX-{{ scan_id[:12].upper() }}</b>
            </div>
        </div>

        <div class="report-header">
            <h2>Executive Overview</h2>
            <p>Unified Assessment Dashboard</p>
        </div>

        <div class="dashboard clearfix">
            <div class="card-wrapper"><div class="metric-card acc-blue"><span class="val">{{ subdomains|length }}</span><span class="lbl">Subdomains</span></div></div>
            <div class="card-wrapper"><div class="metric-card acc-purple"><span class="val">{{ total_vulns }}</span><span class="lbl">Verifiable Vulns</span></div></div>
            <div class="card-wrapper"><div class="metric-card acc-red"><span class="val">{{ critical_count }}</span><span class="lbl">Critical Risks</span></div></div>
            <div class="card-wrapper"><div class="metric-card acc-green"><span class="val">{{ risk_score }}%</span><span class="lbl">Avg Risk Score</span></div></div>
        </div>

        <div class="container" style="padding-bottom: 0;">
            <h3 class="section-title">AI Insights &amp; Security Summary</h3>
            
            <div class="ai-block">
                <span class="ai-title">Security Summary</span>
                <div class="ai-content">{{ ai_summary }}</div>
            </div>
            
            <div class="ai-block">
                <span class="ai-title">Risk Rating &amp; Key Factors</span>
                <div class="ai-content">{{ ai_score }}</div>
            </div>
            
            <div class="ai-block" style="border-left-color: #f59e0b;">
                <span class="ai-title">Biggest Identified Risk</span>
                <div class="ai-content">{{ ai_biggest_risk }}</div>
            </div>

            <div class="ai-block" style="border-left-color: #10b981;">
                <span class="ai-title">What To Fix First (Priorities)</span>
                <div class="ai-content">{{ ai_priorities }}</div>
            </div>
        </div>

        <div class="page-break"></div>

        <div class="container" style="padding-top: 40pt; padding-bottom: 0;">
            <h3 class="section-title">Model 1: Subdomain Discovery</h3>
            <p style="margin-bottom: 20pt; color: #6b7280;">Logical grouping of assets based on shared infrastructure patterns.</p>
            
            <div class="clearfix">
                {% for c in clusters %}
                <div style="width: 48%; float: left; margin-right: 2%; margin-bottom: 20pt;">
                    <div class="glass-card" style="margin-bottom: 0;">
                        <span class="card-title">Cluster {{ c.cluster_id }} ({{ c.size }} Nodes)</span>
                        <div style="max-height: 250pt; overflow: hidden;">
                            {% for sub in c.examples[:12] %}
                            {% set sub_dat = host_details[sub] %}
                            <div class="cluster-item">
                                <span class="cluster-item-title">{{ sub }}</span>
                                {% if sub_dat and sub_dat.is_active %}
                                    <span class="badge bg-green" style="font-size: 6pt; padding: 1pt 3pt;">ACTIVE</span>
                                {% else %}
                                    <span class="badge bg-gray" style="font-size: 6pt; padding: 1pt 3pt;">DEAD</span>
                                {% endif %}
                                
                                {% if sub_dat and sub_dat.ips %}
                                <div class="cluster-ips">IP: {{ sub_dat.ips | join(', ') }}</div>
                                {% endif %}
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                </div>
                {% if loop.index is divisibleby 2 %}<div class="clearfix"></div>{% endif %}
                {% endfor %}
            </div>
        </div>

        <div class="page-break"></div>
        
        <div class="container" style="padding-top: 40pt; padding-bottom: 0;">
            <h3 class="section-title">Model 2: Port Exposure</h3>
            <p style="margin-bottom: 20pt; color: #6b7280;">Extracted service footprint across all discovered network assets.</p>
            <table>
                <thead>
                    <tr><th>Host Subdomain</th><th>Port Layout</th></tr>
                </thead>
                <tbody>
                    {% for sub, dat in host_details.items() %}
                    {% if dat.ports %}
                    <tr>
                        <td style="font-weight: bold; width: 40%; font-family: monospace;">{{ sub }}</td>
                        <td>
                            {% for p in dat.ports %}
                            <span style="background: #f1f5f9; padding: 2pt 5pt; border-radius: 3pt; font-size: 8pt; color: #475569; display: inline-block; margin-right: 3pt; margin-bottom: 3pt;">
                                {{ p.port }}/{{ p.service }}
                            </span>
                            {% endfor %}
                        </td>
                    </tr>
                    {% endif %}
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="page-break"></div>

        <div class="container" style="padding-top: 40pt; padding-bottom: 0;">
            <h3 class="section-title">Model 3: Technology Fingerprinting</h3>
            <p style="margin-bottom: 20pt; color: #6b7280;">Extracted tech stacks and vulnerability classification.</p>
            {% for t in tech_fingerprints %}
            <div class="glass-card">
                {% if t.is_root or t.subdomain == domain %}
                <span style="background: #3b82f6; color: white; padding: 1pt 4pt; border-radius: 3pt; font-size: 6.5pt; font-weight: bold; float: right; margin-bottom: 5pt;">PRIMARY TARGET</span>
                {% endif %}
                <span class="card-title" style="color: #3b82f6;">{{ t.url }}</span>
                <table>
                    <thead>
                        <tr><th>Technology</th><th>Version</th><th>Vulnerabilities</th></tr>
                    </thead>
                    <tbody>
                        {% for tech in t.technologies %}
                        <tr>
                            <td><b>{{ tech.technology }}</b></td>
                            <td>{{ tech.version or 'Unknown' }}</td>
                            <td>
                                {% if tech.cves %}
                                    {% for cve in tech.cves[:4] %}
                                    <div style="margin-bottom: 2pt;">
                                        <span class="badge bg-red" style="font-size: 7pt;">{{ cve.cve }}</span>
                                        <span style="font-size: 7pt; color: #6b7280;">(CVSS {{ cve.cvss }}) - {{ cve.severity }}</span>
                                    </div>
                                    {% endfor %}
                                    {% if tech.cves|length > 4 %}
                                    <div style="font-size: 7pt; color: #6b7280;">+ {{ tech.cves|length - 4 }} more CVEs</div>
                                    {% endif %}
                                {% else %}
                                    <span style="color: #10b981; font-weight: 700; font-size: 8pt;">SECURE</span>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endfor %}
        </div>

        <div class="page-break"></div>

        <div class="container" style="padding-top: 40pt; padding-bottom: 0;">
            <h3 class="section-title">Model 4: Traffic Anomaly Analysis</h3>
             <p style="margin-bottom: 20pt; color: #6b7280;">Packet and SYN analysis, uncovering suspicious status flags.</p>
            <div class="clearfix">
                {% for a in anomalies %}
                <div class="anomaly-grid">
                    <div class="glass-card" style="border-left: 4pt solid {% if a.model4_result.status == 'suspicious' %}#ef4444{% else %}#10b981{% endif %};">
                        {% if a.is_root or a.subdomain == domain %}
                        <span style="background: #3b82f6; color: white; padding: 1pt 4pt; border-radius: 3pt; font-size: 6.5pt; font-weight: bold; float: right; margin-bottom: 5pt;">PRIMARY TARGET</span>
                        {% endif %}
                        <span class="card-title" style="font-size: 9pt; word-break: break-all;">{{ a.subdomain }}</span>
                        <div style="font-size: 8pt; color: #6b7280; margin-bottom: 5pt;">
                            Status: <b style="color: {% if a.model4_result.status == 'suspicious' %}#ef4444{% else %}#10b981{% endif %}; border: 1px solid {% if a.model4_result.status == 'suspicious' %}#ef4444{% else %}#10b981{% endif %}; padding: 1pt 3pt; border-radius: 3pt;">{{ a.model4_result.status|upper }}</b>
                        </div>
                        <div style="background: #f8fafc; padding: 5pt; border-radius: 4pt; font-size: 8pt; margin-bottom: 5pt;">
                            <div style="display: inline-block; width: 30%;">PKTs: <b>{{ a.model4_result.traffic_data.packet_count or 0 }}</b></div>
                            <div style="display: inline-block; width: 30%;">SYNs: <b>{{ a.model4_result.traffic_data.tcp_syn_count or 0 }}</b></div>
                            <div style="display: inline-block; width: 30%;">IPs: <b>{{ a.model4_result.traffic_data.unique_ips or 0 }}</b></div>
                        </div>
                        {% if a.model4_result.signals %}
                        <div style="font-size: 7.5pt; color: #ef4444;">
                            {% for sig in a.model4_result.signals[:3] %}
                            <div style="margin-bottom: 2pt;">• {{ sig }}</div>
                            {% endfor %}
                        </div>
                        {% elif a.model4_result.status == 'suspicious' %}
                        <div style="font-size: 7.5pt; color: #f97316; font-style: italic;">
                            • {{ a.model4_result.justification or "Statistical anomaly detected in traffic patterns." }}
                        </div>
                        {% else %}
                        <div style="font-size: 7.5pt; color: #10b981;">• No suspicious signals detected</div>
                        {% endif %}
                    </div>
                </div>
                {% if loop.index is divisibleby 3 %}<div class="clearfix"></div>{% endif %}
                {% endfor %}
            </div>
        </div>

        <div class="page-break"></div>

        <div class="container" style="padding-top: 40pt;">
            <h3 class="section-title">Model 5: Exploitation Strategy</h3>
            <p style="margin-bottom: 20pt; color: #6b7280;">Attack chain prediction and exploit availability.</p>
            {% for strat in model5_strategies %}
            <div class="glass-card">
                <span class="badge bg-red" style="float: right;">{{ strat.evidence_status }}</span>
                <span class="card-title">{{ strat.cve_id }}</span>
                <p style="font-size: 9pt; font-style: italic; color: #4b5563; margin-bottom: 10pt;">"{{ strat.explanation }}"</p>
                <div style="margin-bottom: 10pt;">
                   <span style="font-size: 8pt; font-weight: bold; color: #6b7280;">MITRE Technique:</span>
                   <span style="font-size: 8pt; font-family: monospace; background: #f3f4f6; padding: 2pt 4pt; border-radius: 3pt;">{{ strat.mitre_technique or 'N/A' }}</span>
                </div>
                
                <h4 style="font-size: 8pt; margin-bottom: 5pt; color: #6b7280;">PREDICTED ATTACK PATH</h4>
                <div class="clearfix" style="margin-bottom: 10pt;">
                    {% for step in strat.attack_chain %}
                    <span class="path-step">{{ step }}</span>
                    {% if not loop.last %}<span class="path-arrow">→</span>{% endif %}
                    {% endfor %}
                </div>

                {% if strat.exploit_db_reference %}
                <h4 style="font-size: 8pt; margin-bottom: 5pt; color: #6b7280;">EXPLOIT-DB INTELLIGENCE</h4>
                <ul style="font-size: 8pt; color: #3b82f6; padding-left: 15pt; margin: 0;">
                    {% for ref in strat.exploit_db_reference %}
                    <li style="margin-bottom: 2pt;"><a href="{{ ref.url }}" style="color: #3b82f6;">{{ ref.title }}</a></li>
                    {% endfor %}
                </ul>
                {% endif %}
            </div>
            {% endfor %}
        </div>

        <div class="page-break"></div>

        <div class="container" style="padding-top: 40pt;">
            <h3 class="section-title">Model 6: Vulnerability Risk Prioritization</h3>
            <p style="margin-bottom: 20pt; color: #6b7280;">Full risk assessment and sorted CVE mapping.</p>
            <table>
                <thead>
                    <tr><th>CVE ID</th><th>Affected Service</th><th>Port</th><th>CVSS</th><th>Risk Level</th></tr>
                </thead>
                <tbody>
                    {% for v in vulns_m6 %}
                    <tr>
                        <td style="font-weight: 700; color: #3b82f6; font-family: monospace;">
                            {% if v.subdomain == domain or v.is_root %}
                            <small style="background: #3b82f6; color: white; padding: 0pt 2pt; border-radius: 2pt; font-size: 6pt; vertical-align: middle; margin-right: 2pt;">PRIMARY</small>
                            {% endif %}
                            {{ v.cve_id or 'N/A' }}
                        </td>
                        <td>{{ v.service or v.service_name or 'System' }}</td>
                        <td>{{ v.port or v.port_number or 'N/A' }}</td>
                        <td><b>{{ v.cvss or v.cvss_score or 'N/A' }}</b></td>
                        <td><span class="badge {% if v.risk_level == 'CRITICAL' or v.risk_level == 'Critical' %}bg-red{% elif v.risk_level == 'HIGH' or v.risk_level == 'High' %}bg-orange{% elif v.risk_level == 'MEDIUM' or v.risk_level == 'Medium' %}bg-yellow{% else %}bg-green{% endif %}">{{ v.risk_level }}</span></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="page-break"></div>

        <div class="container" style="padding-top: 40pt;">
            <h3 class="section-title">Model 7: Recommendation Engine</h3>
            <p style="margin-bottom: 20pt; color: #6b7280;">Comprehensive, categorized fixes including attacker perspective.</p>
            {% for rec in recommendations %}
            {% set sev = (rec.priority or rec.severity or "LOW") | string | upper %}
            <div class="glass-card" style="border-left: 4pt solid {% if 'CRITICAL' in sev %}#ef4444{% elif 'HIGH' in sev %}#f97316{% elif 'MEDIUM' in sev %}#eab308{% else %}#10b981{% endif %};">
                <div style="float: right;">
                    <span class="badge {% if 'CRITICAL' in sev %}bg-red{% elif 'HIGH' in sev %}bg-orange{% elif 'MEDIUM' in sev %}bg-yellow{% else %}bg-green{% endif %}" style="font-size: 7.5pt;">{{ sev }}</span>
                </div>
                <span class="card-title">{{ rec.vulnerability_id or rec.cve_id or 'General Finding' }} - {{ rec.service or 'System' }}</span>
                
                <div style="margin-bottom: 10pt; font-size: 8.5pt;">
                    <span style="padding: 2pt 5pt; background: #f3f4f6; border-radius: 4pt; font-weight: bold; color: #4b5563;">
                        {{ rec.confidence_level or 'MEDIUM' }} CONFIDENCE
                    </span>
                    <span style="margin-left: 10pt; color: #6b7280;">{{ rec.justification or 'Derived from structural analysis.' }}</span>
                </div>

                <p style="font-size: 9.5pt; margin-bottom: 15pt; color: #1f2937;">{{ rec.explanation }}</p>
                
                {% if rec.attacker_perspective %}
                <div style="background: #fef2f2; border: 1px solid #fecaca; padding: 10pt; border-radius: 6pt; margin-bottom: 15pt;">
                    <h5 style="margin: 0 0 5pt 0; color: #b91c1c; font-size: 8pt; text-transform: uppercase;">Attacker Perspective</h5>
                    <p style="margin: 0; font-size: 8.5pt; color: #991b1b;">{{ rec.attacker_perspective }}</p>
                </div>
                {% endif %}

                <div style="background: #f0fdf4; border: 1px solid #bbf7d0; padding: 10pt; border-radius: 6pt; margin-bottom: 15pt;">
                    <h5 style="margin: 0 0 8pt 0; color: #166534; font-size: 8pt; text-transform: uppercase;">Categorized Remediation Steps</h5>
                    <ul style="font-size: 8.5pt; color: #14532d; margin: 0; padding-left: 15pt; line-height: 1.5;">
                        {% if rec.remediation is string %}
                            <li>{{ rec.remediation }}</li>
                        {% else %}
                            {% for step in rec.remediation %}
                            <li style="margin-bottom: 4pt;">{{ step }}</li>
                            {% endfor %}
                        {% endif %}
                    </ul>
                </div>

                {% if rec.references %}
                <div style="border-top: 1px dashed #e5e7eb; padding-top: 10pt;">
                    <h5 style="margin: 0 0 5pt 0; color: #6b7280; font-size: 7.5pt; text-transform: uppercase;">References</h5>
                    <ul style="font-size: 7.5pt; color: #3b82f6; margin: 0; padding-left: 15pt;">
                        {% for ref in rec.references %}
                        <li><a href="{{ ref }}" style="color: #3b82f6; word-break: break-all;">{{ ref }}</a></li>
                        {% endfor %}
                    </ul>
                </div>
                {% endif %}
            </div>
            {% else %}
            <div class="glass-card">
                 <p style="font-size: 9.5pt; color: #1f2937;">No recommendations found for this target.</p>
            </div>
            {% endfor %}
        </div>
    </body>
    </html>
    """
    
    template = Template(html_template)
    return template.render(
        username=username,
        domain=domain,
        date=datetime.now().strftime("%B %d, %Y"),
        scan_id=scan_id,
        subdomains=subdomains,
        ports=ports,
        total_vulns=total_vulns,
        critical_count=critical_count,
        risk_score=risk_score,
        host_details=host_details,
        clusters=clusters,
        tech_fingerprints=tech_fingerprints,
        anomalies=anomalies,
        model5=model5,
        model5_strategies=model5_strategies,
        vulns_m6=vulns_m6,
        recommendations=recommendations_sorted,
        ai_summary=ai_summary,
        ai_score=ai_score,
        ai_priorities=ai_priorities,
        ai_biggest_risk=ai_biggest_risk,
        logo_uri=logo_data_uri
    )

def generate_pdf_report(html_file_path):
    """
    Converts the HTML file to PDF using wkhtmltopdf.
    """
    global config
    if config is None:
        config = get_pdfkit_config()
        
    output_pdf = html_file_path.replace(".html", ".pdf")
    options = {
        'page-size': 'A4',
        'margin-top': '0mm', 'margin-right': '0mm', 'margin-bottom': '0mm', 'margin-left': '0mm',
        'encoding': "UTF-8", 'no-outline': None, 'enable-local-file-access': None, 'quiet': None
    }
    if not config: return None
    try:
        pdfkit.from_file(html_file_path, output_pdf, configuration=config, options=options)
        return output_pdf
    except Exception as e:
        print(f"[!] ERROR during PDF generation: {str(e)}")
        return None
