import os
import sys
from utils.report_generator import generate_html_report, generate_pdf_report

# Mock Data to simulate a full ReconX scan result (syncing with website fields)
mock_scan_results = {
    "raw_docs": [
        {"subdomain": "api.example.com", "open_ports": [{"port": "443", "service": "https"}]},
        {"subdomain": "dev.example.com", "open_ports": [{"port": "80", "service": "http"}]},
        {"subdomain": "mail.example.com", "open_ports": []}
    ],
    "hosts": [
        {"domain": "api.example.com", "ports": [{"port": "443", "service": "https", "version": "nginx 1.18.0"}]},
        {"domain": "dev.example.com", "ports": [{"port": "80", "service": "http", "version": "Apache 2.4.41"}]}
    ],
    "clusters": [
        {"cluster_id": 1, "size": 2, "examples": ["api.example.com", "dev.example.com"]},
        {"cluster_id": 2, "size": 1, "examples": ["mail.example.com"]}
    ],
    "technology_fingerprints": [
        {
            "url": "https://api.example.com",
            "technologies": [
                {"technology": "nginx", "version": "1.18.0", "cves": [
                    {"cve": "CVE-2021-23017", "cvss": 8.1, "severity": "High"}
                ]},
                {"technology": "OpenSSL", "version": "1.1.1u", "cves": []}
            ]
        },
        {
            "url": "http://dev.example.com",
            "technologies": [
                {"technology": "Apache", "version": "2.4.41", "cves": [
                    {"cve": "CVE-2021-41773", "cvss": 7.5, "severity": "High"},
                    {"cve": "CVE-2021-42013", "cvss": 7.5, "severity": "High"}
                ]}
            ]
        }
    ],
    "http_anomalies": [
        {
            "subdomain": "api.example.com",
            "model4_result": {
                "status": "safe",
                "traffic_data": {"unique_ips": 12, "tcp_syn_count": 45, "packet_count": 1200}
            }
        },
        {
            "subdomain": "dev.example.com",
            "model4_result": {
                "status": "suspicious",
                "traffic_data": {"unique_ips": 1500, "tcp_syn_count": 8000, "packet_count": 50000}
            }
        }
    ],
    "model5": {
        "strategies": [
            {
                "cve_id": "CVE-2021-44228",
                "evidence_status": "VULNERABLE",
                "explanation": "Log4Shell RCE path available via JNDI injection in user-agent header.",
                "attack_chain": ["Recon", "Fingerprint", "Payload Injection", "RCE"],
                "exploit_db_reference": [{"title": "Log4j 2.14.1 - RCE", "url": "https://www.exploit-db.com/exploits/50592"}]
            }
        ]
    },
    "model6": [
        {"cve_id": "CVE-2021-44228", "service": "Log4j", "port": 443, "cvss": 10.0, "risk_level": "Critical"},
        {"cve_id": "CVE-2021-23017", "service": "nginx", "port": 443, "cvss": 8.1, "risk_level": "High"},
        {"cve_id": "CVE-2021-41773", "service": "Apache", "port": 80, "cvss": 7.5, "risk_level": "High"}
    ],
    "recommendations": [
        {
            "service": "Web Server",
            "port": 443,
            "host": "api.example.com",
            "severity": "CRITICAL",
            "explanation": "Critical remote code execution vulnerability in Log4j.",
            "attacker_perspective": "Gaining full server control through logging injection.",
            "remediation": ["Immediate Fix: Update to Log4j 2.17.1", "Hardening: Set log4j2.formatMsgNoLookups=true"],
            "cvss_score": 10.0,
            "cve_id": "CVE-2021-44228"
        }
    ]
}

def verify():
    domain = "example.com"
    username = "Test User"
    scan_id = "test-scan-full-sync"
    
    print("[*] Generating Full Feature HTML Report...")
    html_content = generate_html_report(mock_scan_results, domain, username, scan_id)
    
    report_dir = os.path.join(os.getcwd(), "reports")
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)
        
    html_path = os.path.join(report_dir, f"report_{scan_id}.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[+] HTML Report generated: {html_path}")

    print("[*] Converting to PDF...")
    pdf_path = generate_pdf_report(html_path)
    if pdf_path:
        print(f"[+] PDF Report generated successfully: {pdf_path}")
    else:
        print("[!] PDF Generation failed.")

if __name__ == "__main__":
    verify()
