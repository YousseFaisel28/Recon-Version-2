import os
from utils.report_generator import generate_html_report, generate_pdf_report

# Mock Data with MISSING and NONE fields to test stability
crash_test_data = {
    "raw_docs": None, # Critical fail point
    "hosts": [
        {"domain": "broken.test", "ports": None} # Nested fail point
    ],
    "clusters": [
        {"cluster_id": 1, "size": 0, "examples": None} # Nested fail point
    ],
    "technology_fingerprints": [
        {
            "url": "http://broken.test",
            "technologies": None # Nested fail point
        }
    ],
    "http_anomalies": [
        {
            "subdomain": "broken.test",
            "model4_result": None # Critical fail point
        }
    ],
    "model5": None, # Root fail point
    "model6": [],
    "recommendations": []
}

def crash_test():
    domain = "crash-test.com"
    username = "Stress Tester"
    scan_id = "test-crash-recovery"
    
    print("[*] Running Stability Crash Test...")
    try:
        html_content = generate_html_report(crash_test_data, domain, username, scan_id)
        print("[+] SUCCESS: HTML generated despite missing data.")
        
        report_dir = os.path.join(os.getcwd(), "reports")
        if not os.path.exists(report_dir): os.makedirs(report_dir)
        html_path = os.path.join(report_dir, f"report_{scan_id}.html")
        with open(html_path, "w", encoding="utf-8") as f: f.write(html_content)
        
        print("[*] Verifying PDF generation...")
        pdf_path = generate_pdf_report(html_path)
        if pdf_path:
            print(f"[+] SUCCESS: PDF generated: {pdf_path}")
    except Exception as e:
        print(f"[!] FAILED: Report engine crashed: {str(e)}")

if __name__ == "__main__":
    crash_test()
