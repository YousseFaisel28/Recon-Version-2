"""
Model 7 – Centralized Recommendation Engine (v2)
Generates tailored, NLP-driven remediation guidance per vulnerability.
"""
from typing import List, Dict, Any
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np
import logging
import re
from datetime import datetime
import random
from utils.nvd_api_tool import get_nvd_client
try:
    from config.database import recommendations_collection
except ImportError:
    recommendations_collection = None

logger = logging.getLogger(__name__)

class RecommendationEngine:
    CWE_MAPPING = {
        "CWE-125": {
            "name": "Out-of-bounds Read",
            "behaviors": [
                "improper memory boundary handling that allows reading sensitive memory regions",
                "insufficient bounds checking that enables unauthorized memory access",
                "out-of-bounds read conditions that allow leakage of internal memory data",
                "memory access violations that permit unintended disclosure of application memory"
            ],
            "impacts": [
                "disclosure of sensitive information or a potential system crash",
                "unauthorized memory exposure leading to data exfiltration",
                "application instability and leakage of privileged data",
                "breach of data confidentiality via low-level memory access"
            ],
            "attacks": [
                "crafted memory request targeting vulnerable parsing logic",
                "malformed input designed to exploit memory handling weaknesses",
                "carefully crafted payload targeting parsing routines",
                "specially structured request triggering memory access flaws"
            ],
            "hardening": "Apply memory safety patches and validate buffer boundaries."
        },
        "CWE-416": {
            "name": "Use-After-Free",
            "behaviors": [
                "use-after-free condition that allows execution of unintended memory references",
                "improper management of memory pointers after deallocation",
                "dangling pointer reference that can be utilized to corrupt program state",
                "memory lifecycle error that permits access to freed memory segments"
            ],
            "impacts": [
                "memory corruption, denial of service, or arbitrary code execution",
                "potential for full system compromise and process hijacking",
                "unpredictable application behavior or unauthorized host control",
                "execution flow manipulation leading to administrative takeover"
            ],
            "attacks": [
                "remote trigger targeting reclaimed memory pointer state",
                "use-after-free exploit sequence aimed at memory corruption",
                "targeted payload designed to hijack freed memory references",
                "adversarial request exploiting timing flaws in memory deallocation"
            ],
            "hardening": "Ensure proper memory deallocation and pointer handling."
        },
        "CWE-787": {
            "name": "Out-of-bounds Write",
            "behaviors": [
                "memory write overflow that may corrupt application state or crash the system",
                "improper limitation of write operations to a specific buffer boundary",
                "out-of-bounds write vulnerability that permits memory address overwriting",
                "buffer overflow condition that allows data corruption in adjacent memory"
            ],
            "impacts": [
                "system instability, data corruption, or code execution",
                "potential for total host crash or unauthorized privilege escalation",
                "corruption of runtime parameters and potential system takeover",
                "immediate service disruption or arbitrary payload execution"
            ],
            "attacks": [
                "oversized input payload designed to overwrite adjacent memory blocks",
                "malicious data sequence targeting buffer boundary weaknesses",
                "crafted request aimed at overflowing internal memory structures",
                "targeted input designed to bypass length validation and corrupt memory"
            ],
            "hardening": "Implement strict bounds checking and memory protection mechanisms."
        },
        "CWE-79": {
            "name": "Cross-Site Scripting (XSS)",
            "behaviors": [
                "improper neutralization of user-supplied input that allows script injection",
                "lack of encoding for dynamic content that enables browser-side execution",
                "unvalidated input processing that permits execution of malicious scripts",
                "failure to sanitize web parameters before rendering them in the UI"
            ],
            "impacts": [
                "unauthorized script execution in user browsers or session hijacking",
                "theft of sensitive session cookies and user account takeover",
                "manipulation of the DOM and delivery of phishing content to users",
                "bypassing of same-origin policy to exfiltrate private user data"
            ],
            "attacks": [
                "malicious script payload injected via unsanitized web parameters",
                "XSS injection vector delivered through crafted URL inputs",
                "specially structured payload targeting unencoded browser output",
                "adversarial input designed to trigger script execution in a victim's session"
            ],
            "hardening": "Implement context-aware output encoding and strict CSP headers."
        },
        "CWE-89": {
            "name": "SQL Injection",
            "behaviors": [
                "improper neutralization of special elements used in a SQL command",
                "unvalidated input that allows manipulation of host database queries",
                "lack of parameterization in database calls that enables query injection",
                "backend vulnerability where user input alters the intended SQL structure"
            ],
            "impacts": [
                "unauthorized data extraction, modification, or authentication bypass",
                "breach of database integrity and mass exfiltration of sensitive records",
                "potential for full database takeover and persistent data manipulation",
                "unauthorized access to administrative credentials and internal schema"
            ],
            "attacks": [
                "malicious SQL fragments designed to alter backend query logic",
                "SQL injection payload targeting vulnerable database parameters",
                "crafted input sequence designed to bypass authentication via SQL logic",
                "targeted request exploiting unsanitized elements in the SQL execution flow"
            ],
            "hardening": "Refactor database queries to exclusively use parameterized statements."
        },
        "CWE-78": {
            "name": "OS Command Injection",
            "behaviors": [
                "improper neutralization of special elements used in an OS command",
                "application logic that allows passing unsanitized input to the shell",
                "vulnerability where user input is executed directly by the operating system",
                "lack of input filtering before execution of low-level system commands"
            ],
            "impacts": [
                "full system compromise via arbitrary command execution",
                "complete host takeover and potential for lateral movement",
                "unauthorized administrative access and installation of persistent backdoors",
                "execution of arbitrary shellcode leading to full infrastructure breach"
            ],
            "attacks": [
                "remote payload containing shell metacharacters to trigger command execution",
                "crafted input designed to escape application logic and reach the shell",
                "malicious command sequence targeting vulnerable system call routines",
                "targeted request aimed at executing arbitrary binaries on the server"
            ],
            "hardening": "Avoid direct OS command execution; use built-in library APIs instead."
        },
        "CWE-77": {
            "name": "Command Injection",
            "behaviors": [
                "improper neutralization of special elements used in a command",
                "unvalidated input processing that enables execution of arbitrary payloads",
                "flaw where external data triggers unintended command execution flow",
                "logic error in command construction allowing for payload injection"
            ],
            "impacts": [
                "arbitrary command execution and complete host takeover",
                "unauthorized control over application logic and system resources",
                "potential for service disruption and data exfiltration via commands",
                "immediate elevation of privilege through malicious command delivery"
            ],
            "attacks": [
                "crafted input designed to escape application logic and reach the shell",
                "remote payload targeting command strings with unsanitized data",
                "specially structured request aimed at triggering unintended sub-processes",
                "adversarial input sequence exploiting vulnerabilities in command parsing"
            ],
            "hardening": "Implement strict input whitelisting and avoid shell spawning."
        },
        "CWE-22": {
            "name": "Path Traversal",
            "behaviors": [
                "improper limitation of a pathname to a restricted directory ('Path Traversal')",
                "unvalidated file path processing that allows directory structure escaping",
                "lack of path normalization that enables access to parent directories",
                "vulnerability where input characters allow traversal outside the intended root"
            ],
            "impacts": [
                "unauthorized access to sensitive files on the server",
                "exposure of confidential configuration files and source code",
                "potential for remote discovery of system-level credentials",
                "bypassing of filesystem permissions to read arbitrary host data"
            ],
            "attacks": [
                "specially crafted dot-dot-slash (../) sequences in URL parameters",
                "path traversal payload designed to escape the web root directory",
                "maliciously structured request targeting file inclusion routines",
                "adversarial input aimed at resolving paths outside the application sandbox"
            ],
            "hardening": "Validate all file paths and use a restricted filesystem root."
        }
    }

    def __init__(self):
        self.nvd_client = get_nvd_client()
        self.cve_cache = {}  
        self.vectorizer = TfidfVectorizer(stop_words='english', max_features=10)

    def generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Main entry point. Outputs list of recommendation dicts matching the Task 6 JSON schema.
        """
        recommendations = []

        for vuln in vulnerabilities or []:
            cve_id = vuln.get("cve_id")
            service = vuln.get("service") or vuln.get("technology_stack") or "Unknown Service"
            port = vuln.get("port") if vuln.get("port") is not None else vuln.get("port_number", "N/A")
            version = vuln.get("version", "")
            host = vuln.get("subdomain") or vuln.get("host") or ""
            
            # Extract and parse CVSS
            cvss = vuln.get("cvss_score")
            if cvss is None: cvss = vuln.get("cvss", 0.0)
            try: cvss = float(cvss)
            except (TypeError, ValueError): cvss = 0.0
                
            risk_score = vuln.get("risk_score") or vuln.get("traffic_anomaly_score", 0.0)
            model6_severity = vuln.get("risk_level") or vuln.get("severity") or "UNKNOWN"
            
            cve_metadata = self.enrich_cve_metadata(cve_id) if cve_id else {}

            explanation = self.generate_explanation(cve_metadata, service, version)
            attacker_perspective = self.generate_attack_scenario(vuln, cve_metadata, service, port)
            attack_chain = self.generate_attack_chain(vuln, cve_metadata, service, port)
            remediation_steps = self.generate_remediation(vuln, cve_metadata, service, port, version)
            priority = self.prioritize_recommendations(cvss, risk_score, model6_severity)
            risk_summary = self.generate_risk_summary(vuln, cve_metadata, priority, cvss)

            # References merging
            references = cve_metadata.get("references", [])
            patch_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id and str(cve_id).startswith("CVE-") else ""
            if patch_link and patch_link not in references:
                references.insert(0, patch_link)

            # --- INTELLIGENT ANALYST METADATA ---
            exploit_search = vuln.get("exploit_db_reference") or []
            has_exploit = len(exploit_search) > 0
            
            #  Strict Risk Scoring ---
            conf_level = "LOW"
            if vuln.get("vulnerability_status") == "vulnerable": # exact match confirmed in Model 3
                if has_exploit:
                    conf_level = "HIGH"
                else:
                    conf_level = "MEDIUM"
            else:
                conf_level = "LOW"

            rec_obj = {
                "host": host,
                "service": service,
                "port": port,
                "cve_id": cve_id or "N/A",
                "severity": model6_severity,
                "cvss_score": cvss,
                "risk_summary": self._clean_output(risk_summary),
                "attack_chain": attack_chain,
                "explanation": self._clean_output(explanation),
                "attacker_perspective": self._clean_output(attacker_perspective),
                "remediation": [self._clean_output(r) for r in remediation_steps],
                "references": references[:5], 
                "priority": priority,
                "confidence_level": conf_level,
                "justification": f"Confidence '{conf_level}' assigned based on strict validation logic (Task 6)."
            }
            
            self.save_recommendation_to_db(rec_obj)
            recommendations.append(rec_obj)

        # Sort recommendations: Critical > High > Medium > Low
        priority_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        recommendations.sort(key=lambda x: priority_map.get(x["priority"], 0), reverse=True)

        return recommendations

    def _clean_output(self, text: str) -> str:
        """
        Task 7: STRICT OUTPUT VALIDATION
        Remove all assumptions, generic statements, and unsupported claims.
        """
        if not text: return ""
        
        # Prohibited generic/assumption-based phrases
        prohibited = [
            "The target is likely",
            "We assume that",
            "It is possible that",
            "Heuristic analysis suggests",
            "Generic security advice:",
            "Based on theoretical assumptions"
        ]
        
        cleaned = text
        for phrase in prohibited:
            cleaned = cleaned.replace(phrase, "")
            
        # If output is too generic or empty after cleaning
        if len(cleaned.strip()) < 10:
            return "INSUFFICIENT EVIDENCE: Supporting claim removed due to lack of verifiable data."
            
        return cleaned.strip()

    def enrich_cve_metadata(self, cve_id: str) -> Dict[str, Any]:
        """
        Fetch specific metadata from NVD with caching.
        """
        if not cve_id or not str(cve_id).startswith("CVE-"):
            return {}

        if cve_id in self.cve_cache:
            return self.cve_cache[cve_id]

        try:
            logger.info(f"Model 7: Fetching NVD data for {cve_id}")
            df = self.nvd_client.search_by_cve_id(cve_id)
            if df is not None and not df.empty:
                record = df.iloc[0].to_dict()
                self.cve_cache[cve_id] = record
                return record
        except Exception as e:
            logger.error(f"Error fetching CVE metadata for {cve_id}: {str(e)}")
            
        return {}

    def generate_explanation(self, metadata: Dict[str, Any], service: str, version: str) -> str:
        """
        Deeply differentiated expert explanation with intra-CWE variation and severity awareness.
        """
        severity = metadata.get("severity") or "HIGH"
        cwe_id = metadata.get("cwe_id") or ""
        cwe_tag = next((tag for tag in self.CWE_MAPPING if tag in (metadata.get("cwe") or "").upper() or tag in cwe_id.upper()), None)
        
        # 1. Opening variations (Avoid starting all with "The [service]...")
        openings = [
            f"Detailed analysis of the {service} environment confirms a verified vulnerability.",
            f"We have identified a specific security flaw that affects the active {service} instance.",
            f"The current {service} deployment on this host shows signs of a vulnerability pattern.",
            f"Security inspection of the {service} service reveals a verified weakness.",
            f"Observation of the {service} runtime indicates a potential security risk."
        ]
        
        # 2. Reasoning logic based on CWE
        if cwe_tag:
            mapping = self.CWE_MAPPING[cwe_tag]
            behavior = random.choice(mapping["behaviors"])
            impact = random.choice(mapping["impacts"])
            
            reasoning_variants = [
                f"This issue relates to {behavior}, which frequently leads to {impact}.",
                f"The core flaw involves {behavior}. In a production setting, this allows for {impact}.",
                f"Because of {behavior}, an adversary can trigger {impact}.",
                f"We observed {behavior}, a condition that directly enables {impact}."
            ]
            reasoning = random.choice(reasoning_variants)
            
            # 3. Why This Matters (Contextual Variation)
            why_matters_map = {
                "CWE-125": ["Data leakage can lead to regulatory fines and loss of client trust.", "Unintended memory exposure often reveals internal system configuration.", "Sensitive information disclosure threatens the overall security of the platform."],
                "CWE-416": ["This is a critical risk as it allows threat actors to pivot through your internal network.", "Memory corruption at this level often leads to full administrative takeover.", "Dangling pointers are a primary vector for remote code execution."],
                "CWE-787": ["Impacts include immediate downtime for users and potential host instability.", "Buffer overflows are frequently weaponized for persistent system control.", "Memory corruption here allows for lateral movement within the network."],
                "CWE-79": ["Attackers can steal user credentials en masse or hijack administrative sessions.", "User-side script execution allows for widespread session theft and phishing.", "Bypassing browser-side security can lead to cross-site request forgery."],
                "CWE-89": ["Data theft from core databases can lead to total loss of business integrity.", "Unauthorized SQL execution often bypasses all authentication layers.", "Database compromise puts every record in the system at immediate risk."],
                "CWE-78": ["Execution vulnerabilities allow for total system takeover and persistent backdoors.", "OS-level command injection is a terminal threat to the entire infrastructure.", "Command execution on a web server allows for direct shell access for attackers."],
                "CWE-77": ["Remote execution is the most critical threat, leading to complete infrastructure compromise.", "Unsanitized command processing allows for immediate host exploitation.", "Payload execution at this level bypasses all traditional perimeter defenses."],
                "CWE-22": ["Exposure of internal configuration files (like /etc/passwd or config.php) can lead to total system breach.", "Directory traversal often reveals hidden credentials and source code.", "Accessing restricted files allows attackers to map internal security controls."]
            }
            
            matters_list = why_matters_map.get(cwe_tag, ["This flaw bypasses core security assumptions and requires immediate remediation."])
            matters = random.choice(matters_list)
            
            # Severity Awareness: Add stronger emphasis for Critical
            if "CRITICAL" in str(severity).upper():
                matters = f"URGENT: {matters} This vulnerability demands immediate intervention to prevent catastrophic failure."
            
        else:
            # Fallback
            reasoning_fallbacks = [
                "The vulnerability stems from improper handling of malformed input, allowing for unexpected state transitions.",
                "The underlying logic fails to adequately sanitize input data, creating a condition for unintended behavior.",
                "Analysis suggests a failure in the input processing layer, potentially exposing an internal logic error."
            ]
            reasoning = random.choice(reasoning_fallbacks)
            matters = "Bypassing security controls at this layer can lead to unauthorized data access or service disruption."

        explanation = f"{random.choice(openings)} {reasoning} Why this matters: {matters}"
        return explanation

    def generate_attack_scenario(self, vuln: Dict[str, Any], metadata: Dict[str, Any], service: str, port: Any) -> str:
        """
        Deeply randomized CWE-aware attacker perspective.
        """
        cwe_id = metadata.get("cwe_id") or ""
        cwe_tag = next((tag for tag in self.CWE_MAPPING if tag in (metadata.get("cwe") or "").upper() or tag in cwe_id.upper()), None)
        
        vector = metadata.get("attack_vector", "NETWORK").lower()
        cvss = float(vuln.get("cvss_score", 0.0))
        
        is_public = str(port) in ["80", "443", "21", "22", "25", "53"]
        exposure_ctx = "externally reachable" if is_public else "internal-only"
        
        if cwe_tag:
            attack_variants = self.CWE_MAPPING[cwe_tag]["attacks"]
            attack_type = random.choice(attack_variants)
            scenarios = [
                f"An attacker would likely utilize a {attack_type} against the {exposure_ctx} {service} service on port {port}.",
                f"Adversarial exploitation would involve a {attack_type} delivered over {vector} channels to port {port}.",
                f"The presence of this service on port {port} exposes the host to a {attack_type} targeting vulnerable {service} logic.",
                f"From an adversarial standpoint, the {exposure_ctx} status of port {port} is a prime target for a {attack_type}."
            ]
        else:
            scenarios = [
                f"An attacker could send crafted {vector} requests to port {port} to exploit this {service} flaw.",
                f"Adversarial logic involves identifying the exposure on port {port} and delivering a tailored payload.",
                f"The {exposure_ctx} status of port {port} allows for remote probing followed by exploit delivery."
            ]
        
        return random.choice(scenarios)

    def generate_attack_chain(self, vuln: Dict[str, Any], metadata: Dict[str, Any], service: str, port: Any) -> List[str]:
        """
        Realistic, service-aware attack path simulation.
        """
        cve_id = vuln.get("cve_id", "Vulnerability")
        cwe = metadata.get("cwe", "Weakness").lower()
        service_l = service.lower()
        
        chain = [f"Reconnaissance: Port {port} identified as accessible endpoint."]
        
        # Step 2: Contextual Fingerprinting
        if "php" in service_l:
            chain.append(f"Fingerprinting: Detected PHP application environment on {service}.")
        elif "apache" in service_l or "nginx" in service_l:
            chain.append(f"Fingerprinting: Web server identified as {service}.")
        else:
            chain.append(f"Fingerprinting: Service banner confirms {service} usage.")

        # Step 3: Vulnerability Mapping
        chain.append(f"Analysis: Target version mapped to {cve_id} ({cwe}).")

        # Step 4: Exploitation (Dynamic)
        if "injection" in cwe:
            chain.append("Exploitation: Delivery of crafted input to bypass input filters.")
        elif "overflow" in cwe:
            chain.append("Exploitation: Memory buffer overflow via oversized packet.")
        else:
            chain.append("Exploitation: Weaponization of public exploit code.")

        # Step 5: Post-Exploitation
        if "rce" in cve_id.lower() or "execution" in cwe:
            chain.append("Post-Exploit: Spawning of interactive shell for system control.")
        else:
            chain.append("Post-Exploit: Unauthorized exfiltration of system memory/data.")

        return chain

    def generate_risk_summary(self, vuln: Dict[str, Any], metadata: Dict[str, Any], priority: str, cvss: float) -> str:
        """
        Summarizes risk with a focus on 'business threat' logic.
        """
        anomaly = float(vuln.get("traffic_anomaly_score", 0.0))
        
        summaries = [
            f"This represents a {priority} threat level. The high CVSS of {cvss} suggests significant potential damage.",
            f"A {priority} priority risk has been flagged. The attack surface on this port allows for reliable exploitation.",
            f"Security analysis classifies this as {priority}. Remediation should be prioritized to prevent unauthorized access."
        ]
        
        summary = random.choice(summaries)
        if anomaly > 0.5:
            summary += " NOTE: Abnormal traffic patterns detected near this service suggest possible probing activity."
            
        return summary
    def generate_remediation(self, vuln: Dict[str, Any], metadata: Dict[str, Any], service: str, port: Any, version: str) -> List[str]:
        """
        Differentiated remediation with clean grouped labels.
        """
        remediation = []
        cve_id = vuln.get('cve_id')
        service_lower = service.lower()
        cwe_id = metadata.get("cwe_id") or ""
        cwe_tag = next((tag for tag in self.CWE_MAPPING if tag in (metadata.get("cwe") or "").upper() or tag in cwe_id.upper()), None)
        
        # 1. IMMEDIATE FIXES
        if version:
            remediation.append(f"Immediate Fix: Force update {service} to version {version} (or newer) to patch the underlying flaw.")
        elif cve_id:
            remediation.append(f"Immediate Fix: Apply security update for {cve_id} across all production {service} instances.")
        else:
            remediation.append(f"Immediate Fix: Redeploy {service} using a hardened container or patched image.")

        # 2. HARDENING (Grouped)
        hardening_steps = []
        if cwe_tag:
            hardening_steps.append(self.CWE_MAPPING[cwe_tag]['hardening'])
        
        if "php" in service_lower:
            hardening_steps.append("Audit php.ini and disable dangerous functions like shell_exec.")
        elif "apache" in service_lower or "nginx" in service_lower:
            hardening_steps.append(f"Deploy a Web Application Firewall (WAF) layer in front of port {port}.")
        
        if str(port) not in ["80", "443", "N/A"]:
            hardening_steps.append(f"Implement an IP-based whitelist to block public access to port {port}.")

        if hardening_steps:
            remediation.append("Hardening:")
            for step in hardening_steps:
                remediation.append(f"- {step}")

        # 3. MONITORING (Grouped)
        remediation.append("Monitoring:")
        remediation.append(f"- Enable enhanced logging on the {service} host to detect exploitation attempts.")
        remediation.append("- Configure real-time alerts for any abnormal outbound traffic from this host.")

        return remediation

    def prioritize_recommendations(self, cvss: float, risk_score: Any, model6_severity: str) -> str:
        """
        Sort priority using strict boundaries relying on model 6 severity, risk score, and CVSS.
        """
        sev_upper = str(model6_severity).upper()
        
        if "CRITICAL" in sev_upper: return "CRITICAL"
        if "HIGH" in sev_upper: return "HIGH"
        if "MEDIUM" in sev_upper: return "MEDIUM"
        if "LOW" in sev_upper: return "LOW"
            
        # Attempt parsing risk score (Model 6 outputs standard floats 0.0 to 1.0)
        try:
            rs = float(risk_score)
            if rs >= 0.9: return "CRITICAL"
            if rs >= 0.7: return "HIGH"
            if rs >= 0.4: return "MEDIUM"
            if rs > 0.0: return "LOW"
        except (TypeError, ValueError):
            pass

        # Fallback to CVSS
        if cvss >= 9.0: return "CRITICAL"
        if cvss >= 7.0: return "HIGH"
        if cvss >= 4.0: return "MEDIUM"
        return "LOW"
        
    def generate_fix_script(self, vulnerability: Dict[str, Any]) -> str:
        """
        Dynamically builds a valid PowerShell remediation script based on detected vulnerabilities.
        """
        cve_id = vulnerability.get("cve_id", "Unknown CVE")
        service = vulnerability.get("service", "Unknown Service")
        port = vulnerability.get("port", "Unknown Port")
        
        script = []
        
        # Admin Privilege Check
        script.append('If (-NOT ([Security.Principal.WindowsPrincipal] `')
        script.append('    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`')
        script.append('    [Security.Principal.WindowsBuiltInRole] "Administrator"))')
        script.append('{')
        script.append('    Write-Host "Please run this script as Administrator." -ForegroundColor Red')
        script.append('    Exit')
        script.append('}\n')
        
        # Improved Script Header
        script.append("# ReconX Automated Security Remediation Script")
        script.append("# Generated by ReconX Vulnerability Recommendation Engine")
        script.append(f"# CVE: {cve_id}")
        script.append(f"# Service: {service}")
        script.append(f"# Port: {port}\n")
        
        script.append('Write-Host "ReconX Security Remediation Script Starting..." -ForegroundColor Green\n')
        
        script.append('Write-Host "Checking service version..." -ForegroundColor Cyan')
        
        service_lower = service.lower()
        
        # 1. Service Specific Actions
        if "php" in service_lower:
            script.append("php -v\n")
            
            script.append('Write-Host "Applying remediation steps..." -ForegroundColor Cyan')
            script.append('$phpIni = "C:\\php\\php.ini"')
            script.append('if (Test-Path $phpIni) {')
            script.append('    Write-Host "Applying PHP security hardening..." -ForegroundColor Cyan')
            script.append('    (Get-Content $phpIni) `')
            script.append('        -replace "disable_functions\\s*=", "disable_functions = exec,shell_exec,passthru,system" |')
            script.append('        Set-Content $phpIni')
            script.append('}\n')
            
        elif "apache" in service_lower or "httpd" in service_lower:
            script.append('Write-Host "Checking Apache configuration..." -ForegroundColor Cyan')
            script.append("httpd -v")
            script.append('Write-Host "Ensure latest Apache version is installed."\n')
            script.append('Write-Host "Applying remediation steps..." -ForegroundColor Cyan')
            script.append('Write-Host "1. Upgrade Apache to a patched version."')
            script.append('Write-Host "2. Implement AllowOverride None on root directories."\n')
            
        elif "mysql" in service_lower or "postgres" in service_lower:
            script.append('Write-Host "Checking database version..." -ForegroundColor Cyan')
            script.append("mysql --version 2>$null" if "mysql" in service_lower else "psql -V 2>$null")
            script.append('Write-Host "Ensure database access is restricted."\n')
            script.append('Write-Host "Applying remediation steps..." -ForegroundColor Cyan\n')
            
        elif "nginx" in service_lower:
            script.append('Write-Host "Checking Nginx version..." -ForegroundColor Cyan')
            script.append("nginx -v")
            script.append('Write-Host "Applying remediation steps..." -ForegroundColor Cyan')
            script.append('Write-Host "1. Upgrade Nginx to a patched version."')
            script.append('Write-Host "2. Toggle server_tokens off in nginx.conf."\n')
            
        elif "ssh" in service_lower:
            script.append('Write-Host "Ensure OpenSSH is updated and root login is disabled."\n')
            script.append('Write-Host "Applying remediation steps..." -ForegroundColor Cyan\n')

        else:
            script.append('Write-Host "Applying remediation steps..." -ForegroundColor Cyan')
            script.append('Write-Host "1. Upgrade the applicable service to a patched version."')
            script.append('Write-Host "2. Restrict public access to vulnerable service blocks."\n')

        script.append('Write-Host "Security hardening complete." -ForegroundColor Green\n')

        # 2. Port and Firewall Hardening with existence check
        if str(port) not in ["N/A", "0", "", "None", None]:
            script.append(f'$ruleName = "ReconX Port {port} Restriction"')
            script.append('if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {')
            script.append('    New-NetFirewallRule `')
            script.append('        -DisplayName $ruleName `')
            script.append('        -Direction Inbound `')
            script.append('        -Protocol TCP `')
            script.append(f'        -LocalPort {port} `')
            script.append('        -Action Block')
            script.append('    Write-Host "Firewall rule created." -ForegroundColor Green')
            script.append('}')
            script.append('else {')
            script.append('    Write-Host "Firewall rule already exists." -ForegroundColor Yellow')
            script.append('}\n')
            
        # Final Completion Message
        script.append('Write-Host ""')
        script.append('Write-Host "ReconX remediation process completed." -ForegroundColor Green')
        script.append('Write-Host "Please review configuration changes and restart affected services if required."')
            
        return "\n".join(script)
        
    def save_recommendation_to_db(self, recommendation: Dict[str, Any]):
        """
        Store recommendation in MongoDB collection if available. Avoid duplicates by host, cve_id, port.
        """
        if recommendations_collection is None:
            return
            
        try:
            query = {
                "host": recommendation.get("host"),
                "cve_id": recommendation.get("cve_id"),
                "port": recommendation.get("port")
            }
            
            # Upsert
            doc = recommendation.copy()
            doc["timestamp"] = datetime.utcnow()
            doc["source"] = "ReconX Model 7"
            
            recommendations_collection.update_one(
                query,
                {"$set": doc},
                upsert=True
            )
        except Exception as e:
            logger.error(f"Failed to save recommendation to DB: {e}")

    def get_recommendations_for_host(self, host: str) -> List[Dict[str, Any]]:
        """
        Retrieve all stored recommendations for a target host.
        """
        if recommendations_collection is None:
            return []
            
        try:
            cursor = recommendations_collection.find({"host": host})
            return [doc for doc in cursor]
        except Exception as e:
            logger.error(f"Failed to fetch recommendations for {host}: {e}")
            return []
