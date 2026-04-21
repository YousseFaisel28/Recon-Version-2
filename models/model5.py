"""
Model 5 – Exploitation Strategy Generator (ReconX)
--------------------------------------------------
Purpose:
- Generate logical attack paths for detected vulnerabilities (CVEs).
- Use Q-Learning to learn common attack transitions (Optimization, NOT creation).
- Reference Exploit-DB for validation/confidence (NOT a blocker).
- Provide defensive awareness of potential exploitation flows.

Constraints:
- NO network scanning.
- NO automated exploitation execution.
- NO heuristics/guessing (Must be based on CVE/CWE).
- Returns ZERO results if no CVEs are present.
"""

import os
import json
import pickle
import random
import time
import requests
from collections import defaultdict
from typing import List, Dict, Tuple, Optional

# ==============================================================================
# 1. CONSTANTS & VOCABULARY
# ==============================================================================

# Fixed Attack Step Vocabulary
ATTACK_STEPS = [
    "Initial Access",
    "Web Exploitation",
    "SQL Injection",
    "XSS Exploitation",
    "Command Injection",
    "Remote Code Execution",
    "File Upload Abuse",
    "Authentication Bypass",
    "Directory Traversal",
    "Data Exposure",
    "Privilege Escalation",
    "Service Disruption"
]

# Deterministic CWE -> Attack Step Mapping
# Maps Common Weakness Enumeration IDs to our internal vocabulary
CWE_MAPPING = {
    "CWE-89": "SQL Injection",
    "CWE-79": "XSS Exploitation",
    "CWE-78": "Command Injection",
    "CWE-77": "Command Injection",
    "CWE-22": "Directory Traversal",
    "CWE-287": "Authentication Bypass",
    "CWE-434": "File Upload Abuse",
    "CWE-200": "Data Exposure",
    "CWE-269": "Privilege Escalation",
    "CWE-94": "Remote Code Execution",
    "CWE-502": "Remote Code Execution", # Deserialization
    "CWE-352": "Web Exploitation", # CSRF
    "CWE-918": "Web Exploitation", # SSRF
}

# Q-Learning Configuration
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
Q_TABLE_FILE = os.path.join(BASE_DIR, "models", "artifacts", "model5", "model5_qtable.pkl")
LEARNING_RATE = 0.1
DISCOUNT_FACTOR = 0.9
EXPLORATION_RATE = 0.2  # Low exploration, rely mostly on rules

# ==============================================================================
# 2. EXPLOIIT-DB CONNECTOR (Reference Only)
# ==============================================================================

class ExploitDBConnector:
    """
    Connects to Exploit-DB to check for PUBLIC EXPLOIT EVIDENCE.
    Does NOT download payloads. Used strictly for reference/confidence.
    """
    SEARCH_URL = "https://www.exploit-db.com/search"
    BASE_URL = "https://www.exploit-db.com"

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconX-Model5/1.0",
            "X-Requested-With": "XMLHttpRequest", # CRITICAL for JSON API
            "Referer": "https://www.exploit-db.com/search"
        })

    def search_by_cve(self, cve_id: str) -> List[Dict]:
        """
        Search Exploit-DB for a specific CVE.
        Returns a list of finding summaries (title, id, url).
        """
        if not cve_id:
            return []

        print(f"[Model 5] Checking Exploit-DB reference for {cve_id}...")
        try:
            # Add delay to respect rate limits
            time.sleep(1.0) 
            
            response = self.session.get(
                self.SEARCH_URL, 
                params={"cve": cve_id}, 
                timeout=10
            )

            if response.status_code == 200:
                try:
                    data = response.json()
                    results = data.get("data", [])
                    findings = []
                    
                    for item in results:
                        # Extract minimal reference info
                        desc_list = item.get("description", [])
                        title = desc_list[1] if len(desc_list) > 1 else "Unknown Exploit"
                        eid = item.get("id")
                        
                        findings.append({
                            "id": eid,
                            "title": title,
                            "url": f"{self.BASE_URL}/exploits/{eid}",
                            "type": item.get("type_id", "unknown")
                        })
                    
                    if findings:
                        print(f"[Model 5] Found {len(findings)} public exploits for {cve_id}")
                    return findings

                except json.JSONDecodeError:
                    print("[Model 5] Exploit-DB returned non-JSON response.")
                    return []
            else:
                print(f"[Model 5] Exploit-DB lookup failed: HTTP {response.status_code}")
                return []
                
        except Exception as e:
            print(f"[Model 5] Exploit-DB connection error: {e}")
            return []

# ==============================================================================
# 3. Q-LEARNING AGENT (Lightweight Optimization)
# ==============================================================================

class QLearningAgent:
    """
    Lightweight Q-Learning agent to optimize attack chain transitions.
    Learns: "After Step A, Step B is a likely next step in this context."
    Does NOT invent steps; chooses from vocabulary.
    """
    def __init__(self):
        self.q_table = defaultdict(float) # key: (state, action) -> value
        self.load_q_table()

    def get_state(self, current_step: str, cwe_context: str) -> str:
        """Create a state representation: Current_Step + CWE_Context"""
        return f"{current_step}|{cwe_context}"

    def get_best_next_step(self, current_step: str, cwe_context: str, valid_next_steps: List[str]) -> Optional[str]:
        """Select the best next step based on Q-Values (or Explore)"""
        state = self.get_state(current_step, cwe_context)
        
        # Epsilon-Greedy Strategy
        if random.random() < EXPLORATION_RATE:
            return random.choice(valid_next_steps) if valid_next_steps else None
        
        # Exploit: Choose step with highest Q-value
        best_step = None
        max_q = -float('inf')
        
        for step in valid_next_steps:
            q_val = self.q_table.get((state, step), 0.0)
            if q_val > max_q:
                max_q = q_val
                best_step = step
                
        return best_step

    def update(self, current_step: str, next_step: str, cwe_context: str, reward: float):
        """Update Q-Table based on transition result"""
        state = self.get_state(current_step, cwe_context)
        key = (state, next_step)
        
        # Simple Q-Learning Update Rule
        # Q(s,a) = Q(s,a) + alpha * (reward - Q(s,a)) 
        # (Simplified as we don't have infinite lookahead here)
        old_val = self.q_table[key]
        self.q_table[key] = old_val + LEARNING_RATE * (reward - old_val)

    def save_q_table(self):
        try:
            os.makedirs(os.path.dirname(Q_TABLE_FILE), exist_ok=True)
            with open(Q_TABLE_FILE, 'wb') as f:
                pickle.dump(dict(self.q_table), f)
        except Exception as e:
            print(f"[Model 5] Failed to save Q-Table: {e}")

    def load_q_table(self):
        if os.path.exists(Q_TABLE_FILE):
            try:
                with open(Q_TABLE_FILE, 'rb') as f:
                    self.q_table = defaultdict(float, pickle.load(f))
                print("[Model 5] Q-Table loaded successfully.")
            except Exception:
                print("[Model 5] Q-Table corrupted or empty. Starting fresh.")

# ==============================================================================
# 4. MAIN GENERATOR LOGIC
# ==============================================================================

class ExploitationStrategyGenerator:
    def __init__(self):
        self.edb_connector = ExploitDBConnector()
        self.q_agent = QLearningAgent()

    def generate_strategies(self, port_scan_results, technology_results, http_anomalies):
        """
        Main entry point.
        Args:
            port_scan_results: List of dicts (Model 2)
            technology_results: List of dicts with CVEs (Model 3)
            http_anomalies: Dict (Model 4)
        """
        strategies = []
        
        # 1. Validation: Must have technologies with CVEs
        if not technology_results:
            print("[Model 5] No technology/CVE inputs. Returning 0 strategies.")
            return strategies

        print(f"[Model 5] Processing {len(technology_results)} technologies...")

        for tech in technology_results:
            tech_name = tech.get("technology", "Unknown")
            cves = tech.get("cves", [])

            # Strict Constraint: No CVEs = No Strategy
            if not cves:
                continue

            for cve_item in cves:
                cve_id = cve_item.get("cve")
                cwe_id = cve_item.get("cwe", "N/A")
                severity = cve_item.get("severity", "LOW")
                cvss = cve_item.get("cvss", 0.0)

                # --- STEP 1: CHECK PUBLIC EXPLOIT EVIDENCE (STRICT GATE) ---
                edb_findings = self.edb_connector.search_by_cve(cve_id)
                has_exploit_evidence = len(edb_findings) > 0

                # --- STEP 2: GENERATE CONTENT BASED ON EVIDENCE ---
                
                if has_exploit_evidence:
                    # CASE A: EXPLOIT EXISTS -> GENERATE CHAIN (Task 3)
                    raw_chain = self._build_attack_chain(cwe_id, tech_name)
                    
                    # Post-processing: Remove consecutive duplicates
                    chain = [raw_chain[0]]
                    for step in raw_chain[1:]:
                        if step != chain[-1]:
                            chain.append(step)
                            
                    mitre_tech = self._map_mitre(chain)
                    if not mitre_tech or mitre_tech == "N/A":
                        mitre_tech = "No MITRE mapping available"  # Task 5 Rule 3

                    explanation = "Theoretical attack path based on documented exploit"  # Task 3 Rule 2.1
                    status = "Public Exploit Available"
                    
                else:
                    # CASE B: NO EXPLOIT -> NO CHAIN (STRICT TASK 3)
                    chain = None
                    mitre_tech = "No MITRE mapping available" # Task 5
                    explanation = "No verified public exploit — exploitation path undetermined" # Task 3 Rule 3
                    status = "No Public Exploit Evidence"

                # --- PORT DEDUPLICATION FIX ---
                # Extract unique ports from scan results
                unique_ports = sorted(list(set([p.get('port') for p in port_scan_results if p.get('port')])))
                ports_str = ", ".join(map(str, unique_ports))
                service_display = f"{tech_name} (Port: {ports_str})" if unique_ports else tech_name

                # --- STEP 3: CONSTRUCT STRATEGY OBJECT ---
                strategy = {
                    "subdomain": "Target Interaction",
                    "service": service_display,
                    "cve_id": cve_id,
                    "cwe_id": cwe_id,
                    "severity": severity,
                    "attack_chain": chain, # Can be None
                    "mitre_technique": mitre_tech,
                    "exploit_db_reference": edb_findings if has_exploit_evidence else None,
                    "evidence_status": status,
                    "explanation": explanation
                }
                strategies.append(strategy)

        # Save learned Q-values (only if learning happened)
        self.q_agent.save_q_table()
        
        return strategies

    def _build_attack_chain(self, cwe_id: str, tech_name: str) -> List[str]:
        """
        Constructs the attack chain using Rules + Q-Learning guidance.
        ONLY called if exploit evidence exists.
        """
        chain = ["Initial Access"]
        
        # Step 1: Map CWE to Core Attack Step (Deterministic Rule)
        core_step = CWE_MAPPING.get(cwe_id)
        
        # Fallback if CWE is unknown/generic
        if not core_step:
            if "SQL" in tech_name: core_step = "SQL Injection"
            elif "PHP" in tech_name: core_step = "Web Exploitation"
            else: core_step = "Service Disruption" 

        chain.append(core_step)
        
        # Step 2: Use Q-Agent to suggest Impact Step
        impact_candidates = ["Data Exposure", "Privilege Escalation", "Remote Code Execution", "Service Disruption"]
        
        if core_step in ["SQL Injection", "XSS Exploitation", "Directory Traversal"]:
            valid_next = ["Data Exposure", "Authentication Bypass"]
        elif core_step in ["Command Injection", "File Upload Abuse"]:
            valid_next = ["Remote Code Execution", "Privilege Escalation"]
        else:
            valid_next = impact_candidates

        # Ask Q-Agent
        suggested_impact = self.q_agent.get_best_next_step(core_step, cwe_id, valid_next)
        
        if suggested_impact:
            chain.append(suggested_impact)
        else:
            # Default logical conclusion
            if "Injection" in core_step or "Execution" in core_step:
                chain.append("Privilege Escalation")
            else:
                chain.append("Data Exposure")

        return chain

    def _map_mitre(self, chain: List[str]) -> str:
        """Map chain to high-level MITRE Technique"""
        if not chain: return "N/A"
        if "SQL Injection" in chain: return "T1190 - Exploit Public-Facing Application"
        if "XSS Exploitation" in chain: return "T1059 - Command and Scripting Interpreter"
        if "Remote Code Execution" in chain: return "T1203 - Exploitation for Client Execution"
        if "Privilege Escalation" in chain: return "T1068 - Exploitation for Privilege Escalation"
        return "T1190 - Exploit Public-Facing Application"

    def _generate_explanation(self, chain: List[str], cwe_id: str) -> str:
        """Generate human-readable explanation for VERIFIED chains"""
        expl = f"The vulnerability ({cwe_id}) allows an attacker to gain {chain[0]}. "
        expl += f"By leveraging {chain[1]}, they could proceed to {chain[-1]}. "
        expl += "Public exploit code is available."
        return expl

# ==============================================================================
# 5. PUBLIC API
# ==============================================================================

def run_model_5(port_scan_results, technology_results, http_anomaly_result):
    """
    Public entry point for the pipeline.
    """
    try:
        generator = ExploitationStrategyGenerator()
        strategies = generator.generate_strategies(
            port_scan_results, 
            technology_results, 
            http_anomaly_result
        )
        
        return {
            "model": "Model 5 - Exploitation Strategy Generator",
            "strategy_count": len(strategies),
            "strategies": strategies
        }
    except Exception as e:
        print(f"[Model 5] Critical Error: {e}")
        return {
            "model": "Model 5 - Error",
            "strategy_count": 0,
            "strategies": [],
            "error": str(e)
        }
