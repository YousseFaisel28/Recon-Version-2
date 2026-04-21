"""
WhatWeb tool for technology fingerprinting
Extracts technology information from web servers
"""
import subprocess
import json
import re
from concurrent.futures import ThreadPoolExecutor

def run_whatweb(url, timeout=30):
    """
    Run WhatWeb to detect technologies on a URL.
    Returns technology fingerprint data.
    """
    try:
        # WhatWeb command with JSON output
        cmd = [
            "whatweb",
            url,
            "--log-json=-",
            "--no-errors",
            "--quiet"
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        if result.returncode == 0 and result.stdout:
            # Parse JSON output (WhatWeb outputs one JSON object per line)
            technologies = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        tech_data = json.loads(line)
                        technologies.append(tech_data)
                    except json.JSONDecodeError:
                        continue
            return {"status": "success", "technologies": technologies}
        else:
            return {"status": "no_results", "technologies": []}
            
    except FileNotFoundError:
        # WhatWeb not installed, return empty
        return {"status": "not_installed", "technologies": []}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "technologies": []}
    except Exception as e:
        return {"status": "error", "error": str(e), "technologies": []}


def extract_technologies_from_whatweb(whatweb_result):
    """
    Extract technology names and versions from WhatWeb output.
    Returns: [{"name": "Apache", "version": "2.4.41", "category": "Web Server"}, ...]
    """
    technologies = []
    
    if whatweb_result.get("status") != "success":
        return technologies
    
    for tech_data in whatweb_result.get("technologies", []):
        # WhatWeb structure: {"name": "Technology", "version": "1.0", ...}
        tech_name = tech_data.get("name", "")
        version = tech_data.get("version", "")
        category = tech_data.get("category", "Unknown")
        
        if tech_name:
            technologies.append({
                "name": tech_name,
                "version": version,
                "category": category,
                "raw_data": tech_data
            })
    
    return technologies


def run_whatweb_parallel(urls, max_workers=10):
    """Run WhatWeb on multiple URLs in parallel."""
    results = {}
    
    def _scan_url(url):
        return (url, run_whatweb(url))
    
    if not urls:
        return results
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_scan_url, url): url for url in urls}
        for future in futures:
            url = futures[future]
            try:
                result = future.result()
                results[url] = result
            except Exception as e:
                results[url] = {"status": "error", "error": str(e), "technologies": []}
    
    return results

