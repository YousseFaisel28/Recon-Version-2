"""
Technology fingerprinting from HTTP headers, banners, and nmap output
"""
import requests
import re
from typing import Dict, List, Optional

def extract_http_headers(url):
    """Extract HTTP headers from a URL."""
    headers_info = {}
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        headers_info = {
            "server": response.headers.get("Server", ""),
            "x-powered-by": response.headers.get("X-Powered-By", ""),
            "x-aspnet-version": response.headers.get("X-AspNet-Version", ""),
            "x-php-version": response.headers.get("X-PHP-Version", ""),
            "x-runtime": response.headers.get("X-Runtime", ""),
            "x-framework": response.headers.get("X-Framework", ""),
            "content-type": response.headers.get("Content-Type", ""),
            "all_headers": dict(response.headers)
        }
    except Exception:
        pass
    return headers_info


def extract_technologies_from_headers(headers_info):
    """Extract technology information from HTTP headers."""
    technologies = []
    
    # Server header
    server = headers_info.get("server", "")
    if server:
        # Parse "Apache/2.4.41" or "nginx/1.18.0"
        match = re.match(r'([^/]+)(?:/(.+))?', server)
        if match:
            name = match.group(1).strip()
            version = match.group(2).strip() if match.group(2) else ""
            technologies.append({
                "name": name,
                "version": version,
                "category": "Web Server",
                "source": "Inferred via application-layer response"
            })
    
    # X-Powered-By header
    powered_by = headers_info.get("x-powered-by", "")
    if powered_by:
        match = re.match(r'([^/]+)(?:/(.+))?', powered_by)
        if match:
            name = match.group(1).strip()
            version = match.group(2).strip() if match.group(2) else ""
            technologies.append({
                "name": name,
                "version": version,
                "category": "Framework",
                "source": "Inferred via application-layer response"
            })
    
    # X-PHP-Version
    php_version = headers_info.get("x-php-version", "")
    if php_version:
        technologies.append({
            "name": "PHP",
            "version": php_version.strip(),
            "category": "Language",
            "source": "Inferred via application-layer response"
        })
    
    # X-AspNet-Version
    aspnet = headers_info.get("x-aspnet-version", "")
    if aspnet:
        technologies.append({
            "name": "ASP.NET",
            "version": aspnet.strip(),
            "category": "Framework",
            "source": "Inferred via application-layer response"
        })
    
    return technologies


def extract_technologies_from_nmap(nmap_data):
    """
    Extract technology information from nmap service detection.
    nmap_data should be from nmap PortScanner output.
    """
    technologies = []
    
    if not nmap_data:
        return technologies
    
    # nmap structure: nm[ip][proto][port]
    for ip in nmap_data.get("all_hosts", []):
        for proto in nmap_data[ip].get("all_protocols", []):
            ports = nmap_data[ip][proto]
            for port, port_data in ports.items():
                if port_data.get("state") == "open":
                    # Service name
                    service = port_data.get("name", "")
                    product = port_data.get("product", "")
                    version = port_data.get("version", "")
                    
                    if product:
                        technologies.append({
                            "name": product,
                            "version": version,
                            "category": "Service",
                            "source": f"nmap-{port}",
                            "port": int(port)
                        })
                    elif service and service not in ["http", "https", "tcp", "udp"]:
                        technologies.append({
                            "name": service,
                            "version": "",
                            "category": "Service",
                            "source": f"nmap-{port}",
                            "port": int(port)
                        })
    
    return technologies


def fingerprint_technologies(url, nmap_data=None, whatweb_result=None):
    """
    Comprehensive technology fingerprinting from multiple sources.
    Returns combined technology list.
    """
    all_technologies = []
    
    # Extract from HTTP headers
    headers = extract_http_headers(url)
    header_techs = extract_technologies_from_headers(headers)
    all_technologies.extend(header_techs)
    
    # Extract from WhatWeb if available
    if whatweb_result:
        from utils.whatweb_tool import extract_technologies_from_whatweb
        whatweb_techs = extract_technologies_from_whatweb(whatweb_result)
        all_technologies.extend(whatweb_techs)
    
    # Extract from nmap if available
    if nmap_data:
        nmap_techs = extract_technologies_from_nmap(nmap_data)
        all_technologies.extend(nmap_techs)
    
    # Remove duplicates (same name and version)
    seen = set()
    unique_techs = []
    for tech in all_technologies:
        key = (tech["name"].lower(), tech.get("version", "").lower())
        if key not in seen:
            seen.add(key)
            unique_techs.append(tech)
    
    return unique_techs

