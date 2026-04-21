"""
SSRF Protection Utility
========================
Validates scan target domains to prevent Server-Side Request Forgery.
Blocks internal IPs, loopback, link-local, and reserved ranges.
"""

import ipaddress
import socket
from typing import List


# Blocked IP ranges (RFC 1918 + loopback + link-local + reserved)
BLOCKED_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),         # Private Class A
    ipaddress.ip_network("172.16.0.0/12"),      # Private Class B
    ipaddress.ip_network("192.168.0.0/16"),     # Private Class C
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local
    ipaddress.ip_network("0.0.0.0/8"),          # Current network
    ipaddress.ip_network("100.64.0.0/10"),      # Shared address space
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
]

# Blocked hostnames
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",      # Cloud metadata
    "169.254.169.254",               # AWS/GCP metadata endpoint
}


def is_safe_target(domain: str) -> tuple:
    """
    Check if a domain is safe to scan (not internal/private).

    Returns:
        (is_safe: bool, reason: str)
    """
    domain = domain.strip().lower()

    # 1. Blocked hostnames
    if domain in BLOCKED_HOSTNAMES:
        return False, f"Blocked hostname: {domain}"

    # 2. Reject raw IP addresses
    try:
        ip = ipaddress.ip_address(domain)
        for net in BLOCKED_RANGES:
            if ip in net:
                return False, f"IP address {domain} is in a restricted range"
        # Even if not in blocked range, we prefer domain names for scans
        return True, "OK"
    except ValueError:
        pass  # Not an IP, it's a domain name — continue checks

    # 3. Resolve domain and check resolved IPs
    try:
        resolved_ips = socket.getaddrinfo(domain, None)
        for entry in resolved_ips:
            ip_str = entry[4][0]
            try:
                ip = ipaddress.ip_address(ip_str)
                for net in BLOCKED_RANGES:
                    if ip in net:
                        return False, f"Domain {domain} resolves to restricted IP {ip_str}"
            except ValueError:
                continue
    except socket.gaierror:
        # DNS resolution failed — domain might not exist, but that's
        # not an SSRF issue. Let the scanner handle it.
        pass

    return True, "OK"
