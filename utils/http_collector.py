"""
ReconX - HTTP Feature Collector
Used by Model 4 (Anomaly Detection)

This file is NOT machine learning.
It collects REAL HTTP behavior and converts it to numeric features.
"""

import requests
import math
from collections import Counter


# Security headers we expect on a well-configured site
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security"
]


# -------------------------------
# Entropy Calculation
# -------------------------------
def calculate_entropy(counter: Counter) -> float:
    """
    Calculate Shannon entropy for HTTP status codes
    """
    total = sum(counter.values())
    if total == 0:
        return 0.0

    entropy = 0.0
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p)

    return entropy


# -------------------------------
# Main Feature Collector
# -------------------------------
def collect_http_features(url: str) -> dict:
    """
    Sends real HTTP request and extracts behavior features
    """

    try:
        response = requests.get(
            url,
            timeout=6,
            allow_redirects=True,
            headers={
                "User-Agent": "ReconX-Scanner/1.0"
            }
        )

        headers = response.headers

        # Count missing security headers
        missing_headers = sum(
            1 for h in SECURITY_HEADERS if h not in headers
        )

        # CORS wildcard check
        cors_wildcard = headers.get("Access-Control-Allow-Origin") == "*"

        # Server version exposure
        server_exposed = "Server" in headers

        # Cookie security flags
        insecure_cookies = 0
        for cookie in response.cookies:
            if not cookie.secure or not cookie.has_nonstandard_attr("HttpOnly"):
                insecure_cookies += 1

        # HTTP status behavior
        status_counter = Counter([response.status_code])

        # Build feature dictionary
        features = {
            "missing_headers": missing_headers,
            "cors_wildcard": cors_wildcard,
            "server_exposed": server_exposed,
            "insecure_cookies": insecure_cookies,
            "response_size_kb": len(response.content) / 1024,
            "error_rate": 1.0 if response.status_code >= 400 else 0.0,
            "status_entropy": calculate_entropy(status_counter)
        }

        return features

    except Exception as e:
        # If site blocks requests or times out → treat as abnormal behavior
        return {
            "missing_headers": len(SECURITY_HEADERS),
            "cors_wildcard": False,
            "server_exposed": False,
            "insecure_cookies": 0,
            "response_size_kb": 0.0,
            "error_rate": 1.0,
            "status_entropy": 0.0
        }
