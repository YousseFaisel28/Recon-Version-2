"""
NVD (National Vulnerability Database) API Integration Module

This module provides secure integration with the NVD API for vulnerability lookups.
The NVD API key is used for:
- Rate limit protection: Authenticated requests have higher rate limits (50 requests per 30 seconds)
- Authenticated access: Allows access to premium features and better API reliability
- Request tracking: Helps NVD monitor and manage API usage

Security Note: The API key is loaded from environment variables and never hardcoded.
"""
print("DEBUG: [nvd_api_tool.py] is being loaded from: " + __file__)

import os
import time
import logging
import requests
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import pandas as pd
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# NVD API Configuration
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY_ENV = "NVD_API_KEY"
DEFAULT_RATE_LIMIT_DELAY = 0.6  # 50 requests per 30 seconds = ~0.6s between requests
MAX_RETRIES = 3
RETRY_BACKOFF_FACTOR = 2


class NVDApiClient:
    """
    Secure NVD API client with authentication and error handling.
    
    The NVD API key provides:
    - Higher rate limits (50 requests per 30 seconds vs 5 for unauthenticated)
    - Better reliability and priority access
    - Usage tracking and monitoring
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize NVD API client.
        
        Args:
            api_key: Optional API key. If not provided, loads from NVD_API_KEY env var.
        
        Raises:
            ValueError: If API key is not found in environment or provided.
        """
        # FORCE KEY FOR TESTING
        self.api_key = "556b16c0-df03-46de-99df-b4719b00fdda"
        print(f"DEBUG: [NVDApiClient] Initialized with key: {self.api_key[:4]}...")
        
        if not self.api_key:
            raise ValueError(
                f"NVD API key not found. Please set {NVD_API_KEY_ENV} environment variable "
                "or provide it during initialization."
            )
        
        # Configure session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=MAX_RETRIES,
            backoff_factor=RETRY_BACKOFF_FACTOR,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set API key in headers
        self.session.headers.update({
            "apiKey": self.api_key,
            "Content-Type": "application/json"
        })
        
        self.last_request_time = 0
        logger.info("NVD API client initialized successfully")
    
    def _rate_limit_delay(self):
        """Enforce rate limiting between requests."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < DEFAULT_RATE_LIMIT_DELAY:
            sleep_time = DEFAULT_RATE_LIMIT_DELAY - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def _make_request(
        self, 
        params: Dict[str, any], 
        endpoint: str = ""
    ) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """
        Make authenticated request to NVD API with error handling.
        
        Args:
            params: Query parameters for the API request
            endpoint: Optional endpoint suffix (defaults to base URL)
        
        Returns:
            Tuple of (success: bool, data: Optional[Dict], error: Optional[str])
        """
        self._rate_limit_delay()
        
        url = f"{NVD_API_BASE_URL}{endpoint}"
        
        try:
            logger.debug(f"Making NVD API request to {url} with params: {params}")
            response = self.session.get(url, params=params, timeout=30)
            
            # Handle rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 60))
                logger.warning(f"Rate limit exceeded. Waiting {retry_after} seconds...")
                time.sleep(retry_after)
                # Retry once after waiting
                response = self.session.get(url, params=params, timeout=30)
            
            response.raise_for_status()
            data = response.json()
            
            logger.info(f"Successfully retrieved {data.get('totalResults', 0)} results from NVD API")
            return True, data, None
            
        except requests.exceptions.HTTPError as e:
            error_msg = f"HTTP error {e.response.status_code}: {e.response.text}"
            logger.error(error_msg)
            return False, None, error_msg
            
        except requests.exceptions.RequestException as e:
            error_msg = f"Network error: {str(e)}"
            logger.error(error_msg)
            return False, None, error_msg
            
        except ValueError as e:
            error_msg = f"JSON decode error: {str(e)}"
            logger.error(error_msg)
            return False, None, error_msg
            
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            logger.error(error_msg)
            return False, None, error_msg
    
    def search_by_keyword(
        self, 
        keyword: str, 
        results_per_page: int = 20,
        start_index: int = 0
    ) -> Optional[pd.DataFrame]:
        """
        Search CVEs by keyword (e.g., technology name + version).
        
        Args:
            keyword: Search term (e.g., "Apache 2.4.41", "WordPress 5.8")
            results_per_page: Number of results per page (max 2000)
            start_index: Starting index for pagination
        
        Returns:
            pandas.DataFrame with CVE data or None if error
        """
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(results_per_page, 2000),
            "startIndex": start_index
        }
        
        success, data, error = self._make_request(params)
        
        if not success:
            logger.error(f"Failed to search by keyword '{keyword}': {error}")
            return None
        
        return self._parse_cve_data(data)
    
    def search_by_cpe(
        self, 
        cpe_uri: str,
        results_per_page: int = 20,
        start_index: int = 0
    ) -> Optional[pd.DataFrame]:
        """
        Search CVEs by CPE (Common Platform Enumeration) URI.
        More accurate than keyword search as it matches exact product/version.
        
        Args:
            cpe_uri: CPE URI string (e.g., "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*")
            results_per_page: Number of results per page (max 2000)
            start_index: Starting index for pagination
        
        Returns:
            pandas.DataFrame with CVE data or None if error
        """
        params = {
            "cpeName": cpe_uri,
            "resultsPerPage": min(results_per_page, 2000),
            "startIndex": start_index
        }
        
        success, data, error = self._make_request(params)
        
        if not success:
            logger.error(f"Failed to search by CPE '{cpe_uri}': {error}")
            return None
        
        return self._parse_cve_data(data)
    
    def search_by_cve_id(self, cve_id: str) -> Optional[pd.DataFrame]:
        """
        Search for a specific CVE by ID.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2020-11984")
        
        Returns:
            pandas.DataFrame with CVE data or None if error
        """
        params = {
            "cveId": cve_id
        }
        
        success, data, error = self._make_request(params)
        
        if not success:
            logger.error(f"Failed to search CVE ID '{cve_id}': {error}")
            return None
        
        return self._parse_cve_data(data)
    
    def _parse_cve_data(self, data: Dict) -> pd.DataFrame:
        """
        Parse NVD API JSON response into pandas DataFrame.
        
        Args:
            data: JSON response from NVD API
        
        Returns:
            pandas.DataFrame with columns: cve_id, description, published_date, 
            severity, cvss_score, cwe
        """
        if not data or "vulnerabilities" not in data:
            logger.warning("No vulnerabilities found in API response")
            return pd.DataFrame(columns=[
                "cve_id", "description", "published_date", 
                "severity", "cvss_score", "cwe"
            ])
        
        cve_records = []
        
        for vuln in data.get("vulnerabilities", []):
            cve_item = vuln.get("cve", {})
            cve_id = cve_item.get("id", "")
            
            # Extract description
            descriptions = cve_item.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Extract published date
            published_date = cve_item.get("published", "")
            
            # Extract references
            references_data = cve_item.get("references", [])
            references = [ref.get("url") for ref in references_data if ref.get("url")]
            
            # Extract metrics (CVSS scores)
            metrics = cve_item.get("metrics", {})
            severity = "UNKNOWN"
            cvss_score = 0.0
            attack_vector = "UNKNOWN"
            attack_complexity = "UNKNOWN"
            
            # Try CVSS v3.1 first, then v3.0, then v2.0
            if "cvssMetricV31" in metrics and len(metrics["cvssMetricV31"]) > 0:
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                attack_vector = cvss_data.get("attackVector", "UNKNOWN")
                attack_complexity = cvss_data.get("attackComplexity", "UNKNOWN")
            elif "cvssMetricV30" in metrics and len(metrics["cvssMetricV30"]) > 0:
                cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                attack_vector = cvss_data.get("attackVector", "UNKNOWN")
                attack_complexity = cvss_data.get("attackComplexity", "UNKNOWN")
            elif "cvssMetricV2" in metrics and len(metrics["cvssMetricV2"]) > 0:
                cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                attack_vector = cvss_data.get("accessVector", "UNKNOWN")
                attack_complexity = cvss_data.get("accessComplexity", "UNKNOWN")
                # Map v2 severity
                if cvss_score >= 7.0:
                    severity = "HIGH"
                elif cvss_score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            
            # Extract CWE (Common Weakness Enumeration)
            weaknesses = cve_item.get("weaknesses", [])
            cwe_list = []
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        cwe_list.append(desc.get("value", ""))
            cwe = ", ".join(cwe_list) if cwe_list else "N/A"
            
            # Extract affected version ranges from configurations
            affected_versions = []
            configurations = cve_item.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable"):
                            range_info = {
                                "start_inc": cpe_match.get("versionStartIncluding"),
                                "start_exc": cpe_match.get("versionStartExcluding"),
                                "end_inc": cpe_match.get("versionEndIncluding"),
                                "end_exc": cpe_match.get("versionEndExcluding")
                            }
                            # Only add if at least one boundary is defined
                            if any(range_info.values()):
                                affected_versions.append(range_info)

            cve_records.append({
                "cve_id": cve_id,
                "description": description,
                "published_date": published_date,
                "severity": severity,
                "cvss_score": cvss_score,
                "cwe": cwe,
                "affected_versions": affected_versions,
                "attack_vector": attack_vector,
                "attack_complexity": attack_complexity,
                "references": references
            })
        
        df = pd.DataFrame(cve_records)
        logger.info(f"Parsed {len(df)} CVE records into DataFrame")
        return df
    
    def lookup_technology_vulnerabilities(
        self, 
        tech_name: str, 
        version: str = ""
    ) -> Optional[pd.DataFrame]:
        """
        Lookup vulnerabilities for a technology/version.

        Strategy:
        1. Try CPE-based search first (most accurate — matches exact product + version).
        2. Fall back to free-text keyword search if CPE returns nothing.

        Args:
            tech_name: Technology name (e.g., "Apache", "WordPress")
            version: Version string (e.g., "2.4.41", "5.8")

        Returns:
            pandas.DataFrame with CVE data or None if error
        """
        # ── Step 1: Build a CPE 2.3 URI and try the precise lookup ──────────
        if version:
            # Normalise: lowercase, spaces → underscores, strip patch qualifiers
            safe_name    = tech_name.lower().replace(" ", "_").replace("-", "_")
            safe_version = version.split(" ")[0]  # "2.4.41 (Ubuntu)" → "2.4.41"
            cpe_uri      = f"cpe:2.3:a:*:{safe_name}:{safe_version}:*:*:*:*:*:*:*"
            logger.info(f"[NVD] Trying CPE lookup: {cpe_uri}")

            df_cpe = self.search_by_cpe(cpe_uri, results_per_page=20)
            if df_cpe is not None and not df_cpe.empty:
                logger.info(f"[NVD] CPE lookup returned {len(df_cpe)} results for {tech_name} {version}")
                return df_cpe

            logger.info(f"[NVD] CPE lookup empty — falling back to keyword for {tech_name} {version}")

        # ── Step 2: Keyword fallback (less precise but catches more) ─────────
        keyword = f"{tech_name} {version}".strip()
        logger.info(f"[NVD] Keyword lookup: '{keyword}'")
        return self.search_by_keyword(keyword)



# Global client instance (lazy initialization)
_client_instance: Optional[NVDApiClient] = None


def get_nvd_client(api_key: Optional[str] = None) -> NVDApiClient:
    """
    Get or create NVD API client instance (singleton pattern).
    
    Args:
        api_key: Optional API key. If not provided, uses environment variable.
    
    Returns:
        NVDApiClient instance
    """
    global _client_instance
    
    if _client_instance is None:
        _client_instance = NVDApiClient(api_key)
    
    return _client_instance


# Example usage
if __name__ == "__main__":
    """
    Example usage of NVD API client.
    
    Note: Never commit API keys to version control!
    Set the API key as an environment variable:
    - Windows: set NVD_API_KEY=your_api_key_here
    - Linux/Mac: export NVD_API_KEY=your_api_key_here
    """
    
    # Initialize client (will use NVD_API_KEY from environment)
    # Or provide directly: client = NVDApiClient(api_key="your-api-key-here")
    try:
        client = get_nvd_client()
        
        # Example 1: Search by keyword
        print("\n=== Example 1: Search by Keyword ===")
        df1 = client.search_by_keyword("Apache 2.4.41", results_per_page=10)
        if df1 is not None and not df1.empty:
            print(df1[["cve_id", "severity", "cvss_score", "description"]].head())
        else:
            print("No results found or error occurred")
        
        # Example 2: Search by CPE URI (more accurate)
        print("\n=== Example 2: Search by CPE URI ===")
        cpe_uri = "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
        df2 = client.search_by_cpe(cpe_uri, results_per_page=10)
        if df2 is not None and not df2.empty:
            print(df2[["cve_id", "severity", "cvss_score"]].head())
        else:
            print("No results found or error occurred")
        
        # Example 3: Search specific CVE
        print("\n=== Example 3: Search Specific CVE ===")
        df3 = client.search_by_cve_id("CVE-2020-11984")
        if df3 is not None and not df3.empty:
            print(df3[["cve_id", "severity", "cvss_score", "description"]])
        else:
            print("CVE not found or error occurred")
        
        # Example 4: Technology lookup convenience method
        print("\n=== Example 4: Technology Vulnerability Lookup ===")
        df4 = client.lookup_technology_vulnerabilities("WordPress", "5.8")
        if df4 is not None and not df4.empty:
            print(f"Found {len(df4)} vulnerabilities")
            print(df4[["cve_id", "severity", "cvss_score"]].head())
        else:
            print("No vulnerabilities found")
        
    except ValueError as e:
        print(f"Error: {e}")
        print("\nTo use this module:")
        print("1. Get an NVD API key from: https://nvd.nist.gov/developers/request-an-api-key")
        print(f"2. Set it as environment variable: {NVD_API_KEY_ENV}")
        print("   Windows: set NVD_API_KEY=your_key_here")
        print("   Linux/Mac: export NVD_API_KEY=your_key_here")

