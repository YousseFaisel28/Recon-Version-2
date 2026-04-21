import re
from typing import Iterable, List, Union


DOMAIN_REGEX = re.compile(
    r"^(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)


def is_valid_domain(domain: str) -> bool:
    """
    Return True if the given string looks like a valid domain.
    Supports subdomains like 'sub.example.com'.
    """
    if not isinstance(domain, str):
        return False
    domain = domain.strip().lower()
    if not domain:
        return False
    return bool(DOMAIN_REGEX.match(domain))


def _split_raw_domains(raw: str) -> List[str]:
    """
    Split a raw string into candidate domains using commas and newlines.
    """
    parts = re.split(r"[,\n]+", raw)
    return [p.strip() for p in parts if p.strip()]


def normalize_domains(raw_domains: Union[str, Iterable[str]]) -> List[str]:
    """
    Accept a string (comma / newline separated) or an iterable of strings and
    return a normalized list of unique, lowercase, validated domains.

    Raises ValueError if no valid domains are found or any entry is invalid.
    """
    candidates: List[str] = []

    if isinstance(raw_domains, str):
        candidates = _split_raw_domains(raw_domains)
    elif isinstance(raw_domains, Iterable):
        for item in raw_domains:
            if not item:
                continue
            if isinstance(item, str):
                candidates.extend(_split_raw_domains(item))
    else:
        raise ValueError("Domains must be a string or list of strings.")

    normalized: List[str] = []
    for raw in candidates:
        domain = raw.strip().lower()
        if not domain:
            continue
        if not is_valid_domain(domain):
            raise ValueError(f"Invalid domain format: {domain}")
        if domain not in normalized:
            normalized.append(domain)

    if not normalized:
        raise ValueError("At least one valid domain is required.")

    return normalized


def is_domain_allowed(target: str, primary_domain: str) -> bool:
    """
    Core Scoping Logic:
    Allows exact matches or strict subdomains of the verified apex.
    """
    if not primary_domain:
        return False
    target = target.strip().lower()
    primary = primary_domain.strip().lower()
    return target == primary or target.endswith("." + primary)

def is_allowed(target: str, user_doc: dict) -> bool:
    """
    Checks if a target domain is authorized by querying the user's primary domain 
    or any additionally verified alternative structures natively.
    """
    if not target or not user_doc:
        return False
        
    if is_domain_allowed(target, user_doc.get("primary_domain", "")):
        return True
        
    for domain in user_doc.get("additional_domains", []):
        if is_domain_allowed(target, domain):
            return True
            
    return False


