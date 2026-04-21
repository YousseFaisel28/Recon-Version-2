"""
Audit Logger Utility — Tamper-Resistant Logging with HMAC Integrity

This module provides centralized audit logging for ReconX.
Every log entry is signed with an HMAC-SHA256 hash to detect tampering.

SECURITY DESIGN:
    - Append-only: No update or delete functions exist.
    - HMAC integrity: Each entry's hash covers all critical fields.
    - If the HMAC_SECRET is rotated, old entries can still be verified
      by checking against the old key (out of scope here).
"""

import os
import hmac
import json
import hashlib
import datetime
from flask import request, session
from utils.logger import get_logger

audit_logger = get_logger("audit")

AUDIT_HMAC_SECRET = os.getenv(
    "AUDIT_HMAC_SECRET",
    "reconx_audit_hmac_secret_a7f3b9c2e1d4"
)


def _compute_hmac(payload: dict) -> str:
    """
    Compute HMAC-SHA256 over a canonical JSON representation of the payload.
    The payload must not include the hmac_hash field itself.
    """
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hmac.new(
        AUDIT_HMAC_SECRET.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_hmac(log_entry: dict) -> bool:
    """
    Verify the integrity of an audit log entry.
    Returns True if the entry has not been tampered with.
    """
    stored_hash = log_entry.get("hmac_hash")
    if not stored_hash:
        return False

    # Rebuild payload without hmac_hash and _id
    payload = {k: v for k, v in log_entry.items() if k not in ("hmac_hash", "_id")}
    expected_hash = _compute_hmac(payload)
    return hmac.compare_digest(stored_hash, expected_hash)


def log_audit_event(
    action: str,
    details: dict = None,
    domain: str = None,
    user_override: dict = None,
):
    """
    Record a tamper-resistant audit log entry.

    Args:
        action:         Action type, e.g. 'login_success', 'scan_started',
                        'report_downloaded', 'user_approved', etc.
        details:        Optional dict with action-specific metadata.
        domain:         Target domain (if applicable).
        user_override:  Override user identity (for failed-login scenarios
                        where there's no active session).
                        Expected keys: username, email, user_id
    """
    from config.database import audit_logs_collection

    # ── User identity ──────────────────────────────────────
    if user_override:
        user_id = user_override.get("user_id", "")
        username = user_override.get("username", "Unknown")
        email = user_override.get("email", "")
    else:
        user_id = session.get("user_id", "")
        username = session.get("username", "Unknown")
        email = session.get("email", "")

    # ── Request metadata ───────────────────────────────────
    ip_address = request.remote_addr or "Unknown"
    user_agent = request.headers.get("User-Agent", "Unknown")
    browser_fingerprint = request.headers.get("X-Browser-Fingerprint", "")

    # ── Build payload (everything EXCEPT hmac_hash) ────────
    timestamp = datetime.datetime.utcnow()
    payload = {
        "action": action,
        "user_id": str(user_id),
        "username": username,
        "email": email,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "browser_fingerprint": browser_fingerprint,
        "domain": domain or "",
        "details": details or {},
        "timestamp": timestamp,
    }

    # ── HMAC integrity hash ────────────────────────────────
    payload["hmac_hash"] = _compute_hmac(
        {k: v for k, v in payload.items() if k != "hmac_hash"}
    )

    # ── Append-only insert (no update/delete by design) ────
    try:
        audit_logs_collection.insert_one(payload)
    except Exception as e:
        audit_logger.info(f"AUDIT EVENT: {action} | User: {user_id} | Email: {email} | IP: {ip_address} | Domain: {domain} | Details: {details}")
