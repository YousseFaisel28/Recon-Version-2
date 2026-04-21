"""
Admin Controller - Handles admin operations
"""
import datetime
from flask import request, jsonify, Blueprint
from bson import ObjectId
from werkzeug.security import generate_password_hash
from config.database import (
    users_collection,
    user_logs_collection,
    reports_collection,
)
from utils.domain_validator import normalize_domains
from utils.audit_logger import log_audit_event, verify_hmac

from middlewares.admin_middleware import admin_required
from utils.json_utils import mongo_to_json

admin_bp = Blueprint(
    'admin',
    __name__,
    url_prefix="/admin"   # ⭐ VERY IMPORTANT
)


@admin_bp.route("/get_users", methods=["GET"])
@admin_required
def get_users():
    users = []
    for u in users_collection.find():
        users.append({
            "_id": str(u["_id"]),
            "username": u.get("username", ""),
            "email": u.get("email", ""),
            "created_at": str(u.get("created_at", "")),
            "role": u.get("role", "user"),
        })
    return jsonify(mongo_to_json(users))


@admin_bp.route("/add_user", methods=["POST"])
@admin_required
def add_user():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify({"message": "Missing required fields"}), 400

    if users_collection.find_one({"email": email}):
        return jsonify({"message": "Email already exists!"}), 409

    hashed_pw = generate_password_hash(password)
    users_collection.insert_one({
        "username": username,
        "email": email,
        "password": hashed_pw,
        "role": "user",
        "status": "active",
        "created_at": datetime.datetime.utcnow()
    })

    # ── Audit Log ──
    log_audit_event(
        action="admin_user_added",
        details={"target_username": username, "target_email": email},
    )

    return jsonify({"message": "User added successfully!"}), 201


@admin_bp.route("/delete_user/<user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    # Fetch user info before deletion for the audit log
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    result = users_collection.delete_one({"_id": ObjectId(user_id)})
    if result.deleted_count == 0:
        return jsonify({"message": "User not found"}), 404

    # ── Audit Log ──
    log_audit_event(
        action="admin_user_deleted",
        details={
            "target_user_id": user_id,
            "target_username": user.get("username", "") if user else "",
            "target_email": user.get("email", "") if user else "",
        },
    )

    return jsonify({"message": "User deleted successfully"}), 200


@admin_bp.route("/get_pending_users", methods=["GET"])
@admin_required
def get_pending_users():
    """Returns all users where status = 'pending'"""
    pending_users = []
    for u in users_collection.find({"status": "pending"}):
        pending_users.append({
            "username": u.get("username", ""),
            "email": u.get("email", ""),
            "created_at": str(u.get("created_at", "")),
        })

    return jsonify(mongo_to_json({"users": pending_users})), 200


@admin_bp.route("/approve_user", methods=["POST"])
@admin_required
def approve_user():
    """Admin approves or declines a pending user."""
    data = request.get_json()
    email = data.get("email")
    action = data.get("action")

    if not email or not action:
        return jsonify({"message": "Email and action required"}), 400

    user = users_collection.find_one({"email": email})
    if not user:
        return jsonify({"message": "User not found"}), 404

    # APPROVE
    if action == "approve":
        users_collection.update_one(
            {"email": email},
            {"$set": {"status": "active"}}
        )
        # ── Audit Log ──
        log_audit_event(
            action="admin_user_approved",
            details={"target_email": email, "target_username": user.get("username", "")},
        )
        return jsonify({"message": "User approved successfully"}), 200

    # DECLINE
    if action == "decline":
        users_collection.delete_one({"email": email})
        # ── Audit Log ──
        log_audit_event(
            action="admin_user_declined",
            details={"target_email": email, "target_username": user.get("username", "")},
        )
        return jsonify({"message": "User declined and removed"}), 200

    return jsonify({"message": "Invalid action"}), 400


@admin_bp.route("/update_user_domains", methods=["POST"])
@admin_required
def update_user_domains():
    """
    Admin endpoint to update the allowed scan domains for a specific user.

    Expected JSON body:
    {
        "email": "user@example.com",
        "domains": "example.com, sub.example.com"
        // or
        "domains": ["example.com", "sub.example.com"]
    }
    """
    data = request.get_json() or {}
    email = data.get("email")
    raw_domains = data.get("domains")

    if not email or raw_domains is None:
        return jsonify({"message": "Email and domains are required"}), 400

    user = users_collection.find_one({"email": email})
    if not user:
        return jsonify({"message": "User not found"}), 404

    try:
        allowed_domains = normalize_domains(raw_domains)
    except ValueError as e:
        return jsonify({"message": str(e)}), 400

    old_domains = user.get("allowed_domains", [])

    result = users_collection.update_one(
        {"email": email},
        {
            "$set": {
                "allowed_domains": allowed_domains,
                "updated_at": datetime.datetime.utcnow(),
            }
        },
    )

    # ── Audit Log ──
    log_audit_event(
        action="admin_domains_updated",
        details={
            "target_email": email,
            "old_domains": old_domains,
            "new_domains": allowed_domains,
        },
    )

    if result.modified_count == 0:
        # No-op update, but treat as success for idempotency
        return jsonify({"message": "Domains unchanged", "allowed_domains": allowed_domains}), 200

    return jsonify(
        {"message": "Allowed domains updated successfully", "allowed_domains": allowed_domains}
    ), 200


@admin_bp.route("/get_user_domains/<user_id>", methods=["GET"])
@admin_required
def get_user_domains(user_id):
    """
    Return an overview of a user's domains:
      - allowed_domains (from user document)
      - scanned_domains (distinct domains from reports)
    """
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"message": "User not found"}), 404

        allowed_domains = user.get("allowed_domains", [])

        # Collect distinct domains scanned by this user
        scanned_set = set()
        for doc in reports_collection.find({"user_id": user_id}, {"domain": 1}):
            d = (doc.get("domain") or "").strip().lower()
            if d:
                scanned_set.add(d)

        return jsonify(
            {
                "username": user.get("username", ""),
                "email": user.get("email", ""),
                "role": user.get("role", "user"),
                "allowed_domains": allowed_domains,
                "scanned_domains": sorted(scanned_set),
            }
        ), 200
    except Exception as e:
        return jsonify({"message": str(e)}), 500


# ====================================================
# AUDIT LOGS API ENDPOINTS
# ====================================================

@admin_bp.route("/get_audit_logs", methods=["GET"])
@admin_required
def get_audit_logs():
    """
    Returns audit logs with optional filtering.

    Query params:
        user       - filter by username (partial match)
        email      - filter by email (partial match)
        domain     - filter by domain (partial match)
        action     - filter by action type (exact match)
        ip         - filter by IP address (partial match)
        date_from  - filter from date (ISO format YYYY-MM-DD)
        date_to    - filter to date (ISO format YYYY-MM-DD)
        page       - page number (default 1)
        per_page   - results per page (default 50, max 200)
    """
    from config.database import audit_logs_collection

    query = {}

    # ── Text filters (partial match via regex) ─────────
    user_filter = request.args.get("user", "").strip()
    if user_filter:
        query["username"] = {"$regex": user_filter, "$options": "i"}

    email_filter = request.args.get("email", "").strip()
    if email_filter:
        query["email"] = {"$regex": email_filter, "$options": "i"}

    domain_filter = request.args.get("domain", "").strip()
    if domain_filter:
        query["domain"] = {"$regex": domain_filter, "$options": "i"}

    action_filter = request.args.get("action", "").strip()
    if action_filter:
        query["action"] = action_filter

    ip_filter = request.args.get("ip", "").strip()
    if ip_filter:
        query["ip_address"] = {"$regex": ip_filter, "$options": "i"}

    # ── Date range filter ──────────────────────────────
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

    if date_from or date_to:
        query["timestamp"] = {}
        if date_from:
            try:
                query["timestamp"]["$gte"] = datetime.datetime.fromisoformat(date_from)
            except ValueError:
                pass
        if date_to:
            try:
                # Include the entire end day
                end_date = datetime.datetime.fromisoformat(date_to)
                end_date = end_date.replace(hour=23, minute=59, second=59)
                query["timestamp"]["$lte"] = end_date
            except ValueError:
                pass
        if not query["timestamp"]:
            del query["timestamp"]

    # ── Pagination ─────────────────────────────────────
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1

    try:
        per_page = min(200, max(1, int(request.args.get("per_page", 50))))
    except (ValueError, TypeError):
        per_page = 50

    skip = (page - 1) * per_page

    # ── Query execution ────────────────────────────────
    total = audit_logs_collection.count_documents(query)
    cursor = audit_logs_collection.find(query).sort("timestamp", -1).skip(skip).limit(per_page)

    logs = []
    for log in cursor:
        logs.append({
            "_id": str(log["_id"]),
            "action": log.get("action", ""),
            "username": log.get("username", "Unknown"),
            "email": log.get("email", ""),
            "ip_address": log.get("ip_address", ""),
            "user_agent": log.get("user_agent", ""),
            "browser_fingerprint": log.get("browser_fingerprint", ""),
            "domain": log.get("domain", ""),
            "details": log.get("details", {}),
            "timestamp": log.get("timestamp").strftime("%Y-%m-%d %H:%M:%S") if log.get("timestamp") else "",
            "hmac_hash": log.get("hmac_hash", ""),
        })

    return jsonify(mongo_to_json({
        "logs": logs,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": max(1, -(-total // per_page)),  # ceil division
    }))


@admin_bp.route("/verify_audit_log/<log_id>", methods=["GET"])
@admin_required
def verify_audit_log(log_id):
    """Verify HMAC integrity of a specific audit log entry."""
    from config.database import audit_logs_collection

    try:
        log_entry = audit_logs_collection.find_one({"_id": ObjectId(log_id)})
    except Exception:
        return jsonify({"error": "Invalid log ID"}), 400

    if not log_entry:
        return jsonify({"error": "Log entry not found"}), 404

    is_valid = verify_hmac(log_entry)

    return jsonify({
        "log_id": log_id,
        "integrity_valid": is_valid,
        "status": "VERIFIED" if is_valid else "TAMPERED",
    })


@admin_bp.route("/get_audit_actions", methods=["GET"])
@admin_required
def get_audit_actions():
    """Returns a list of distinct action types for the filter dropdown."""
    from config.database import audit_logs_collection

    try:
        actions = audit_logs_collection.distinct("action")
        return jsonify({"actions": sorted(actions)})
    except Exception as e:
        return jsonify({"actions": [], "error": str(e)})


@admin_bp.route("/update_user_role/<user_id>", methods=["POST"])
@admin_required
def update_user_role(user_id):
    """Update a user's role (admin/user)."""
    data = request.get_json() or {}
    new_role = data.get("role")

    if new_role not in ["admin", "user"]:
        return jsonify({"message": "Invalid role"}), 400

    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"message": "User not found"}), 404

    old_role = user.get("role", "user")
    users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"role": new_role, "updated_at": datetime.datetime.utcnow()}}
    )

    # ── Audit Log ──
    log_audit_event(
        action="admin_role_updated",
        details={
            "target_user_id": user_id,
            "target_email": user.get("email"),
            "old_role": old_role,
            "new_role": new_role
        }
    )

    return jsonify({"message": f"User role updated to {new_role}"}), 200


@admin_bp.route("/update_user_status/<user_id>", methods=["POST"])
@admin_required
def update_user_status(user_id):
    """Update a user's status (active/disabled)."""
    data = request.get_json() or {}
    new_status = data.get("status")

    if new_status not in ["active", "disabled"]:
        return jsonify({"message": "Invalid status"}), 400

    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"message": "User not found"}), 404

    old_status = user.get("status", "active")
    users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"status": new_status, "updated_at": datetime.datetime.utcnow()}}
    )

    # ── Audit Log ──
    log_audit_event(
        action="admin_status_updated",
        details={
            "target_user_id": user_id,
            "target_email": user.get("email"),
            "old_status": old_status,
            "new_status": new_status
        }
    )

    return jsonify({"message": f"User status updated to {new_status}"}), 200
