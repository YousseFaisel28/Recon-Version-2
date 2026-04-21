"""
Auth Controller - Handles authentication (login, signup, forgot-password)
"""
import datetime
import os
import re
import secrets
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import request, jsonify, Blueprint, session
from werkzeug.security import generate_password_hash, check_password_hash
from config.database import users_collection, user_logs_collection
from utils.domain_validator import normalize_domains
from utils.audit_logger import log_audit_event
from middlewares.auth_middleware import login_required
from utils.logger import get_logger
from utils.extensions import limiter

logger = get_logger(__name__)

auth_bp = Blueprint('auth', __name__)


# ──────────────────────────────────────────────
# Helper utilities for Forgot Password flow
# ──────────────────────────────────────────────

def _hash_otp(otp: str) -> str:
    """Hash the OTP using werkzeug so it is never stored in plain text."""
    return generate_password_hash(otp, method='pbkdf2:sha256')


def _verify_otp(otp: str, otp_hash: str) -> bool:
    """Verify a plain OTP against its stored hash."""
    return check_password_hash(otp_hash, otp)


def _send_otp_email(to_email: str, otp: str) -> None:
    """
    Send the OTP to the user via SMTP (Gmail TLS).
    Raises RuntimeError if config is missing or sending fails.
    """
    mail_server   = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    mail_port     = int(os.environ.get('MAIL_PORT', 587))
    mail_username = os.environ.get('MAIL_USERNAME', '')
    mail_password = os.environ.get('MAIL_PASSWORD', '')
    mail_from     = os.environ.get('MAIL_FROM', mail_username)

    if not mail_username or not mail_password:
        raise RuntimeError(
            'Email configuration is missing. '
            'Set MAIL_USERNAME and MAIL_PASSWORD in .env'
        )

    msg = MIMEMultipart('alternative')
    msg['Subject'] = '🔐 ReconX – Your Password Reset Code'
    msg['From']    = mail_from
    msg['To']      = to_email

    plain_body = (
        f'Your ReconX password reset code is: {otp}\n\n'
        f'This code expires in 10 minutes and can only be used once.\n'
        f'If you did not request this, please ignore this email.'
    )
    html_body = f"""
    <html><body style="font-family:Inter,Arial,sans-serif;background:#0B0F19;color:#fff;padding:40px;">
      <div style="max-width:480px;margin:0 auto;background:rgba(255,255,255,0.04);
                  border:1px solid rgba(255,255,255,0.08);border-radius:20px;padding:40px;">
        <h2 style="color:#10B981;margin-bottom:8px;">ReconX Security</h2>
        <p style="color:#9CA3AF;margin-bottom:24px;">Password Reset Request</p>
        <p style="font-size:14px;color:#d1d5db;">Use the code below to reset your password.
           It expires in <strong>10 minutes</strong> and is valid for one use only.</p>
        <div style="background:#111827;border:1px solid #10B981;border-radius:12px;
                    padding:24px;text-align:center;margin:24px 0;">
          <span style="font-size:36px;font-weight:700;letter-spacing:12px;color:#10B981;">{otp}</span>
        </div>
        <p style="font-size:12px;color:#6B7280;">If you did not request a password reset,
           you can safely ignore this email. Your password will not be changed.</p>
        <hr style="border-color:rgba(255,255,255,0.08);margin:24px 0;">
        <p style="font-size:12px;color:#4B5563;">ReconX – Reconnaissance Platform</p>
      </div>
    </body></html>
    """

    msg.attach(MIMEText(plain_body, 'plain'))
    msg.attach(MIMEText(html_body,  'html'))

    context = ssl.create_default_context()
    with smtplib.SMTP(mail_server, mail_port) as server:
        server.ehlo()
        server.starttls(context=context)
        server.login(mail_username, mail_password)
        server.sendmail(mail_from, to_email, msg.as_string())


def _validate_password_strength(password: str):
    """
    Returns a list of error strings.  Empty list means password is valid.
    Rules: min 8 chars, 1 uppercase, 1 digit, 1 special char.
    """
    errors = []
    if len(password) < 8:
        errors.append('at least 8 characters')
    if not re.search(r'[A-Z]', password):
        errors.append('at least one uppercase letter')
    if not re.search(r'\d', password):
        errors.append('at least one number')
    if not re.search(r'[!@#$%^&*(),.?":{}|<>\-_=+\[\]\\/;\']', password):
        errors.append('at least one special character')
    return errors




@auth_bp.route("/signup", methods=["POST"])
@limiter.limit("5 per minute") if limiter else lambda f: f
def signup():
    data = request.get_json() or {}
    email = data.get("email")
    username = data.get("username")
    password = data.get("password")
    domain = data.get("domain", "").strip()

    if not email or not username or not password or not domain:
        return jsonify({"message": "All fields are required!"}), 400



    from urllib.parse import urlparse
    
    parsed = urlparse(domain)
    # Handle inputs missing standard protocol wrappers
    if not parsed.scheme:
        parsed = urlparse("https://" + domain)
        
    base_domain = parsed.netloc

    try:
        allowed_domains = normalize_domains(base_domain)
    except ValueError as e:
        allowed_domains = [base_domain]

    if users_collection.find_one({"email": email}):
        return jsonify({"message": "Email already registered!"}), 409

    hashed_pw = generate_password_hash(password)
    


    users_collection.insert_one({
        "email": email,
        "username": username,
        "password": hashed_pw,
        "status": "pending",
        "role": "user",
        "created_at": datetime.datetime.utcnow(),
        "primary_domain": allowed_domains[0] if allowed_domains else base_domain,
        "additional_domains": [],
        "verified": True
    })

    # ── Audit Log ──
    log_audit_event(
        action="user_signup",
        details={"status": "pending", "domain": domain},
        user_override={"username": username, "email": email, "user_id": ""},
    )

    return jsonify(
        {
            "message": "User registered successfully and is now pending admin approval.",
            "status": "pending",
        }
    ), 201


@auth_bp.route("/login", methods=["POST"])
@limiter.limit("10 per minute") if limiter else lambda f: f
def login():
    """
    Unified login endpoint for both regular users and admin.

    Admin credentials are stored in the database like any other user, with:
    - role: "admin"
    - password: securely hashed (see utils/seed_admin.py)
    """
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"message": "Email and password are required!"}), 400

    ip_address = request.remote_addr or "Unknown IP"

    # Look up user (admin and regular users share the same collection)
    user = users_collection.find_one({"email": email})
    if not user:
        user_logs_collection.insert_one({
            "username": "Unknown",
            "email": email,
            "status": "Failed - User not found",
            "ip": ip_address,
            "login_time": datetime.datetime.utcnow()
        })
        # ── Audit Log ──
        log_audit_event(
            action="login_failed",
            details={"reason": "User not found"},
            user_override={"username": "Unknown", "email": email, "user_id": ""},
        )
        return jsonify({"message": "Invalid email or password"}), 401

    # Check if user is pending (BLOCK LOGIN for non-admin users)
    if user.get("role") != "admin" and user.get("status", "pending") != "active":
        user_logs_collection.insert_one({
            "username": user["username"],
            "email": email,
            "status": "Failed - Pending approval",
            "ip": ip_address,
            "login_time": datetime.datetime.utcnow()
        })
        # ── Audit Log ──
        log_audit_event(
            action="login_failed",
            details={"reason": "Pending approval"},
            user_override={
                "username": user["username"],
                "email": email,
                "user_id": str(user["_id"]),
            },
        )
        return jsonify({"message": "Account awaiting admin approval"}), 403

    # Password Check (hashed password only)
    stored_password = user.get("password") or ""
    if check_password_hash(stored_password, password):
        user_logs_collection.insert_one({
            "username": user["username"],
            "email": email,
            "status": "Success",
            "ip": ip_address,
            "login_time": datetime.datetime.utcnow()
        })
        session.permanent = True
        session["logged_in"] = True
        session["user_id"] = str(user["_id"])
        session["role"] = user.get("role", "user")
        session["email"] = user.get("email")
        session["username"] = user.get("username")
        role = user.get("role", "user")

        # ── Audit Log ──
        log_audit_event(
            action="login_success",
            details={"role": role},
            user_override={
                "username": user["username"],
                "email": email,
                "user_id": str(user["_id"]),
            },
        )

        return jsonify({"message": "Login successful!", "email": user["email"], "role": role}), 200
    else:
        user_logs_collection.insert_one({
            "username": user["username"],
            "email": email,
            "status": "Failed - Wrong password",
            "ip": ip_address,
            "login_time": datetime.datetime.utcnow()
        })
        # ── Audit Log ──
        log_audit_event(
            action="login_failed",
            details={"reason": "Wrong password"},
            user_override={
                "username": user["username"],
                "email": email,
                "user_id": str(user["_id"]),
            },
        )
        return jsonify({"message": "Invalid email or password"}), 401


@auth_bp.route("/logout", methods=["POST", "GET"])
def logout():
    # ── Audit Log ──
    log_audit_event(action="logout")
    session.clear()
    return jsonify({"message": "Logged out successfully"}), 200


@auth_bp.route("/user/profile", methods=["GET"])
def get_user_profile():
    """Get current logged-in user's profile (username, email, role, allowed domains)."""
    if "user_id" not in session or not session.get("logged_in"):
        return jsonify({"success": False, "error": "User not logged in"}), 401
    
    user_id = session.get("user_id")

    try:
        from bson.objectid import ObjectId

        query_id = ObjectId(user_id)
        user = users_collection.find_one(
            {"_id": query_id},
            {"username": 1, "email": 1, "role": 1, "primary_domain": 1, "additional_domains": 1, "allowed_domains": 1},
        )

        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404
            
        primary = user.get("primary_domain")
        additional = user.get("additional_domains", [])
        
        # Legacy backwards compatibility support for 'allowed_domains' references on the dashboard
        legacy = user.get("allowed_domains", [])
        if primary and primary not in legacy:
            legacy.insert(0, primary)
        for d in additional:
            if d not in legacy:
                legacy.append(d)

        return jsonify(
            {
                "username": user.get("username"),
                "email": user.get("email"),
                "role": user.get("role", "user"),
                "primary_domain": primary,
                "additional_domains": additional,
                "allowed_domains": legacy,
            }
        ), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@auth_bp.route("/verify-password", methods=["POST"])
def verify_password():
    """Verify user's current password for account settings access."""
    if "user_id" not in session or not session.get("logged_in"):
        return jsonify({"success": False, "error": "User not logged in"}), 401
    
    user_id = session.get("user_id")
    data = request.get_json()
    password = data.get("password") if data else None
    
    if not password:
        return jsonify({"success": False, "error": "Password is required"}), 400

    try:
        from bson.objectid import ObjectId
        query_id = ObjectId(user_id)
        user = users_collection.find_one({"_id": query_id}, {"password": 1})
        
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404
        
        stored_password = user.get("password")
        
        # Check hashed password
        if stored_password and check_password_hash(stored_password, password):
            return jsonify({"success": True, "message": "Password verified"}), 200
        else:
            return jsonify({"success": False, "error": "Incorrect password"}), 401
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@auth_bp.route("/change-username", methods=["POST"])
def change_username():
    """
    Endpoint for a logged-in user to change their username.
    
    Request body:
    {
        "new_username": "new_username_here"
    }
    
    Validation rules:
    - No spaces or special characters (letters, numbers, underscore only)
    - Min 3 chars, max 20 chars
    - Cannot be only numbers (e.g., "123" rejected, "user123" allowed)
    - Cannot be "admin" or "reconx" (reserved)
    - Username must not already exist in DB
    """
    from bson.objectid import ObjectId
    
    # Check if user is logged in
    if "user_id" not in session or not session.get("logged_in"):
        return jsonify({"success": False, "error": "User not logged in"}), 401
    
    user_id = session.get("user_id")
    
    # Get request data
    data = request.get_json()
    new_username = data.get("new_username", "").strip() if data else ""
    
    # Validation 1: Not empty
    if not new_username:
        return jsonify({"success": False, "error": "Username cannot be empty"}), 400
    
    # Validation 2: Length 3-20
    if len(new_username) < 3 or len(new_username) > 20:
        return jsonify({"success": False, "error": "Username must be between 3 and 20 characters"}), 400
    
    # Validation 3: Alphanumeric + underscore only
    if not all(c.isalnum() or c == "_" for c in new_username):
        return jsonify({"success": False, "error": "Username can only contain letters, numbers, and underscore"}), 400
    
    # Validation 4: Cannot be only numbers
    if new_username.isdigit():
        return jsonify({"success": False, "error": "Username cannot be only numbers"}), 400
    
    # Validation 5: Reserved usernames
    if new_username.lower() in ["admin", "reconx"]:
        return jsonify({"success": False, "error": "This username is reserved"}), 400
    
    # Validation 6: Username not already taken
    existing_user = users_collection.find_one({"username": new_username})
    if existing_user:
        return jsonify({"success": False, "error": "Username already taken"}), 409
    
    # Update username in DB
    try:
        # Handle both admin and regular user IDs
        if user_id == "admin":
            return jsonify({"success": False, "error": "Admin cannot change username this way"}), 403
        
        query_id = ObjectId(user_id) if isinstance(user_id, str) else user_id
        old_user = users_collection.find_one({"_id": query_id}, {"username": 1})
        old_username = old_user.get("username", "") if old_user else ""

        result = users_collection.update_one(
            {"_id": query_id},
            {"$set": {"username": new_username, "updated_at": datetime.datetime.utcnow()}}
        )
        
        if result.modified_count == 0:
            return jsonify({"success": False, "error": "Failed to update username"}), 500
        
        # ── Audit Log ──
        log_audit_event(
            action="username_changed",
            details={"old_username": old_username, "new_username": new_username},
        )

        return jsonify({"success": True, "message": "Username changed successfully"}), 200
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@auth_bp.route('/change-password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401

    data = request.get_json() or {}
    current_password = data.get('current_password')
    new_password = data.get('new_password')

    if not current_password or not new_password:
        return jsonify({'success': False, 'error': 'Both current and new passwords are required'}), 400

    # ── Strength validation ──
    strength_errors = _validate_password_strength(new_password)
    if strength_errors:
        return jsonify({
            'success': False,
            'error': f'Password must contain: {", ".join(strength_errors)}'
        }), 400

    user_id = session.get('user_id')

    try:
        from bson.objectid import ObjectId
        query_id = ObjectId(user_id) if isinstance(user_id, str) else user_id
        user = users_collection.find_one({'_id': query_id})
    except Exception:
        user = None

    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404

    stored_password = user.get('password', '')
    # Check hashed password only
    if not (stored_password and check_password_hash(stored_password, current_password)):
        return jsonify({'success': False, 'error': 'Current password is incorrect'}), 403

    # All checks passed — update password hash
    new_hash = generate_password_hash(new_password)
    users_collection.update_one({'_id': query_id}, {'$set': {'password': new_hash}})

    # ── Audit Log ──
    log_audit_event(action="password_changed")

    return jsonify({'success': True, 'message': 'Password changed successfully'})


# ══════════════════════════════════════════════════════
# FORGOT PASSWORD FLOW  (3-step: send-otp → verify → reset)
# ══════════════════════════════════════════════════════

@auth_bp.route('/forgot-password/send-otp', methods=['POST'])
@limiter.limit("3 per minute") if limiter else lambda f: f
def forgot_password_send_otp():
    """
    Step 1 – validate email, generate & email a 6-digit OTP.
    Rate-limited to 5 requests per hour per email address.
    """
    data  = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()

    if not email:
        return jsonify({'success': False, 'error': 'Email is required'}), 400

    user = users_collection.find_one({'email': email})
    # Security: don't reveal whether the email exists
    if not user:
        return jsonify({
            'success': True,
            'message': 'If that email is registered you will receive a code shortly.'
        }), 200

    now = datetime.datetime.utcnow()

    # ── Rate limiting: max 5 OTP requests per hour ──
    window_start = now - datetime.timedelta(hours=1)
    req_count  = user.get('otp_request_count', 0)
    req_window = user.get('otp_request_window')
    if req_window and req_window > window_start:
        if req_count >= 5:
            return jsonify({
                'success': False,
                'error': 'Too many reset requests. Please try again in an hour.'
            }), 429
        new_count = req_count + 1
    else:
        new_count = 1

    # ── Generate OTP ──
    otp      = str(secrets.randbelow(900000) + 100000)   # 100000-999999
    otp_hash = _hash_otp(otp)
    expiry   = now + datetime.timedelta(minutes=10)

    users_collection.update_one(
        {'email': email},
        {'$set': {
            'otp_hash':              otp_hash,
            'otp_expiry':            expiry,
            'otp_attempts':          0,
            'otp_used':              False,
            'reset_token_verified':  False,
            'otp_request_count':     new_count,
            'otp_request_window':    now,
        }}
    )

    # ── Send email ──
    try:
        _send_otp_email(email, otp)
    except RuntimeError as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    except Exception:
        return jsonify({
            'success': False,
            'error': 'Failed to send email. Please check SMTP configuration.'
        }), 500

    log_audit_event(
        action='forgot_password_otp_sent',
        details={'email': email},
        user_override={'username': user.get('username', ''), 'email': email, 'user_id': str(user['_id'])}
    )

    return jsonify({
        'success': True,
        'message': 'If that email is registered you will receive a code shortly.'
    }), 200


@auth_bp.route('/forgot-password/verify-otp', methods=['POST'])
def forgot_password_verify_otp():
    """
    Step 2 – verify the OTP.  Max 5 wrong attempts before lockout.
    """
    data  = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    otp   = (data.get('otp')   or '').strip()

    if not email or not otp:
        return jsonify({'success': False, 'error': 'Email and OTP are required'}), 400

    user = users_collection.find_one({'email': email})
    if not user or not user.get('otp_hash'):
        return jsonify({'success': False, 'error': 'No OTP was issued for this email.'}), 400

    now = datetime.datetime.utcnow()

    # ── Expiry check ──
    if now > user.get('otp_expiry', now):
        users_collection.update_one({'email': email}, {'$unset': {
            'otp_hash': '', 'otp_expiry': '', 'otp_attempts': '',
            'otp_used': '', 'reset_token_verified': ''
        }})
        return jsonify({'success': False, 'error': 'OTP has expired. Please request a new code.'}), 400

    # ── OTP already used? ──
    if user.get('otp_used'):
        return jsonify({'success': False, 'error': 'OTP has already been used.'}), 400

    # ── Brute-force check ──
    attempts = user.get('otp_attempts', 0)
    if attempts >= 5:
        return jsonify({
            'success': False,
            'error': 'Too many failed attempts. Please request a new code.'
        }), 429

    # ── Verify hash ──
    if not _verify_otp(otp, user['otp_hash']):
        users_collection.update_one(
            {'email': email},
            {'$inc': {'otp_attempts': 1}}
        )
        remaining = 4 - attempts
        return jsonify({
            'success': False,
            'error': f'Invalid OTP. {remaining} attempt(s) remaining.'
        }), 400

    # ── Mark OTP as used + grant reset permission ──
    users_collection.update_one(
        {'email': email},
        {'$set': {
            'otp_used':             True,
            'reset_token_verified': True,
            'reset_verified_at':    now,
        }}
    )

    log_audit_event(
        action='forgot_password_otp_verified',
        details={'email': email},
        user_override={'username': user.get('username', ''), 'email': email, 'user_id': str(user['_id'])}
    )

    return jsonify({'success': True, 'message': 'OTP verified. You may now reset your password.'}), 200


@auth_bp.route('/forgot-password/reset-password', methods=['POST'])
def forgot_password_reset_password():
    """
    Step 3 – reset the password after successful OTP verification.
    The reset window is 15 minutes from OTP verification.
    """
    data             = request.get_json() or {}
    email            = (data.get('email')        or '').strip().lower()
    new_password     = data.get('new_password',     '')
    confirm_password = data.get('confirm_password', '')

    if not email or not new_password:
        return jsonify({'success': False, 'error': 'Email and new password are required'}), 400

    user = users_collection.find_one({'email': email})
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404

    # ── Ensure OTP was verified first ──
    if not user.get('reset_token_verified'):
        return jsonify({
            'success': False,
            'error': 'Please verify your email OTP before resetting your password.'
        }), 403

    # ── Enforce 15-minute reset window ──
    now = datetime.datetime.utcnow()
    verified_at = user.get('reset_verified_at')
    if not verified_at or (now - verified_at).total_seconds() > 900:
        users_collection.update_one({'email': email}, {'$unset': {
            'otp_hash': '', 'otp_expiry': '', 'otp_attempts': '',
            'otp_used': '', 'reset_token_verified': '', 'reset_verified_at': ''
        }})
        return jsonify({
            'success': False,
            'error': 'Reset session expired. Please start over.'
        }), 403

    # ── Password confirmation ──
    if new_password != confirm_password:
        return jsonify({'success': False, 'error': 'Passwords do not match'}), 400

    # ── Strength validation ──
    errors = _validate_password_strength(new_password)
    if errors:
        return jsonify({
            'success': False,
            'error': f'Password must contain: {", ".join(errors)}'
        }), 400

    # ── Hash and save ──
    new_hash = generate_password_hash(new_password)
    users_collection.update_one(
        {'email': email},
        {
            '$set':   {'password': new_hash, 'updated_at': now},
            '$unset': {
                'otp_hash': '', 'otp_expiry': '', 'otp_attempts': '',
                'otp_used': '', 'reset_token_verified': '',
                'reset_verified_at': '', 'otp_request_count': '',
                'otp_request_window': ''
            }
        }
    )

    log_audit_event(
        action='password_reset_via_otp',
        details={'email': email},
        user_override={'username': user.get('username', ''), 'email': email, 'user_id': str(user['_id'])}
    )

    return jsonify({'success': True, 'message': 'Password reset successfully. You may now log in.'}), 200
@auth_bp.route("/auth/status", methods=["GET"])
def auth_status():
    """Returns the current authentication status for the frontend guard."""
    if session.get("user_id"):
        return jsonify({
            "logged_in": True,
            "user_id": session.get("user_id"),
            "role": session.get("role", "user"),
            "email": session.get("email")
        }), 200
    return jsonify({"logged_in": false}), 200
