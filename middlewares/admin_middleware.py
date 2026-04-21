from functools import wraps
from flask import session, redirect, url_for, jsonify, request
from utils.logger import get_logger

logger = get_logger(__name__)

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        # Check for user_id in session
        if not session.get("user_id"):
            logger.warning(f"Unauthorized access attempt to {request.path} - Redirecting to login.")
            return redirect(url_for("views.login_page"))

        # Check for admin role
        if session.get("role") != "admin":
            logger.warning(f"Non-admin access attempt to {request.path} by {session.get('email')}")
            
            # Detect JSON/AJAX requests
            if request.headers.get('Accept') == 'application/json' or \
               request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({"error": "Unauthorized. Admin role required.", "status": "forbidden"}), 403
                
            return redirect(url_for("views.unauthorized_page"))

        return f(*args, **kwargs)
    return decorated
