from functools import wraps
from flask import session, redirect, url_for, request
from utils.logger import get_logger

logger = get_logger(__name__)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Use user_id as the primary source of truth for session
        if not session.get("user_id"):
            logger.warning(f"Unauthorized access attempt to {request.path} - Redirecting or returning 401.")
            
            # Detect JSON/AJAX requests
            if request.headers.get('Accept') == 'application/json' or \
               request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({"error": "Authentication required", "status": "unauthenticated"}), 401
                
            return redirect(url_for("views.login_page"))
            
        return f(*args, **kwargs)
    return decorated
