from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize limiter without an app object
# This avoids circular imports when controllers need to access the limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)
