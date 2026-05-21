"""Rate limiting configuration for API endpoints"""

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import request
import logging

logger = logging.getLogger(__name__)

# Initialize Limiter with memory backend
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)


def get_rate_limit_key():
    """
    Custom rate limit key that includes both IP and user ID if authenticated

    Returns:
        Rate limit key string
    """
    from flask_login import current_user

    if current_user.is_authenticated:
        return f"{get_remote_address()}:{current_user.id}"
    else:
        return get_remote_address()


class RateLimitConfig:
    """Rate limiting configuration for different endpoints"""

    # OTP verification - 5 attempts per 5 minutes per IP
    OTP_VERIFY = "5/5minutes"

    # OTP resend - 3 attempts per 15 minutes per IP
    OTP_RESEND = "3/15minutes"

    # Share access - 10 attempts per minute (prevent rapid access)
    SHARE_ACCESS = "10/1minute"

    # Login attempts - 5 failed attempts per 15 minutes
    LOGIN = "5/15minutes"

    # API endpoints - general limits
    API_GENERAL = "100/1hour"

    # Share creation - 20 per hour
    SHARE_CREATE = "20/1hour"

    # Download - 50 per hour
    DOWNLOAD = "50/1hour"


def rate_limit_exceeded(error):
    """
    Handler for rate limit exceeded

    Args:
        error: The rate limit error

    Returns:
        JSON response with error message
    """
    from flask import jsonify

    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.',
        'retry_after': error.retry_after
    }), 429


def configure_rate_limiting(app):
    """
    Configure rate limiting for Flask app

    Args:
        app: Flask application instance
    """
    limiter.init_app(app)
    app.register_error_handler(429, rate_limit_exceeded)

    logger.info("Rate limiting configured")


def apply_otp_limit(f):
    """Decorator to apply OTP verification rate limit"""
    from flask_limiter.util import get_remote_address

    def decorator(*args, **kwargs):
        return f(*args, **kwargs)

    decorator.__wrapped__ = f
    return decorator


def apply_login_limit(f):
    """Decorator to apply login rate limit"""
    def decorator(*args, **kwargs):
        return f(*args, **kwargs)

    decorator.__wrapped__ = f
    return decorator
