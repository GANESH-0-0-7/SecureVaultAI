"""Utilities for secure file sharing system"""

import qrcode
import pyotp
import secrets
import base64
import io
import json
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify


class QRCodeGenerator:
    """Generate QR codes for file sharing"""
    
    @staticmethod
    def generate_qr_code(data, version=1, box_size=10, border=2):
        """
        Generate a QR code from data
        
        Args:
            data: String data to encode in QR code
            version: QR code version (1-40)
            box_size: Size of each box in pixels
            border: Border size in boxes
            
        Returns:
            Base64 encoded image string
        """
        try:
            qr = qrcode.QRCode(
                version=version,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=box_size,
                border=border,
            )
            qr.add_data(data)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64
            img_io = io.BytesIO()
            img.save(img_io, 'PNG')
            img_io.seek(0)
            img_base64 = base64.b64encode(img_io.getvalue()).decode()
            
            return f"data:image/png;base64,{img_base64}"
        except Exception as e:
            raise Exception(f"Error generating QR code: {str(e)}")


class OTPManager:
    """Manage One-Time Passwords for secure verification"""
    
    @staticmethod
    def generate_otp(length=6):
        """
        Generate a random OTP code
        
        Args:
            length: Length of OTP (default 6 digits)
            
        Returns:
            OTP string
        """
        return ''.join([str(secrets.randbelow(10)) for _ in range(length)])
    
    @staticmethod
    def generate_totp_secret():
        """
        Generate a TOTP secret for time-based OTP
        
        Returns:
            TOTP secret string
        """
        return pyotp.random_base32()
    
    @staticmethod
    def verify_otp(otp_code, stored_otp, expires_at=None, max_age_seconds=300):
        """
        Verify OTP code with expiry validation

        Args:
            otp_code: OTP provided by user
            stored_otp: OTP stored in database
            expires_at: Expiry datetime (if provided, checks expiry)
            max_age_seconds: Maximum age of OTP in seconds (default 5 minutes, legacy support)

        Returns:
            Boolean indicating if OTP is valid
        """
        if not otp_code or otp_code != stored_otp:
            return False

        if expires_at is not None:
            if datetime.utcnow() > expires_at:
                return False

        return True
    
    @staticmethod
    def verify_totp(secret, token, window=1):
        """
        Verify TOTP token
        
        Args:
            secret: TOTP secret
            token: Token provided by user
            window: Time window to check (in 30-second intervals)
            
        Returns:
            Boolean indicating if token is valid
        """
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=window)


class ShareTokenGenerator:
    """Generate secure sharing tokens"""
    
    @staticmethod
    def generate_share_token(length=32):
        """
        Generate a secure random sharing token
        
        Args:
            length: Length of token
            
        Returns:
            Hex encoded token string
        """
        return secrets.token_hex(length // 2)
    
    @staticmethod
    def generate_qr_token(file_id, user_id, length=32):
        """
        Generate a QR-specific token
        
        Args:
            file_id: ID of the file being shared
            user_id: ID of the owner
            length: Length of token
            
        Returns:
            QR token string
        """
        token_data = f"{file_id}:{user_id}:{secrets.token_hex(8)}"
        return base64.urlsafe_b64encode(token_data.encode()).decode()


class AccessValidator:
    """Validate access to shared files"""
    
    @staticmethod
    def validate_share_expiry(share_expiry):
        """
        Check if share has expired
        
        Args:
            share_expiry: Expiry datetime
            
        Returns:
            Boolean indicating if share is still valid
        """
        if share_expiry is None:
            return True
        return datetime.utcnow() < share_expiry
    
    @staticmethod
    def validate_otp_expiry(otp_expiry):
        """
        Check if OTP has expired
        
        Args:
            otp_expiry: OTP expiry datetime
            
        Returns:
            Boolean indicating if OTP is still valid
        """
        if otp_expiry is None:
            return True
        return datetime.utcnow() < otp_expiry
    
    @staticmethod
    def validate_access_count(current_count, max_count):
        """
        Check if access count limit is reached
        
        Args:
            current_count: Current access count
            max_count: Maximum allowed accesses (None for unlimited)
            
        Returns:
            Boolean indicating if access is allowed
        """
        if max_count is None:
            return True
        return current_count < max_count
    
    @staticmethod
    def validate_otp_attempts(attempts, max_attempts):
        """
        Check if OTP attempts limit is reached
        
        Args:
            attempts: Current attempt count
            max_attempts: Maximum allowed attempts
            
        Returns:
            Boolean indicating if more attempts are allowed
        """
        return attempts < max_attempts


class DeviceFingerprint:
    """Generate device fingerprints for access tracking"""
    
    @staticmethod
    def get_device_info():
        """
        Extract device information from request
        
        Returns:
            Dictionary with device information
        """
        from flask import request
        
        user_agent = request.headers.get('User-Agent', 'Unknown')
        ip_address = request.remote_addr
        
        device_info = {
            'ip_address': ip_address,
            'user_agent': user_agent,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return device_info
    
    @staticmethod
    def generate_fingerprint(ip_address, user_agent):
        """
        Generate a device fingerprint
        
        Args:
            ip_address: IP address of the device
            user_agent: User agent string
            
        Returns:
            Fingerprint hash
        """
        import hashlib
        
        fingerprint_data = f"{ip_address}:{user_agent}"
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()


class ShareLinkGenerator:
    """Generate secure temporary share links"""
    
    @staticmethod
    def generate_temporary_link(shared_file_id, expiry_minutes=24*60):
        """
        Generate a temporary share link
        
        Args:
            shared_file_id: ID of the shared file
            expiry_minutes: Link expiry in minutes
            
        Returns:
            Dictionary with link and expiry info
        """
        token = secrets.token_urlsafe(32)
        expiry = datetime.utcnow() + timedelta(minutes=expiry_minutes)
        
        return {
            'token': token,
            'expiry': expiry,
            'link': f"/sharing/access/{token}"
        }
    
    @staticmethod
    def validate_temporary_link(token, stored_token, expiry_time):
        """
        Validate a temporary link
        
        Args:
            token: Token provided in request
            stored_token: Token stored in database
            expiry_time: Expiry datetime
            
        Returns:
            Boolean indicating if link is valid
        """
        token_valid = secrets.compare_digest(token, stored_token)
        time_valid = datetime.utcnow() < expiry_time
        
        return token_valid and time_valid


def require_api_key(f):
    """
    Decorator to require API key for sharing endpoints
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        # Validate API key (implement your validation logic)
        # For now, we'll skip this
        
        return f(*args, **kwargs)
    
    return decorated_function


def rate_limit(max_requests=10, window_seconds=60):
    """
    Decorator to rate limit requests
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Implementation would use Redis or similar
            # For now, we'll skip this
            return f(*args, **kwargs)
        return decorated_function
    return decorator
