import os
import string
import secrets
import math
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Common weak passwords list (small sample - extend as needed)
COMMON_PASSWORDS = {
    '123456', 'password', '123456789', '12345678', '12345', '1234567',
    'password123', '123123', '1234567890', '000000', '111111', '666666',
    '123321', '666666', '696969', 'abc123', 'batman', 'trustno1'
}

class EncryptionManager:
    """Manages file encryption and decryption"""

    @staticmethod
    def generate_key_from_password(password: str, salt: bytes = None) -> tuple:
        """
        Generate encryption key from password using PBKDF2
        Returns: (key, salt)
        """
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    @staticmethod
    def encrypt_file(file_content: bytes, password: str) -> tuple:
        """
        Encrypt file content using Fernet (AES-128-CBC)
        Returns: (encrypted_content, salt_hex)
        """
        key, salt = EncryptionManager.generate_key_from_password(password)
        cipher_suite = Fernet(key)
        encrypted_content = cipher_suite.encrypt(file_content)
        return encrypted_content, salt.hex()

    @staticmethod
    def decrypt_file(encrypted_content: bytes, password: str, salt_hex: str) -> bytes:
        """
        Decrypt file content using stored salt
        Returns: decrypted_content
        """
        salt = bytes.fromhex(salt_hex)
        key, _ = EncryptionManager.generate_key_from_password(password, salt)
        cipher_suite = Fernet(key)
        decrypted_content = cipher_suite.decrypt(encrypted_content)
        return decrypted_content

    @staticmethod
    def is_file_encrypted(file_path: str) -> bool:
        """Check if file appears to be encrypted"""
        try:
            with open(file_path, 'rb') as f:
                first_bytes = f.read(10)
            # Fernet tokens start with 'gAAAAAA'
            return b'gAAAAAA' in first_bytes
        except Exception:
            return False


class PasswordAnalyzer:
    """Analyzes password strength and generates secure passwords"""

    @staticmethod
    def calculate_entropy(password: str) -> float:
        """
        Calculate Shannon entropy of password
        Higher entropy = more random = stronger
        """
        entropy = 0
        for char in set(password):
            px = password.count(char) / len(password)
            entropy -= px * math.log2(px)
        return entropy

    @staticmethod
    def estimate_crack_time(entropy: float) -> str:
        """
        Estimate time to crack password via brute force
        Assumes 1 billion attempts per second
        """
        attempts = 2 ** entropy
        seconds = attempts / 1e9

        if seconds < 1:
            return "Less than 1 second"
        elif seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            return f"{int(seconds / 60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds / 3600)} hours"
        elif seconds < 2592000:  # 30 days
            return f"{int(seconds / 86400)} days"
        elif seconds < 31536000:  # 1 year
            return f"{int(seconds / 2592000)} months"
        else:
            years = int(seconds / 31536000)
            if years > 1000000:
                return "Centuries"
            return f"{years} years"

    @staticmethod
    def analyze_password(password: str) -> dict:
        """
        Comprehensive password analysis
        Returns dictionary with strength metrics
        """
        analysis = {
            'password_length': len(password),
            'has_uppercase': any(c.isupper() for c in password),
            'has_lowercase': any(c.islower() for c in password),
            'has_numbers': any(c.isdigit() for c in password),
            'has_special_chars': any(c in string.punctuation for c in password),
            'is_common': password.lower() in COMMON_PASSWORDS,
            'entropy': PasswordAnalyzer.calculate_entropy(password),
        }

        # Calculate strength level
        score = 0
        if analysis['password_length'] >= 8:
            score += 1
        if analysis['password_length'] >= 12:
            score += 1
        if analysis['has_uppercase']:
            score += 1
        if analysis['has_lowercase']:
            score += 1
        if analysis['has_numbers']:
            score += 1
        if analysis['has_special_chars']:
            score += 2

        if analysis['is_common']:
            score = 0

        if score <= 2:
            strength = 'Weak'
        elif score <= 4:
            strength = 'Medium'
        else:
            strength = 'Strong'

        analysis['strength_level'] = strength
        analysis['score'] = score
        analysis['crack_time'] = PasswordAnalyzer.estimate_crack_time(analysis['entropy'])

        # Generate recommendations
        recommendations = []
        if not analysis['has_uppercase']:
            recommendations.append("Add uppercase letters")
        if not analysis['has_lowercase']:
            recommendations.append("Add lowercase letters")
        if not analysis['has_numbers']:
            recommendations.append("Add numbers")
        if not analysis['has_special_chars']:
            recommendations.append("Add special characters (!@#$%^&*)")
        if analysis['password_length'] < 12:
            recommendations.append(f"Use at least 12 characters (current: {analysis['password_length']})")
        if analysis['is_common']:
            recommendations.append("This password is too common, choose something unique")

        analysis['recommendations'] = recommendations
        return analysis

    @staticmethod
    def generate_secure_password(length: int = 16) -> str:
        """
        Generate a cryptographically secure random password
        Includes uppercase, lowercase, numbers, and special characters
        """
        chars = string.ascii_uppercase + string.ascii_lowercase + string.digits + string.punctuation
        password = ''.join(secrets.choice(chars) for _ in range(length))
        return password

    @staticmethod
    def generate_memorable_password(length: int = 12) -> str:
        """
        Generate memorable but secure password
        Format: Word-Number-Word-Symbol pattern
        """
        words = ['blue', 'green', 'red', 'fast', 'slow', 'bright', 'dark', 'bold', 'swift']
        password = f"{secrets.choice(words)}-{secrets.randbelow(999)}-{secrets.choice(words)}-{secrets.choice('!@#$%')}"
        return password


class FileValidator:
    """Validates uploaded files"""

    ALLOWED_EXTENSIONS = {'pdf', 'docx', 'txt', 'zip', 'png', 'jpg', 'jpeg'}
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

    @staticmethod
    def allowed_file(filename: str) -> bool:
        """Check if file extension is allowed"""
        if '.' not in filename:
            return False
        ext = filename.rsplit('.', 1)[1].lower()
        return ext in FileValidator.ALLOWED_EXTENSIONS

    @staticmethod
    def check_file_size(file_size: int) -> bool:
        """Check if file size is within limits"""
        return file_size <= FileValidator.MAX_FILE_SIZE

    @staticmethod
    def get_file_extension(filename: str) -> str:
        """Extract file extension"""
        if '.' in filename:
            return filename.rsplit('.', 1)[1].lower()
        return 'unknown'


class InputValidator:
    """Validates user input"""

    @staticmethod
    def validate_username(username: str) -> tuple:
        """Validate username format"""
        if not username or len(username) < 3:
            return False, "Username must be at least 3 characters"
        if len(username) > 80:
            return False, "Username must be less than 80 characters"
        if not all(c.isalnum() or c in '_-' for c in username):
            return False, "Username can only contain alphanumeric characters, underscores, and hyphens"
        return True, "Valid"

    @staticmethod
    def validate_email(email: str) -> tuple:
        """Validate email format"""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(pattern, email):
            return True, "Valid"
        return False, "Invalid email format"

    @staticmethod
    def validate_password(password: str) -> tuple:
        """Validate password format"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        if len(password) > 255:
            return False, "Password is too long"
        return True, "Valid"


def get_client_ip(request):
    """Get client IP address from request"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'
