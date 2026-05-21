from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import uuid

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """User model for authentication"""
    __tablename__ = 'users'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    profile_image = db.Column(db.String(255), default='default-avatar.png')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    theme = db.Column(db.String(20), default='light')
    last_login = db.Column(db.DateTime)

    # Relationships
    encrypted_files = db.relationship('EncryptedFile', backref='user', lazy=True, cascade='all, delete-orphan')
    password_analyses = db.relationship('PasswordAnalysis', backref='user', lazy=True, cascade='all, delete-orphan')
    security_logs = db.relationship('SecurityLog', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        """Hash and set user password"""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        """Check if provided password matches hash"""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class EncryptedFile(db.Model):
    """Model for encrypted files"""
    __tablename__ = 'encrypted_files'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False, index=True)
    original_filename = db.Column(db.String(255), nullable=False)
    encrypted_filename = db.Column(db.String(255), nullable=False, unique=True)
    file_extension = db.Column(db.String(10), nullable=False)
    encryption_type = db.Column(db.String(50), default='AES-256', nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_accessed = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='encrypted', nullable=False)
    decryption_password_hint = db.Column(db.String(255))
    is_decrypted = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<EncryptedFile {self.original_filename}>'


class PasswordAnalysis(db.Model):
    """Model for password strength analysis"""
    __tablename__ = 'password_analyses'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False, index=True)
    analyzed_password = db.Column(db.String(255), nullable=False)
    strength_level = db.Column(db.String(20), nullable=False)  # Weak, Medium, Strong
    entropy_score = db.Column(db.Float, nullable=False)
    crack_time_estimation = db.Column(db.String(100), nullable=False)
    has_uppercase = db.Column(db.Boolean, default=False)
    has_lowercase = db.Column(db.Boolean, default=False)
    has_numbers = db.Column(db.Boolean, default=False)
    has_special_chars = db.Column(db.Boolean, default=False)
    password_length = db.Column(db.Integer, nullable=False)
    is_common = db.Column(db.Boolean, default=False)
    recommendations = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    suggested_password = db.Column(db.String(255))

    def __repr__(self):
        return f'<PasswordAnalysis {self.strength_level}>'


class SecurityLog(db.Model):
    """Model for security audit logs"""
    __tablename__ = 'security_logs'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False, index=True)
    action = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    status = db.Column(db.String(20), default='success')

    def __repr__(self):
        return f'<SecurityLog {self.action}>'


class SharedFile(db.Model):
    """Model for shared encrypted files between users"""
    __tablename__ = 'shared_files'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    encrypted_file_id = db.Column(db.String(36), db.ForeignKey('encrypted_files.id'), nullable=False, index=True)
    owner_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False, index=True)
    recipient_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=True, index=True)
    recipient_email = db.Column(db.String(120), nullable=True)
    
    # Sharing methods
    share_method = db.Column(db.String(50), nullable=False)  # qrcode, otp, user_id, link
    sharing_token = db.Column(db.String(255), unique=True, nullable=False)
    qr_token = db.Column(db.String(255), unique=True, nullable=True)
    otp_code = db.Column(db.String(10), nullable=True)
    otp_attempts = db.Column(db.Integer, default=0)
    max_otp_attempts = db.Column(db.Integer, default=5)
    
    # Access modes
    access_mode = db.Column(db.String(50), default='view_only')  # view_only, download_only, full_access, locked
    
    # Expiry settings
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    share_expiry = db.Column(db.DateTime, nullable=True)
    otp_expiry = db.Column(db.DateTime, nullable=True)
    
    # Sharing status
    is_active = db.Column(db.Boolean, default=True)
    access_count = db.Column(db.Integer, default=0)
    max_access_count = db.Column(db.Integer, nullable=True)  # None for unlimited
    
    # QR Code
    qr_code_data = db.Column(db.Text, nullable=True)  # Base64 encoded QR code image
    
    # Relationships
    owner = db.relationship('User', foreign_keys=[owner_id], backref='shared_files_owner')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='shared_files_recipient')
    encrypted_file = db.relationship('EncryptedFile')
    access_logs = db.relationship('AccessLog', backref='shared_file', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<SharedFile {self.id}>'


class AccessLog(db.Model):
    """Model for tracking access to shared files"""
    __tablename__ = 'access_logs'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    shared_file_id = db.Column(db.String(36), db.ForeignKey('shared_files.id'), nullable=False, index=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=True, index=True)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(255))
    device_info = db.Column(db.String(255))
    device_type = db.Column(db.String(50), nullable=True)  # desktop, mobile, tablet
    browser = db.Column(db.String(100), nullable=True)
    operating_system = db.Column(db.String(100), nullable=True)
    action = db.Column(db.String(100), nullable=False)  # viewed, downloaded, failed_otp, etc.
    status = db.Column(db.String(20), default='success')
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    # Additional tracking
    failure_reason = db.Column(db.String(255), nullable=True)
    request_method = db.Column(db.String(10), nullable=True)

    # Relationships
    user = db.relationship('User', backref='access_logs')

    def __repr__(self):
        return f'<AccessLog {self.action}>'


class OTPVerification(db.Model):
    """Model for tracking OTP verification attempts"""
    __tablename__ = 'otp_verifications'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False, index=True)
    shared_file_id = db.Column(db.String(36), db.ForeignKey('shared_files.id'), nullable=True, index=True)
    otp_code = db.Column(db.String(10), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    verified = db.Column(db.Boolean, default=False)
    failed_attempts = db.Column(db.Integer, default=0)
    ip_address = db.Column(db.String(45), nullable=False)
    device_info = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    verified_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    user = db.relationship('User', backref='otp_verifications')
    shared_file = db.relationship('SharedFile', backref='otp_verifications')

    def __repr__(self):
        return f'<OTPVerification {self.id}>'


class DeviceSession(db.Model):
    """Model for tracking trusted devices"""
    __tablename__ = 'device_sessions'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False, index=True)
    device_fingerprint = db.Column(db.String(255), nullable=False)
    device_name = db.Column(db.String(255), nullable=False)  # e.g., "Chrome on Windows"
    device_type = db.Column(db.String(50), nullable=False)  # desktop, mobile, tablet
    browser = db.Column(db.String(100), nullable=True)
    operating_system = db.Column(db.String(100), nullable=True)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(255), nullable=True)
    is_trusted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_used = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = db.relationship('User', backref='device_sessions')

    def __repr__(self):
        return f'<DeviceSession {self.device_name}>'


class ShareNotification(db.Model):
    """Model for share-related notifications"""
    __tablename__ = 'share_notifications'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    recipient_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False, index=True)
    shared_file_id = db.Column(db.String(36), db.ForeignKey('shared_files.id'), nullable=False, index=True)
    sender_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=True)
    notification_type = db.Column(db.String(50), nullable=False)  # shared, accessed, expired, revoked
    message = db.Column(db.String(500), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    read_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_notifications')
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_notifications')
    shared_file = db.relationship('SharedFile', backref='notifications')

    def __repr__(self):
        return f'<ShareNotification {self.notification_type}>'


class SecurityEvent(db.Model):
    """Model for security-related events"""
    __tablename__ = 'security_events'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False, index=True)
    event_type = db.Column(db.String(100), nullable=False)  # failed_otp, unauthorized_access, device_change, unusual_activity
    severity = db.Column(db.String(20), default='low')  # low, medium, high, critical
    message = db.Column(db.String(500), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=False)
    device_info = db.Column(db.String(255), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    is_resolved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    resolved_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    user = db.relationship('User', backref='security_events')

    def __repr__(self):
        return f'<SecurityEvent {self.event_type}>'
